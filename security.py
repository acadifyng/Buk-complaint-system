"""Security helpers: passwords, validation, encryption at rest, two-factor codes, file checks."""
import base64
import hashlib
import hmac
import os
import re
import secrets
import struct
import time
from datetime import datetime, timezone
from urllib.parse import quote

from cryptography.fernet import Fernet
from werkzeug.security import check_password_hash, generate_password_hash

EMAIL_RE = re.compile(r"^[^@\s]{1,64}@[^@\s]{1,200}\.[^@\s]{2,}$")
MATRIC_RE = re.compile(r"^[A-Za-z0-9/\-]{4,30}$")
REFERENCE_RE = re.compile(r"^BUK-[0-9A-F]{8}$")
COMMON_PASSWORDS = {"password", "password123", "12345678", "123456789", "1234567890",
                    "qwerty123", "iloveyou1", "welcome123", "admin12345", "letmein123"}
TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


# ------------------------------------------------------------------ time helpers
def now_iso():
    return datetime.now(timezone.utc).strftime(TIME_FORMAT)


def parse_iso(value):
    return datetime.strptime(value, TIME_FORMAT).replace(tzinfo=timezone.utc)


# ------------------------------------------------- passwords (salted, never stored plain)
def hash_password(password, method=None):
    return generate_password_hash(password, method=method) if method else generate_password_hash(password)


def verify_password(stored_hash, password):
    return check_password_hash(stored_hash, password)


# Used so a login for an unknown email takes about as long as a real one.
DUMMY_HASH = generate_password_hash("not-a-real-password")


def validate_password(password, email="", name=""):
    errors = []
    if len(password) < 10:
        errors.append("Password must be at least 10 characters long.")
    if len(password) > 128:
        errors.append("Password must be 128 characters or fewer.")
    classes = sum(bool(re.search(p, password)) for p in (r"[a-z]", r"[A-Z]", r"\d", r"[^A-Za-z0-9]"))
    if classes < 3:
        errors.append("Use at least three of: lowercase letters, uppercase letters, numbers and symbols.")
    local = email.split("@")[0].lower() if email else ""
    if len(local) >= 4 and local in password.lower():
        errors.append("Password must not contain your email name.")
    if password.lower() in COMMON_PASSWORDS:
        errors.append("That password is too common. Choose a different one.")
    return errors


def generate_password(length=14):
    """Random password with lowercase, uppercase, digits and symbols (no look-alike characters)."""
    pools = ["abcdefghjkmnpqrstuvwxyz", "ABCDEFGHJKLMNPQRSTUVWXYZ", "23456789", "#$%&*+=?@"]
    chars = [secrets.choice(p) for p in pools]
    allchars = "".join(pools)
    chars += [secrets.choice(allchars) for _ in range(length - len(chars))]
    secrets.SystemRandom().shuffle(chars)
    return "".join(chars)


# ----------------------------------------------------------------------- identifiers
def new_reference():
    """Random, non-sequential reference so complaint numbers cannot be guessed."""
    return "BUK-" + secrets.token_hex(4).upper()


# ------------------------------------------------------------- encryption at rest
class Vault:
    """Encrypts text and files before they are written to disk or the database."""

    def __init__(self, key):
        self._fernet = Fernet(key)

    def encrypt(self, text):
        return self._fernet.encrypt(text.encode("utf-8"))

    def decrypt(self, token):
        return self._fernet.decrypt(bytes(token)).decode("utf-8")

    def encrypt_bytes(self, data):
        return self._fernet.encrypt(data)

    def decrypt_bytes(self, token):
        return self._fernet.decrypt(bytes(token))


def _write_private(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as handle:
        handle.write(value)


def load_or_create_secret(path, env_value=None):
    if env_value:
        return env_value
    if os.path.exists(path):
        with open(path) as handle:
            return handle.read().strip()
    value = secrets.token_hex(32)
    _write_private(path, value)
    return value


def load_or_create_data_key(path, env_value=None):
    if env_value:
        return env_value.encode()
    if os.path.exists(path):
        with open(path, "rb") as handle:
            return handle.read().strip()
    key = Fernet.generate_key()
    _write_private(path, key.decode())
    return key


# ------------------------------------------------ two-factor authentication (RFC 6238)
def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode().rstrip("=")


def _hotp(secret, counter, digits=6):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8), casefold=True)
    mac = hmac.new(key, struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = mac[-1] & 0x0F
    number = (struct.unpack(">I", mac[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** digits)
    return str(number).zfill(digits)


def totp_now(secret, at=None, step=30, digits=6):
    return _hotp(secret, int((at if at is not None else time.time()) // step), digits)


def verify_totp(secret, code, last_step=0, at=None, window=1):
    """Returns the time step that matched, or None. A step can only be used once."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(r"\d{6}", code):
        return None
    current = int((at if at is not None else time.time()) // 30)
    for offset in range(-window, window + 1):
        step = current + offset
        if step <= last_step:
            continue
        if hmac.compare_digest(_hotp(secret, step), code):
            return step
    return None


def otpauth_uri(secret, email, issuer="BUK Complaint System"):
    return "otpauth://totp/%s:%s?secret=%s&issuer=%s&digits=6&period=30" % (
        quote(issuer), quote(email), secret, quote(issuer))


def generate_backup_codes(count=8):
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return ["".join(secrets.choice(alphabet) for _ in range(5)) + "-" +
            "".join(secrets.choice(alphabet) for _ in range(5)) for _ in range(count)]


def normalise_backup_code(code):
    return re.sub(r"[^A-Z0-9]", "", (code or "").upper())


def backup_code_hash(secret_key, code):
    return hmac.new(secret_key.encode(), normalise_backup_code(code).encode(), hashlib.sha256).hexdigest()


# ------------------------------------------------------------------ uploads and exports
def detect_upload_type(data):
    """Identify an upload by its real content, not by the file name it claims."""
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return ("png", "image/png")
    if data[:3] == b"\xff\xd8\xff":
        return ("jpg", "image/jpeg")
    if data.startswith(b"%PDF-"):
        return ("pdf", "application/pdf")
    return None


def safe_csv_cell(value):
    """Stops spreadsheet formula injection in exported files."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text
