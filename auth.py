"""Sign-in, registration, password changes and two-factor authentication."""
import secrets
import time
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, flash, g, redirect, render_template, request, session, url_for

import db
import security as sec
from core import audit, home_for, login_required, vault

bp = Blueprint("auth", __name__)


def _start_session(user):
    session.clear()                                   # new session on login (prevents fixation)
    session["uid"] = user["id"]
    session["csrf"] = secrets.token_urlsafe(32)
    session["last_seen"] = time.time()


def finish_login(user):
    conn = db.get_db()
    conn.execute(
        "UPDATE users SET failed_logins = 0, locked_until = NULL, prev_login_at = last_login_at, "
        "prev_login_ip = last_login_ip, last_login_at = ?, last_login_ip = ? WHERE id = ?",
        (sec.now_iso(), request.remote_addr, user["id"]))
    conn.commit()
    _start_session(user)
    audit("login_success", user=user)
    if user["must_change_password"]:
        flash("Please choose a new password before you continue.", "warn")
        return redirect(url_for("auth.change_password"))
    return redirect(home_for(user))


def register_failure(user, attempted, reason):
    """Count a failed attempt and lock the account after too many."""
    conn = db.get_db()
    if user:
        failed = user["failed_logins"] + 1
        lock_until = None
        if failed >= current_app.config["MAX_FAILED_LOGINS"]:
            lock_until = (datetime.now(timezone.utc) + timedelta(minutes=current_app.config["LOCK_MINUTES"])
                          ).strftime(sec.TIME_FORMAT)
            failed = 0
            audit("account_locked", user=user)
        conn.execute("UPDATE users SET failed_logins = ?, locked_until = COALESCE(?, locked_until) WHERE id = ?",
                     (failed, lock_until, user["id"]))
        conn.commit()
    audit("login_failed", actor=attempted or "(blank)", detail=reason)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if g.user:
        return redirect(home_for(g.user))
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()[:200]
        password = request.form.get("password", "")
        user = db.get_db().execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        now = datetime.now(timezone.utc)
        locked = bool(user and user["locked_until"] and sec.parse_iso(user["locked_until"]) > now)
        password_ok = sec.verify_password(user["password_hash"] if user else sec.DUMMY_HASH, password)
        if user and user["is_active"] and password_ok and not locked:
            if user["totp_enabled"]:
                session.clear()
                session["pre2fa"] = user["id"]
                session["pre2fa_at"] = time.time()
                session["csrf"] = secrets.token_urlsafe(32)
                return redirect(url_for("auth.login_2fa"))
            return finish_login(user)
        register_failure(user, email, "locked" if locked else "bad credentials")
        flash("Invalid email or password, or the account is temporarily locked.", "error")
    elif request.args.get("expired"):
        flash("You were signed out because of inactivity. Please sign in again.", "warn")
    return render_template("login.html")


@bp.route("/login/2fa", methods=["GET", "POST"])
def login_2fa():
    uid = session.get("pre2fa")
    if not uid or time.time() - session.get("pre2fa_at", 0) > 300:
        session.clear()
        return redirect(url_for("auth.login"))
    user = db.get_db().execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (uid,)).fetchone()
    if user is None:
        session.clear()
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        code = request.form.get("code", "")
        conn = db.get_db()
        step = sec.verify_totp(vault().decrypt(user["totp_secret_enc"]), code, user["totp_last_step"])
        if step:
            conn.execute("UPDATE users SET totp_last_step = ? WHERE id = ?", (step, user["id"]))
            conn.commit()
            return finish_login(user)
        row = None
        if len(sec.normalise_backup_code(code)) == 10:
            digest = sec.backup_code_hash(current_app.config["SECRET_KEY"], code)
            row = conn.execute("SELECT id FROM backup_codes WHERE user_id = ? AND code_hash = ? AND used = 0",
                               (user["id"], digest)).fetchone()
        if row:
            conn.execute("UPDATE backup_codes SET used = 1 WHERE id = ?", (row["id"],))
            conn.commit()
            audit("backup_code_used", user=user)
            return finish_login(user)
        register_failure(user, user["email"], "bad two-factor code")
        fresh = conn.execute("SELECT locked_until FROM users WHERE id = ?", (user["id"],)).fetchone()
        if fresh["locked_until"] and sec.parse_iso(fresh["locked_until"]) > datetime.now(timezone.utc):
            session.clear()
            flash("Too many wrong codes. The account is temporarily locked.", "error")
            return redirect(url_for("auth.login"))
        flash("That code is not correct. Try the newest code from your authenticator app.", "error")
    return render_template("login_2fa.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if g.user:
        return redirect(home_for(g.user))
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        matric = request.form.get("matric_no", "").strip().upper()
        password = request.form.get("password", "")
        confirm = request.form.get("confirm", "")
        errors = []
        if not 3 <= len(full_name) <= 100:
            errors.append("Enter your full name (3 to 100 characters).")
        if not sec.EMAIL_RE.match(email):
            errors.append("Enter a valid email address.")
        if not sec.MATRIC_RE.match(matric):
            errors.append("Enter a valid matriculation number (letters, numbers, / and - only).")
        errors += sec.validate_password(password, email, full_name)
        if password != confirm:
            errors.append("The two passwords do not match.")
        if not errors:
            try:
                uid = db.add_user(full_name, email, "student", password, matric)
            except Exception:
                errors.append("An account with these details already exists.")
            else:
                audit("register", user={"id": uid, "email": email}, detail="student account created")
                flash("Account created. You can now sign in.", "ok")
                return redirect(url_for("auth.login"))
        for message in errors:
            flash(message, "error")
    return render_template("register.html")


@bp.post("/logout")
@login_required
def logout():
    audit("logout")
    session.clear()
    flash("You have been signed out.", "ok")
    return redirect(url_for("auth.login"))


@bp.post("/session/ping")
@login_required
def session_ping():
    return ("", 204)                                  # any request refreshes the idle timer


@bp.get("/account")
@login_required
def account():
    codes_left = db.get_db().execute(
        "SELECT COUNT(*) FROM backup_codes WHERE user_id = ? AND used = 0", (g.user["id"],)).fetchone()[0]
    return render_template("account.html", codes_left=codes_left)


@bp.route("/account/password", methods=["GET", "POST"])
@login_required
def change_password():
    forced = bool(g.user["must_change_password"])
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        confirm = request.form.get("confirm", "")
        errors = []
        if not sec.verify_password(g.user["password_hash"], current):
            errors.append("Your current password is incorrect.")
        errors += sec.validate_password(new, g.user["email"], g.user["full_name"])
        if new == current:
            errors.append("Choose a password that is different from the current one.")
        if new != confirm:
            errors.append("The two new passwords do not match.")
        if not errors:
            conn = db.get_db()
            conn.execute("UPDATE users SET password_hash = ?, must_change_password = 0, password_changed_at = ? "
                         "WHERE id = ?",
                         (sec.hash_password(new, current_app.config.get("HASH_METHOD")), sec.now_iso(), g.user["id"]))
            conn.commit()
            audit("password_changed")
            flash("Password updated.", "ok")
            return redirect(home_for(g.user))
        for message in errors:
            flash(message, "error")
    return render_template("password.html", forced=forced)


@bp.route("/account/2fa", methods=["GET", "POST"])
@login_required
def twofa_setup():
    conn = db.get_db()
    if g.user["totp_enabled"]:
        return redirect(url_for("auth.account"))
    if request.method == "POST":
        pending = session.get("totp_pending")
        step = sec.verify_totp(pending, request.form.get("code", "")) if pending else None
        if not step:
            flash("That code is not correct. Make sure your phone's clock is automatic and try again.", "error")
        else:
            codes = sec.generate_backup_codes()
            conn.execute("UPDATE users SET totp_secret_enc = ?, totp_enabled = 1, totp_last_step = ? WHERE id = ?",
                         (vault().encrypt(pending), step, g.user["id"]))
            conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (g.user["id"],))
            for code in codes:
                conn.execute("INSERT INTO backup_codes (user_id, code_hash) VALUES (?, ?)",
                             (g.user["id"], sec.backup_code_hash(current_app.config["SECRET_KEY"], code)))
            conn.commit()
            session.pop("totp_pending", None)
            audit("twofa_enabled")
            return render_template("twofa_codes.html", codes=codes)
    if "totp_pending" not in session:
        session["totp_pending"] = sec.new_totp_secret()
    secret = session["totp_pending"]
    spaced = " ".join(secret[i:i + 4] for i in range(0, len(secret), 4))
    return render_template("twofa_setup.html", secret=spaced, uri=sec.otpauth_uri(secret, g.user["email"]))


@bp.post("/account/2fa/disable")
@login_required
def twofa_disable():
    if not sec.verify_password(g.user["password_hash"], request.form.get("password", "")):
        flash("Your password is incorrect, so two-factor sign-in was not turned off.", "error")
        return redirect(url_for("auth.account"))
    conn = db.get_db()
    conn.execute("UPDATE users SET totp_secret_enc = NULL, totp_enabled = 0, totp_last_step = 0 WHERE id = ?",
                 (g.user["id"],))
    conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (g.user["id"],))
    conn.commit()
    audit("twofa_disabled")
    flash("Two-factor sign-in has been turned off.", "ok")
    return redirect(url_for("auth.account"))
