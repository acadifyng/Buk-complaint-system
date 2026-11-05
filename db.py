import os
import sqlite3

from flask import current_app, g

import security as sec

# --- Detect Postgres ---
DATABASE_URL = os.environ.get("DATABASE_URL")
IS_POSTGRES = bool(DATABASE_URL)

if IS_POSTGRES:
    import psycopg2
    import psycopg2.extras

# Columns added after the first version. Older databases are upgraded when the app starts.
MIGRATIONS = {
    "users": [
        ("must_change_password", "INTEGER NOT NULL DEFAULT 0"),
        ("password_changed_at", "TEXT"),
        ("last_login_at", "TEXT"), ("last_login_ip", "TEXT"),
        ("prev_login_at", "TEXT"), ("prev_login_ip", "TEXT"),
        ("totp_secret_enc", "BYTEA"),
        ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
        ("totp_last_step", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "complaints": [
        ("priority", "TEXT NOT NULL DEFAULT 'Normal'"),
        ("anonymous", "INTEGER NOT NULL DEFAULT 0"),
        ("escalated", "INTEGER NOT NULL DEFAULT 0"),
        ("due_at", "TEXT"), ("resolved_at", "TEXT"), ("closed_at", "TEXT"),
        ("rating", "INTEGER"), ("rating_comment_enc", "BYTEA"),
    ],
    "responses": [("is_internal", "INTEGER NOT NULL DEFAULT 0")],
}

INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_complaints_role ON complaints(assigned_role, status)",
    "CREATE INDEX IF NOT EXISTS idx_complaints_student ON complaints(student_id)",
    "CREATE INDEX IF NOT EXISTS idx_complaints_due ON complaints(due_at)",
    "CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts)",
    "CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id, is_read)",
    "CREATE INDEX IF NOT EXISTS idx_history_complaint ON status_history(complaint_id)",
]

# --- Wrapper so your old code with "?" still works on Postgres ---
class CursorWrapper:
    def __init__(self, cur):
        self.cur = cur

    def execute(self, sql, params=()):
        if IS_POSTGRES:
            sql = sql.replace("?", "%s")
        return self.cur.execute(sql, params)

    def executemany(self, sql, seq):
        if IS_POSTGRES:
            sql = sql.replace("?", "%s")
        return self.cur.executemany(sql, seq)

    def fetchone(self):
        return self.cur.fetchone()

    def fetchall(self):
        return self.cur.fetchall()

    @property
    def lastrowid(self):
        try:
            return self.cur.fetchone()[0] if self.cur.description else 0
        except Exception:
            return 0

    def __getattr__(self, name):
        return getattr(self.cur, name)

class ConnWrapper:
    def __init__(self, conn):
        self.conn = conn
        self._raw_conn = conn

    def execute(self, sql, params=()):
        # For Postgres, use DictCursor so row["name"] works like sqlite3.Row
        if IS_POSTGRES:
            cur = CursorWrapper(self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor))
        else:
            cur = self.conn.cursor()
        cur.execute(sql, params)
        return cur

    def executescript(self, sql):
        # Only used for SQLite
        cur = self.conn.cursor()
        cur.executescript(sql)
        return cur

    def commit(self):
        return self.conn.commit()

    def close(self):
        return self.conn.close()

    def cursor(self):
        if IS_POSTGRES:
            return CursorWrapper(self.conn.cursor(cursor_factory=psycopg2.extras.DictCursor))
        return self.conn.cursor()

def get_db():
    if "db" not in g:
        if IS_POSTGRES:
            conn = psycopg2.connect(DATABASE_URL)
            conn.autocommit = False
            g.db = ConnWrapper(conn)
        else:
            conn = sqlite3.connect(current_app.config["DATABASE"])
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            # Wrap sqlite conn too so .execute returns same interface
            # But keep raw sqlite behaviour for executescript
            g.db = conn
            # Add wrapper methods to sqlite conn via simple attribute hack:
            # Instead, return raw conn for SQLite - your old code expects sqlite conn
            # So we store raw conn directly
    return g.db

def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        try:
            conn.close()
        except Exception:
            pass

def migrate(conn):
    for table, columns in MIGRATIONS.items():
        if IS_POSTGRES:
            cur = conn.execute(
                "SELECT column_name FROM information_schema.columns WHERE table_name = %s",
                (table,))
            existing = {row["column_name"] for row in cur.fetchall()}
        else:
            existing = {row["name"] for row in conn.execute("PRAGMA table_info(%s)" % table)}
        for name, definition in columns:
            if name not in existing:
                conn.execute("ALTER TABLE %s ADD COLUMN %s %s" % (table, name, definition))
    for statement in INDEXES:
        conn.execute(statement)
    conn.commit()

def init_db():
    conn = get_db()
    with current_app.open_resource("schema.sql") as handle:
        sql = handle.read().decode("utf-8")
        if IS_POSTGRES:
            sql = sql.replace("INTEGER PRIMARY KEY AUTOINCREMENT", "SERIAL PRIMARY KEY")
            sql = sql.replace("BLOB", "BYTEA")
            # Remove SQLite comment lines starting with --
            lines = [l for l in sql.splitlines() if not l.strip().startswith("--")]
            sql = "\n".join(lines)
            # Postgres can run the whole script at once
            cur = conn.conn.cursor()
            cur.execute(sql)
            conn.conn.commit()
        else:
            conn.executescript(sql)
    migrate(conn)

def add_user(full_name, email, role, password, matric_no=None, must_change=False):
    """Create an account with a hashed password. Returns the new user id."""
    conn = get_db()
    now = sec.now_iso()
    if IS_POSTGRES:
        cur = conn.execute(
            "INSERT INTO users (full_name, email, matric_no, password_hash, role, created_at, "
            "must_change_password, password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?) RETURNING id",
            (full_name, email.lower(), matric_no,
             sec.hash_password(password, current_app.config.get("HASH_METHOD")), role, now,
             1 if must_change else 0, now))
        new_id = cur.fetchone()[0]
        conn.commit()
        return new_id
    else:
        cur = conn.execute(
            "INSERT INTO users (full_name, email, matric_no, password_hash, role, created_at, "
            "must_change_password, password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (full_name, email.lower(), matric_no,
             sec.hash_password(password, current_app.config.get("HASH_METHOD")), role, now,
             1 if must_change else 0, now))
        conn.commit()
        return cur.lastrowid
