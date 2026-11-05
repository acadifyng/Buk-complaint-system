import sqlite3

from flask import current_app, g

import security as sec

# Columns added after the first version. Older databases are upgraded when the app starts.
MIGRATIONS = {
    "users": [
        ("must_change_password", "INTEGER NOT NULL DEFAULT 0"),
        ("password_changed_at", "TEXT"),
        ("last_login_at", "TEXT"), ("last_login_ip", "TEXT"),
        ("prev_login_at", "TEXT"), ("prev_login_ip", "TEXT"),
        ("totp_secret_enc", "BLOB"),
        ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
        ("totp_last_step", "INTEGER NOT NULL DEFAULT 0"),
    ],
    "complaints": [
        ("priority", "TEXT NOT NULL DEFAULT 'Normal'"),
        ("anonymous", "INTEGER NOT NULL DEFAULT 0"),
        ("escalated", "INTEGER NOT NULL DEFAULT 0"),
        ("due_at", "TEXT"), ("resolved_at", "TEXT"), ("closed_at", "TEXT"),
        ("rating", "INTEGER"), ("rating_comment_enc", "BLOB"),
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


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_error=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def migrate(conn):
    for table, columns in MIGRATIONS.items():          # table and column names are constants
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
        conn.executescript(handle.read().decode("utf-8"))
    migrate(conn)


def add_user(full_name, email, role, password, matric_no=None, must_change=False):
    """Create an account with a hashed password. Returns the new user id."""
    conn = get_db()
    now = sec.now_iso()
    cur = conn.execute(
        "INSERT INTO users (full_name, email, matric_no, password_hash, role, created_at, "
        "must_change_password, password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (full_name, email.lower(), matric_no,
         sec.hash_password(password, current_app.config.get("HASH_METHOD")), role, now,
         1 if must_change else 0, now))
    conn.commit()
    return cur.lastrowid
