-- Database schema for the BUK Student Complaint Management System (SQLite).
-- Older databases are upgraded automatically by db.migrate().

CREATE TABLE IF NOT EXISTS users (
    id                   INTEGER PRIMARY KEY AUTOINCREMENT,
    full_name            TEXT    NOT NULL,
    email                TEXT    NOT NULL UNIQUE,
    matric_no            TEXT    UNIQUE,
    password_hash        TEXT    NOT NULL,
    role                 TEXT    NOT NULL CHECK (role IN (
                             'student', 'hostel_officer', 'security_officer',
                             'academic_affairs_officer', 'exams_records_officer',
                             'student_affairs_officer', 'admin')),
    is_active            INTEGER NOT NULL DEFAULT 1,
    failed_logins        INTEGER NOT NULL DEFAULT 0,
    locked_until         TEXT,
    created_at           TEXT    NOT NULL,
    must_change_password INTEGER NOT NULL DEFAULT 0,
    password_changed_at  TEXT,
    last_login_at        TEXT,
    last_login_ip        TEXT,
    prev_login_at        TEXT,
    prev_login_ip        TEXT,
    totp_secret_enc      BLOB,
    totp_enabled         INTEGER NOT NULL DEFAULT 0,
    totp_last_step       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS complaints (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    reference           TEXT    NOT NULL UNIQUE,
    student_id          INTEGER NOT NULL REFERENCES users(id),
    category            TEXT    NOT NULL CHECK (category IN ('hostel', 'security', 'academic', 'welfare')),
    subcategory         TEXT,
    title_enc           BLOB    NOT NULL,       -- encrypted at rest
    description_enc     BLOB    NOT NULL,       -- encrypted at rest
    status              TEXT    NOT NULL DEFAULT 'Submitted' CHECK (status IN (
                            'Submitted', 'Under Review', 'In Progress', 'Resolved', 'Closed')),
    assigned_role       TEXT    NOT NULL,       -- the only staff role allowed to handle this case
    created_at          TEXT    NOT NULL,
    updated_at          TEXT    NOT NULL,
    priority            TEXT    NOT NULL DEFAULT 'Normal',
    anonymous           INTEGER NOT NULL DEFAULT 0,
    escalated           INTEGER NOT NULL DEFAULT 0,
    due_at              TEXT,
    resolved_at         TEXT,
    closed_at           TEXT,
    rating              INTEGER,
    rating_comment_enc  BLOB
);

CREATE TABLE IF NOT EXISTS responses (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    complaint_id INTEGER NOT NULL REFERENCES complaints(id),
    author_id    INTEGER NOT NULL REFERENCES users(id),
    message_enc  BLOB    NOT NULL,          -- encrypted at rest
    created_at   TEXT    NOT NULL,
    is_internal  INTEGER NOT NULL DEFAULT 0 -- 1 = staff-only note, never shown to the student
);

CREATE TABLE IF NOT EXISTS status_history (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    complaint_id INTEGER NOT NULL REFERENCES complaints(id),
    status       TEXT    NOT NULL,
    changed_by   INTEGER REFERENCES users(id),
    note         TEXT,
    created_at   TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS attachments (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    complaint_id  INTEGER NOT NULL REFERENCES complaints(id),
    original_name TEXT    NOT NULL,
    mime          TEXT    NOT NULL,
    size          INTEGER NOT NULL,
    stored_name   TEXT    NOT NULL UNIQUE,   -- random name; the file itself is encrypted
    uploaded_by   INTEGER NOT NULL REFERENCES users(id),
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS notifications (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id),
    message    TEXT    NOT NULL,             -- never contains complaint text
    link       TEXT,
    is_read    INTEGER NOT NULL DEFAULT 0,
    created_at TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS backup_codes (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id   INTEGER NOT NULL REFERENCES users(id),
    code_hash TEXT    NOT NULL,
    used      INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS audit_log (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    ts            TEXT    NOT NULL,
    user_id       INTEGER,
    actor         TEXT,
    action        TEXT    NOT NULL,
    complaint_ref TEXT,
    ip            TEXT,
    detail        TEXT
);
