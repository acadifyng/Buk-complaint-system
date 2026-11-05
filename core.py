"""Shared helpers used by every part of the application."""
import math
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import abort, current_app, g, redirect, request, url_for

import db
import rbac
import security as sec


def vault():
    return current_app.extensions["vault"]


def audit(action, complaint_ref=None, detail=None, user=None, actor=None):
    who = user if user is not None else g.get("user")
    conn = db.get_db()
    conn.execute(
        "INSERT INTO audit_log (ts, user_id, actor, action, complaint_ref, ip, detail) VALUES (?,?,?,?,?,?,?)",
        (sec.now_iso(), who["id"] if who else None, actor or (who["email"] if who else None),
         action, complaint_ref, request.remote_addr, (detail or "")[:300]))
    conn.commit()


def notify(user_id, message, link=None):
    """In-app notification. The message never contains complaint text."""
    conn = db.get_db()
    conn.execute("INSERT INTO notifications (user_id, message, link, created_at) VALUES (?,?,?,?)",
                 (user_id, message[:200], link, sec.now_iso()))
    conn.commit()


def notify_role(role, message, link=None, exclude_id=None):
    for row in db.get_db().execute("SELECT id FROM users WHERE role = ? AND is_active = 1", (role,)).fetchall():
        if row["id"] != exclude_id:
            notify(row["id"], message, link)


def add_history(complaint_id, status, user_id=None, note=None):
    conn = db.get_db()
    conn.execute("INSERT INTO status_history (complaint_id, status, changed_by, note, created_at) VALUES (?,?,?,?,?)",
                 (complaint_id, status, user_id, note, sec.now_iso()))
    conn.commit()


def home_for(user):
    if user["role"] == "student":
        return url_for("student.home")
    if user["role"] == "admin":
        return url_for("admin.home")
    return url_for("staff.home")


def login_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if g.user is None:
            return redirect(url_for("auth.login"))
        return view(*args, **kwargs)
    return wrapper


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        @login_required
        def wrapper(*args, **kwargs):
            if g.user["role"] not in roles:
                audit("access_denied", detail="role %s tried %s" % (g.user["role"], request.path))
                abort(403)
            return view(*args, **kwargs)
        return wrapper
    return decorator


def get_complaint(reference):
    if not sec.REFERENCE_RE.match(reference or ""):
        return None
    return db.get_db().execute(
        "SELECT c.*, u.full_name AS student_name, u.matric_no AS matric_no "
        "FROM complaints c JOIN users u ON u.id = c.student_id WHERE c.reference = ?",
        (reference,)).fetchone()


def complaint_text(complaint):
    return vault().decrypt(complaint["title_enc"]), vault().decrypt(complaint["description_enc"])


def conversation(complaint_id, include_internal):
    query = ("SELECT r.*, u.full_name AS author_name, u.role AS author_role FROM responses r "
             "JOIN users u ON u.id = r.author_id WHERE r.complaint_id = ?")
    if not include_internal:
        query += " AND r.is_internal = 0"
    rows = db.get_db().execute(query + " ORDER BY r.id", (complaint_id,)).fetchall()
    return [{"author": r["author_name"], "role": rbac.role_label(r["author_role"]),
             "is_student": r["author_role"] == "student", "internal": bool(r["is_internal"]),
             "message": vault().decrypt(r["message_enc"]), "created_at": r["created_at"]} for r in rows]


def history_for(complaint_id):
    return db.get_db().execute(
        "SELECT h.*, u.role AS actor_role FROM status_history h LEFT JOIN users u ON u.id = h.changed_by "
        "WHERE h.complaint_id = ? ORDER BY h.id", (complaint_id,)).fetchall()


def attachments_for(complaint_id):
    return db.get_db().execute(
        "SELECT id, original_name, mime, size, created_at FROM attachments WHERE complaint_id = ? ORDER BY id",
        (complaint_id,)).fetchall()


def due_at_for(priority, created_iso=None):
    created = sec.parse_iso(created_iso) if created_iso else datetime.now(timezone.utc)
    return (created + timedelta(hours=rbac.SLA_HOURS.get(priority, 120))).strftime(sec.TIME_FORMAT)


def is_overdue(complaint, now=None):
    if complaint["status"] in ("Resolved", "Closed") or not complaint["due_at"]:
        return False
    return sec.parse_iso(complaint["due_at"]) < (now or datetime.now(timezone.utc))


def hours_left(complaint, now=None):
    if not complaint["due_at"]:
        return None
    delta = sec.parse_iso(complaint["due_at"]) - (now or datetime.now(timezone.utc))
    return int(delta.total_seconds() // 3600)


def int_arg(name, default=1, minimum=1, maximum=10**6):
    try:
        return max(minimum, min(maximum, int(request.args.get(name, default))))
    except (TypeError, ValueError):
        return default


def paginate(total, page, per_page):
    pages = max(1, math.ceil(total / per_page))
    page = max(1, min(page, pages))
    return {"page": page, "pages": pages, "per_page": per_page, "offset": (page - 1) * per_page, "total": total}
