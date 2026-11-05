"""Administration: statistics, accounts and the audit log. Admins never see complaint content."""
import csv
import io
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, abort, current_app, flash, g, redirect, render_template, request, url_for

import db
import rbac
import security as sec
from core import audit, int_arg, paginate, roles_required

bp = Blueprint("admin", __name__)


@bp.get("/admin")
@roles_required("admin")
def home():
    conn = db.get_db()
    now = datetime.now(timezone.utc)
    rows = conn.execute("SELECT category, status, priority, due_at, escalated, rating, created_at, resolved_at, "
                        "assigned_role FROM complaints").fetchall()
    by_cat = {key: {s: 0 for s in rbac.STATUSES} for key in rbac.CATEGORY_LABELS}
    for r in rows:
        by_cat[r["category"]][r["status"]] += 1
    status_totals = {s: sum(by_cat[c][s] for c in by_cat) for s in rbac.STATUSES}
    open_rows = [r for r in rows if r["status"] in rbac.OPEN_STATUSES]
    overdue = sum(1 for r in open_rows if r["due_at"] and sec.parse_iso(r["due_at"]) < now)
    ratings = [r["rating"] for r in rows if r["rating"]]
    days = [(now - timedelta(days=i)).strftime("%Y-%m-%d") for i in range(13, -1, -1)]
    trend = {d: 0 for d in days}
    for r in rows:
        day = r["created_at"][:10]
        if day in trend:
            trend[day] += 1
    hours = {}
    for r in rows:
        if r["resolved_at"]:
            delta = (sec.parse_iso(r["resolved_at"]) - sec.parse_iso(r["created_at"])).total_seconds() / 3600
            hours.setdefault(r["category"], []).append(delta)
    avg_hours = {rbac.CATEGORY_LABELS[k]: round(sum(v) / len(v), 1) for k, v in hours.items()}
    workload = {rbac.role_label(role): sum(1 for r in open_rows if r["assigned_role"] == role)
                for role in rbac.STAFF_ROLES}
    locked = conn.execute("SELECT COUNT(*) FROM users WHERE locked_until > ?", (sec.now_iso(),)).fetchone()[0]
    role_counts = {rbac.role_label(r["role"]): r["n"] for r in
                   conn.execute("SELECT role, COUNT(*) AS n FROM users GROUP BY role").fetchall()}
    no_2fa = conn.execute("SELECT COUNT(*) FROM users WHERE role != 'student' AND is_active = 1 AND totp_enabled = 0"
                          ).fetchone()[0]
    cards = {
        "total": len(rows), "open": len(open_rows), "overdue": overdue,
        "escalated": sum(1 for r in rows if r["escalated"]),
        "rating": round(sum(ratings) / len(ratings), 1) if ratings else None, "rated": len(ratings),
        "locked": locked, "no_2fa": no_2fa,
    }
    cat_totals = [(rbac.CATEGORY_LABELS[k], sum(v.values())) for k, v in by_cat.items()]
    return render_template("admin_home.html", cards=cards, cat_totals=cat_totals, status_totals=status_totals,
                           trend=list(trend.items()), avg_hours=avg_hours, workload=workload,
                           role_counts=role_counts, statuses=rbac.STATUSES, by_cat=by_cat,
                           labels=rbac.CATEGORY_LABELS)


@bp.get("/admin/stats.csv")
@roles_required("admin")
def stats_csv():
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Category", "Status", "Complaints"])
    for r in db.get_db().execute("SELECT category, status, COUNT(*) n FROM complaints GROUP BY category, status"):
        writer.writerow([sec.safe_csv_cell(rbac.CATEGORY_LABELS.get(r["category"])), r["status"], r["n"]])
    audit("export_csv", detail="statistics")
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=statistics.csv"})


@bp.route("/admin/users", methods=["GET", "POST"])
@roles_required("admin")
def users():
    if request.method == "POST":
        full_name = request.form.get("full_name", "").strip()
        email = request.form.get("email", "").strip().lower()
        role = request.form.get("role", "")
        password = request.form.get("password", "")
        errors = []
        if not 3 <= len(full_name) <= 100:
            errors.append("Enter the staff member's full name.")
        if not sec.EMAIL_RE.match(email):
            errors.append("Enter a valid email address.")
        if role not in rbac.STAFF_ROLES:
            errors.append("Choose a valid staff role.")
        errors += sec.validate_password(password, email, full_name)
        if not errors:
            try:
                db.add_user(full_name, email, role, password, must_change=True)
            except Exception:
                errors.append("An account with this email already exists.")
            else:
                audit("user_created", detail="%s as %s" % (email, role))
                flash("Staff account created. They must choose a new password the first time they sign in.", "ok")
                return redirect(url_for("admin.users"))
        for message in errors:
            flash(message, "error")
    q = request.args.get("q", "").strip().lower()
    role_filter = request.args.get("role", "")
    query, params = "SELECT * FROM users WHERE 1=1", []
    if role_filter in rbac.ROLE_LABELS:
        query += " AND role = ?"
        params.append(role_filter)
    if q:
        query += " AND (lower(full_name) LIKE ? OR lower(email) LIKE ?)"
        params += ["%" + q + "%"] * 2
    total = db.get_db().execute(query.replace("SELECT *", "SELECT COUNT(*)"), params).fetchone()[0]
    page = paginate(total, int_arg("page"), 20)
    accounts = db.get_db().execute(query + " ORDER BY role, full_name LIMIT ? OFFSET ?",
                                   params + [page["per_page"], page["offset"]]).fetchall()
    return render_template("admin_users.html", accounts=accounts, roles=rbac.STAFF_ROLES, page=page, now=sec.now_iso(),
                           role_filter=role_filter, q=q)


def _target_or_404(user_id):
    target = db.get_db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        abort(404)
    return target


@bp.post("/admin/users/<int:user_id>/toggle")
@roles_required("admin")
def user_toggle(user_id):
    target = _target_or_404(user_id)
    if target["id"] == g.user["id"]:
        flash("You cannot deactivate your own account.", "error")
    else:
        state = 0 if target["is_active"] else 1
        db.get_db().execute("UPDATE users SET is_active = ? WHERE id = ?", (state, user_id))
        db.get_db().commit()
        audit("user_activated" if state else "user_deactivated", detail=target["email"])
        flash("Account updated.", "ok")
    return redirect(url_for("admin.users"))


@bp.post("/admin/users/<int:user_id>/unlock")
@roles_required("admin")
def user_unlock(user_id):
    target = _target_or_404(user_id)
    db.get_db().execute("UPDATE users SET failed_logins = 0, locked_until = NULL WHERE id = ?", (user_id,))
    db.get_db().commit()
    audit("user_unlocked", detail=target["email"])
    flash("Account unlocked.", "ok")
    return redirect(url_for("admin.users"))


@bp.post("/admin/users/<int:user_id>/reset")
@roles_required("admin")
def user_reset(user_id):
    target = _target_or_404(user_id)
    if target["id"] == g.user["id"]:
        flash("Use the Password page to change your own password.", "error")
        return redirect(url_for("admin.users"))
    temp = sec.generate_password(14)
    db.get_db().execute(
        "UPDATE users SET password_hash = ?, must_change_password = 1, failed_logins = 0, locked_until = NULL, "
        "password_changed_at = ? WHERE id = ?",
        (sec.hash_password(temp, current_app.config.get("HASH_METHOD")), sec.now_iso(), user_id))
    db.get_db().commit()
    audit("password_reset_by_admin", detail=target["email"])
    return render_template("admin_reset.html", target=target, temp=temp)   # shown once, never stored in plain text


@bp.get("/admin/audit")
@roles_required("admin")
def audit_log():
    action = request.args.get("action", "").strip()
    q = request.args.get("q", "").strip()
    query, params = "SELECT * FROM audit_log WHERE 1=1", []
    if action:
        query += " AND action = ?"
        params.append(action)
    if q:
        query += " AND (actor LIKE ? OR complaint_ref LIKE ? OR ip LIKE ?)"
        params += ["%" + q + "%"] * 3
    conn = db.get_db()
    total = conn.execute(query.replace("SELECT *", "SELECT COUNT(*)"), params).fetchone()[0]
    page = paginate(total, int_arg("page"), 50)
    rows = conn.execute(query + " ORDER BY id DESC LIMIT ? OFFSET ?", params + [page["per_page"], page["offset"]]).fetchall()
    actions = [r[0] for r in conn.execute("SELECT DISTINCT action FROM audit_log ORDER BY action")]
    return render_template("admin_audit.html", rows=rows, page=page, actions=actions, action=action, q=q)


@bp.get("/admin/audit.csv")
@roles_required("admin")
def audit_csv():
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Time (UTC)", "User", "Action", "Complaint", "IP", "Detail"])
    for r in db.get_db().execute("SELECT * FROM audit_log ORDER BY id DESC LIMIT 5000"):
        writer.writerow([sec.safe_csv_cell(v) for v in (r["ts"], r["actor"], r["action"], r["complaint_ref"], r["ip"], r["detail"])])
    audit("export_csv", detail="audit log")
    return Response(out.getvalue(), mimetype="text/csv", headers={"Content-Disposition": "attachment; filename=audit-log.csv"})
