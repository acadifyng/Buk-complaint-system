"""Staff pages: assigned complaints, replies, internal notes, status, priority and reassignment."""
import csv
import io
from datetime import datetime, timedelta, timezone

from flask import Blueprint, Response, abort, flash, g, redirect, render_template, request, url_for

import db
import rbac
import security as sec
from core import (add_history, attachments_for, audit, complaint_text, conversation, due_at_for, get_complaint,
                  history_for, hours_left, int_arg, is_overdue, notify, notify_role, paginate, roles_required, vault)

bp = Blueprint("staff", __name__)
STAFF = tuple(rbac.STAFF_ROLES)


def _complaint_or_404(reference):
    complaint = get_complaint(reference)
    if complaint is None:
        abort(404)
    if not rbac.can_staff_view(g.user, complaint):
        audit("access_denied", complaint_ref=reference, detail="staff outside responsibility")
        abort(404)                                    # do not reveal that the case exists
    return complaint


def _load_rows():
    """Assigned complaints after the filters in the address bar. Titles are decrypted for searching."""
    status = request.args.get("status", "")
    priority = request.args.get("priority", "")
    category = request.args.get("category", "")
    query = "SELECT * FROM complaints WHERE assigned_role = ?"
    params = [g.user["role"]]
    if status in rbac.STATUSES:
        query += " AND status = ?"
        params.append(status)
    if priority in rbac.PRIORITIES:
        query += " AND priority = ?"
        params.append(priority)
    if category in rbac.CATEGORY_LABELS:
        query += " AND category = ?"
        params.append(category)
    rows = db.get_db().execute(query, params).fetchall()
    items = [{"row": r, "title": vault().decrypt(r["title_enc"]), "overdue": is_overdue(r)} for r in rows]
    if request.args.get("overdue") == "1":
        items = [i for i in items if i["overdue"]]
    q = request.args.get("q", "").strip().lower()
    if q:
        items = [i for i in items if q in i["title"].lower() or q in i["row"]["reference"].lower()]
    sort = request.args.get("sort", "new")
    if sort == "old":
        items.sort(key=lambda i: i["row"]["id"])
    elif sort == "due":
        items.sort(key=lambda i: (i["row"]["due_at"] is None, i["row"]["due_at"] or ""))
    elif sort == "priority":
        items.sort(key=lambda i: (-rbac.PRIORITY_RANK.get(i["row"]["priority"], 1), i["row"]["due_at"] or "9"))
    else:
        items.sort(key=lambda i: -i["row"]["id"])
    return items


@bp.get("/staff")
@roles_required(*STAFF)
def home():
    items = _load_rows()
    page = paginate(len(items), int_arg("page"), 15)
    shown = items[page["offset"]:page["offset"] + page["per_page"]]
    conn = db.get_db()
    role = g.user["role"]
    week = (datetime.now(timezone.utc) - timedelta(days=7)).strftime(sec.TIME_FORMAT)
    all_rows = conn.execute("SELECT status, priority, due_at, resolved_at FROM complaints WHERE assigned_role = ?",
                            (role,)).fetchall()
    open_rows = [r for r in all_rows if r["status"] in rbac.OPEN_STATUSES]
    stats = {
        "open": len(open_rows),
        "overdue": sum(1 for r in open_rows if r["due_at"] and sec.parse_iso(r["due_at"]) < datetime.now(timezone.utc)),
        "urgent": sum(1 for r in open_rows if r["priority"] in ("Urgent", "High")),
        "resolved_week": sum(1 for r in all_rows if r["resolved_at"] and r["resolved_at"] >= week),
    }
    avg = conn.execute("SELECT AVG(rating), COUNT(rating) FROM complaints WHERE assigned_role = ? AND rating IS NOT NULL",
                       (role,)).fetchone()
    stats["rating"] = round(avg[0], 1) if avg[0] else None
    stats["rated"] = avg[1]
    return render_template("staff_home.html", items=shown, page=page, stats=stats, total=len(items),
                           statuses=rbac.STATUSES, priorities=rbac.PRIORITIES, categories=rbac.CATEGORY_LABELS,
                           args=request.args)


@bp.get("/staff/export.csv")
@roles_required(*STAFF)
def export():
    out = io.StringIO()
    writer = csv.writer(out)
    writer.writerow(["Reference", "Category", "Priority", "Status", "Submitted", "Due", "Overdue", "Rating"])
    for item in _load_rows():
        r = item["row"]
        writer.writerow([sec.safe_csv_cell(v) for v in (
            r["reference"], rbac.CATEGORY_LABELS.get(r["category"]), r["priority"], r["status"], r["created_at"],
            r["due_at"] or "", "yes" if item["overdue"] else "no", r["rating"] or "")])
    audit("export_csv", detail="staff list")
    return Response(out.getvalue(), mimetype="text/csv",
                    headers={"Content-Disposition": "attachment; filename=complaints.csv"})


@bp.get("/staff/complaints/<reference>")
@roles_required(*STAFF)
def view(reference):
    complaint = _complaint_or_404(reference)
    title, description = complaint_text(complaint)
    audit("complaint_viewed", complaint_ref=reference)
    comment = vault().decrypt(complaint["rating_comment_enc"]) if complaint["rating_comment_enc"] else ""
    return render_template(
        "staff_complaint.html", c=complaint, title=title, description=description,
        messages=conversation(complaint["id"], True), history=history_for(complaint["id"]),
        files=attachments_for(complaint["id"]), next_statuses=rbac.NEXT_STATUSES[complaint["status"]],
        priorities=rbac.PRIORITIES, quick=rbac.QUICK_REPLIES, overdue=is_overdue(complaint),
        hours_left=hours_left(complaint), rating_comment=comment,
        targets=[r for r in rbac.STAFF_ROLES if r != complaint["assigned_role"]])


@bp.post("/staff/complaints/<reference>/status")
@roles_required(*STAFF)
def status(reference):
    complaint = _complaint_or_404(reference)
    new_status = request.form.get("status", "")
    if new_status not in rbac.NEXT_STATUSES[complaint["status"]]:
        flash("That status change is not allowed.", "error")
    else:
        now = sec.now_iso()
        db.get_db().execute(
            "UPDATE complaints SET status = ?, updated_at = ?, resolved_at = CASE WHEN ? = 'Resolved' THEN ? "
            "WHEN ? = 'In Progress' THEN NULL ELSE resolved_at END, closed_at = CASE WHEN ? = 'Closed' THEN ? "
            "ELSE closed_at END WHERE id = ?",
            (new_status, now, new_status, now, new_status, new_status, now, complaint["id"]))
        db.get_db().commit()
        add_history(complaint["id"], new_status, g.user["id"], request.form.get("note", "").strip()[:200] or None)
        audit("status_changed", complaint_ref=reference, detail="%s -> %s" % (complaint["status"], new_status))
        notify(complaint["student_id"], "Complaint %s is now: %s." % (reference, new_status), "/complaints/" + reference)
        flash("Status updated to %s." % new_status, "ok")
    return redirect(url_for("staff.view", reference=reference))


@bp.post("/staff/complaints/<reference>/respond")
@roles_required(*STAFF)
def respond(reference):
    complaint = _complaint_or_404(reference)
    message = request.form.get("message", "").strip()
    if not 5 <= len(message) <= 2000:
        flash("The response must be between 5 and 2000 characters.", "error")
    elif complaint["status"] == "Closed":
        flash("This complaint is closed.", "error")
    else:
        db.get_db().execute("INSERT INTO responses (complaint_id, author_id, message_enc, created_at) VALUES (?,?,?,?)",
                            (complaint["id"], g.user["id"], vault().encrypt(message), sec.now_iso()))
        db.get_db().execute("UPDATE complaints SET updated_at = ? WHERE id = ?", (sec.now_iso(), complaint["id"]))
        db.get_db().commit()
        audit("response_added", complaint_ref=reference)
        notify(complaint["student_id"], "You have a new response on complaint %s." % reference, "/complaints/" + reference)
        flash("Response sent to the student.", "ok")
    return redirect(url_for("staff.view", reference=reference))


@bp.post("/staff/complaints/<reference>/note")
@roles_required(*STAFF)
def note(reference):
    complaint = _complaint_or_404(reference)
    message = request.form.get("message", "").strip()
    if not 3 <= len(message) <= 2000:
        flash("The note must be between 3 and 2000 characters.", "error")
    else:
        db.get_db().execute(
            "INSERT INTO responses (complaint_id, author_id, message_enc, created_at, is_internal) VALUES (?,?,?,?,1)",
            (complaint["id"], g.user["id"], vault().encrypt(message), sec.now_iso()))
        db.get_db().commit()
        audit("internal_note_added", complaint_ref=reference)
        flash("Internal note saved. The student cannot see it.", "ok")
    return redirect(url_for("staff.view", reference=reference))


@bp.post("/staff/complaints/<reference>/priority")
@roles_required(*STAFF)
def priority(reference):
    complaint = _complaint_or_404(reference)
    new_priority = request.form.get("priority", "")
    if new_priority not in rbac.PRIORITIES:
        flash("Choose a valid priority.", "error")
    else:
        db.get_db().execute("UPDATE complaints SET priority = ?, due_at = ?, updated_at = ? WHERE id = ?",
                            (new_priority, due_at_for(new_priority, complaint["created_at"]), sec.now_iso(), complaint["id"]))
        db.get_db().commit()
        audit("priority_changed", complaint_ref=reference, detail="%s -> %s" % (complaint["priority"], new_priority))
        flash("Priority set to %s. The response deadline was updated." % new_priority, "ok")
    return redirect(url_for("staff.view", reference=reference))


@bp.post("/staff/complaints/<reference>/reassign")
@roles_required(*STAFF)
def reassign(reference):
    complaint = _complaint_or_404(reference)
    target = request.form.get("target", "")
    reason = request.form.get("reason", "").strip()[:200]
    if target not in rbac.STAFF_ROLES or target == complaint["assigned_role"]:
        flash("Choose a different office to send this complaint to.", "error")
        return redirect(url_for("staff.view", reference=reference))
    escalated = 1 if target == "student_affairs_officer" else complaint["escalated"]
    db.get_db().execute("UPDATE complaints SET assigned_role = ?, escalated = ?, updated_at = ? WHERE id = ?",
                        (target, escalated, sec.now_iso(), complaint["id"]))
    db.get_db().commit()
    add_history(complaint["id"], complaint["status"], g.user["id"],
                "Sent to %s%s" % (rbac.role_label(target), (": " + reason) if reason else ""))
    audit("complaint_reassigned", complaint_ref=reference, detail="%s -> %s" % (complaint["assigned_role"], target))
    notify_role(target, "Complaint %s was sent to your office by %s." % (reference, rbac.role_label(g.user["role"])),
                "/staff/complaints/" + reference)
    notify(complaint["student_id"], "Complaint %s was passed to %s." % (reference, rbac.role_label(target)),
           "/complaints/" + reference)
    flash("Complaint sent to %s." % rbac.role_label(target), "ok")
    return redirect(url_for("staff.home"))                # this office can no longer open it
