"""Student pages: submit complaints, follow progress, reply, confirm, reopen and rate."""
import os
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, abort, current_app, flash, g, redirect, render_template, request, url_for
from werkzeug.utils import secure_filename

import db
import rbac
import security as sec
from core import (add_history, attachments_for, audit, complaint_text, conversation, due_at_for, get_complaint,
                  history_for, hours_left, int_arg, is_overdue, notify_role, paginate, roles_required, vault)

bp = Blueprint("student", __name__)


def _own_complaint_or_404(reference):
    complaint = get_complaint(reference)
    if complaint is None or not rbac.can_student_view(g.user, complaint):
        if complaint is not None:
            audit("access_denied", complaint_ref=reference, detail="student opened another student's complaint")
        abort(404)
    return complaint


@bp.get("/student")
@roles_required("student")
def home():
    tab = request.args.get("tab", "all")
    where, params = "student_id = ?", [g.user["id"]]
    if tab == "open":
        where += " AND status IN ('Submitted','Under Review','In Progress')"
    elif tab == "resolved":
        where += " AND status IN ('Resolved','Closed')"
    conn = db.get_db()
    total = conn.execute("SELECT COUNT(*) FROM complaints WHERE " + where, params).fetchone()[0]
    page = paginate(total, int_arg("page"), 10)
    rows = conn.execute("SELECT * FROM complaints WHERE " + where + " ORDER BY id DESC LIMIT ? OFFSET ?",
                        params + [page["per_page"], page["offset"]]).fetchall()
    items = [{"reference": r["reference"], "title": vault().decrypt(r["title_enc"]), "category": r["category"],
              "status": r["status"], "priority": r["priority"], "created_at": r["created_at"]} for r in rows]
    counts = conn.execute(
        "SELECT COUNT(*), SUM(status IN ('Submitted','Under Review','In Progress')), "
        "SUM(status IN ('Resolved','Closed')) FROM complaints WHERE student_id = ?", (g.user["id"],)).fetchone()
    stats = {"total": counts[0] or 0, "open": counts[1] or 0, "done": counts[2] or 0}
    return render_template("student_home.html", items=items, page=page, tab=tab, stats=stats)


def _save_attachments(complaint_id, files):
    """Validate, encrypt and store uploaded evidence. Returns a list of error messages."""
    errors = []
    folder = current_app.config["UPLOAD_FOLDER"]
    os.makedirs(folder, exist_ok=True)
    for upload in files:
        data = upload.read(rbac.MAX_ATTACHMENT_BYTES + 1)
        name = secure_filename(upload.filename or "") or "file"
        if len(data) > rbac.MAX_ATTACHMENT_BYTES:
            errors.append("%s is larger than 2 MB." % name)
            continue
        kind = sec.detect_upload_type(data)
        if kind is None:
            errors.append("%s is not a PNG, JPG or PDF file." % name)
            continue
        stored = secrets.token_hex(16) + ".bin"
        with open(os.path.join(folder, stored), "wb") as handle:
            handle.write(vault().encrypt_bytes(data))
        db.get_db().execute(
            "INSERT INTO attachments (complaint_id, original_name, mime, size, stored_name, uploaded_by, created_at) "
            "VALUES (?,?,?,?,?,?,?)", (complaint_id, name[:120], kind[1], len(data), stored, g.user["id"], sec.now_iso()))
    db.get_db().commit()
    return errors


@bp.route("/complaints/new", methods=["GET", "POST"])
@roles_required("student")
def new():
    if request.method == "POST":
        category = request.form.get("category", "")
        subcategory = request.form.get("subcategory", "") or None
        title = request.form.get("title", "").strip()
        description = request.form.get("description", "").strip()
        anonymous = request.form.get("anonymous") == "1"
        urgent = request.form.get("urgent") == "1"
        files = [f for f in request.files.getlist("attachments") if f and f.filename]
        errors = []
        assigned = None
        if category not in rbac.CATEGORY_LABELS:
            errors.append("Choose a valid complaint category.")
        elif category == "academic":
            assigned = rbac.route_complaint(category, subcategory)
            if assigned is None:
                errors.append("Choose the type of academic issue.")
        else:
            subcategory = None
            assigned = rbac.route_complaint(category)
        if not 5 <= len(title) <= 120:
            errors.append("The title must be between 5 and 120 characters.")
        if not 20 <= len(description) <= 3000:
            errors.append("The description must be between 20 and 3000 characters.")
        if len(files) > rbac.MAX_ATTACHMENTS:
            errors.append("You can attach at most %d files." % rbac.MAX_ATTACHMENTS)
        since = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime(sec.TIME_FORMAT)
        recent = db.get_db().execute("SELECT COUNT(*) FROM complaints WHERE student_id = ? AND created_at >= ?",
                                     (g.user["id"], since)).fetchone()[0]
        if recent >= current_app.config["MAX_COMPLAINTS_PER_HOUR"]:
            errors.append("You have submitted several complaints recently. Please try again later.")
        if not errors:
            reference = sec.new_reference()
            now = sec.now_iso()
            priority = rbac.default_priority(category, urgent)
            cur = db.get_db().execute(
                "INSERT INTO complaints (reference, student_id, category, subcategory, title_enc, description_enc, "
                "assigned_role, created_at, updated_at, priority, anonymous, due_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                (reference, g.user["id"], category, subcategory, vault().encrypt(title), vault().encrypt(description),
                 assigned, now, now, priority, 1 if anonymous else 0, due_at_for(priority, now)))
            db.get_db().commit()
            complaint_id = cur.lastrowid
            add_history(complaint_id, "Submitted", g.user["id"], "Complaint submitted")
            problems = _save_attachments(complaint_id, files) if files else []
            audit("complaint_submitted", complaint_ref=reference, detail="routed to %s, priority %s" % (assigned, priority))
            notify_role(assigned, "New %s priority complaint %s was assigned to your office." % (priority.lower(), reference),
                        "/staff/complaints/" + reference)
            flash("Complaint submitted. Your reference number is %s." % reference, "ok")
            for message in problems:
                flash("Attachment skipped: " + message, "warn")
            return redirect(url_for("student.view", reference=reference))
        for message in errors:
            flash(message, "error")
    return render_template("complaint_new.html", categories=rbac.CATEGORY_LABELS, hints=rbac.CATEGORY_HINTS,
                           subtypes=rbac.ACADEMIC_SUBTYPES, max_files=rbac.MAX_ATTACHMENTS)


@bp.get("/complaints/<reference>")
@roles_required("student")
def view(reference):
    complaint = _own_complaint_or_404(reference)
    title, description = complaint_text(complaint)
    comment = vault().decrypt(complaint["rating_comment_enc"]) if complaint["rating_comment_enc"] else ""
    return render_template(
        "student_complaint.html", c=complaint, title=title, description=description,
        handler=rbac.role_label(complaint["assigned_role"]), messages=conversation(complaint["id"], False),
        history=history_for(complaint["id"]), files=attachments_for(complaint["id"]),
        rating_comment=comment, overdue=is_overdue(complaint), hours_left=hours_left(complaint))


@bp.get("/complaints/<reference>/receipt")
@roles_required("student")
def receipt(reference):
    complaint = _own_complaint_or_404(reference)
    title, _ = complaint_text(complaint)
    return render_template("receipt.html", c=complaint, title=title, handler=rbac.role_label(complaint["assigned_role"]))


@bp.post("/complaints/<reference>/reply")
@roles_required("student")
def reply(reference):
    complaint = _own_complaint_or_404(reference)
    message = request.form.get("message", "").strip()
    if complaint["status"] == "Closed":
        flash("This complaint is closed.", "error")
    elif not 5 <= len(message) <= 2000:
        flash("Your message must be between 5 and 2000 characters.", "error")
    else:
        db.get_db().execute("INSERT INTO responses (complaint_id, author_id, message_enc, created_at) VALUES (?,?,?,?)",
                            (complaint["id"], g.user["id"], vault().encrypt(message), sec.now_iso()))
        db.get_db().execute("UPDATE complaints SET updated_at = ? WHERE id = ?", (sec.now_iso(), complaint["id"]))
        db.get_db().commit()
        audit("student_reply", complaint_ref=reference)
        notify_role(complaint["assigned_role"], "The student replied on complaint %s." % reference,
                    "/staff/complaints/" + reference)
        flash("Your message was sent.", "ok")
    return redirect(url_for("student.view", reference=reference))


def _set_status(complaint, status, note):
    now = sec.now_iso()
    conn = db.get_db()
    conn.execute("UPDATE complaints SET status = ?, updated_at = ?, resolved_at = CASE WHEN ? = 'In Progress' THEN NULL "
                 "ELSE resolved_at END, closed_at = CASE WHEN ? = 'Closed' THEN ? ELSE closed_at END WHERE id = ?",
                 (status, now, status, status, now, complaint["id"]))
    conn.commit()
    add_history(complaint["id"], status, g.user["id"], note)


@bp.post("/complaints/<reference>/reopen")
@roles_required("student")
def reopen(reference):
    complaint = _own_complaint_or_404(reference)
    if complaint["status"] != "Resolved":
        flash("Only a resolved complaint can be reopened.", "error")
    else:
        _set_status(complaint, "In Progress", "Reopened by the student")
        audit("complaint_reopened", complaint_ref=reference)
        notify_role(complaint["assigned_role"], "Complaint %s was reopened by the student." % reference,
                    "/staff/complaints/" + reference)
        flash("Your complaint was reopened and sent back to the office.", "ok")
    return redirect(url_for("student.view", reference=reference))


@bp.post("/complaints/<reference>/close")
@roles_required("student")
def confirm_close(reference):
    complaint = _own_complaint_or_404(reference)
    if complaint["status"] != "Resolved":
        flash("You can confirm a complaint once it has been marked as resolved.", "error")
    else:
        _set_status(complaint, "Closed", "Confirmed as resolved by the student")
        audit("complaint_closed", complaint_ref=reference)
        notify_role(complaint["assigned_role"], "The student confirmed complaint %s as resolved." % reference,
                    "/staff/complaints/" + reference)
        flash("Thank you. The complaint is now closed.", "ok")
    return redirect(url_for("student.view", reference=reference))


@bp.post("/complaints/<reference>/rate")
@roles_required("student")
def rate(reference):
    complaint = _own_complaint_or_404(reference)
    try:
        rating = int(request.form.get("rating", "0"))
    except ValueError:
        rating = 0
    comment = request.form.get("comment", "").strip()[:500]
    if complaint["status"] not in ("Resolved", "Closed"):
        flash("You can rate the service after the complaint is resolved.", "error")
    elif complaint["rating"]:
        flash("You have already rated this complaint.", "error")
    elif rating not in (1, 2, 3, 4, 5):
        flash("Choose a rating from 1 to 5 stars.", "error")
    else:
        db.get_db().execute("UPDATE complaints SET rating = ?, rating_comment_enc = ? WHERE id = ?",
                            (rating, vault().encrypt(comment) if comment else None, complaint["id"]))
        db.get_db().commit()
        audit("complaint_rated", complaint_ref=reference, detail="%d stars" % rating)
        flash("Thank you for your feedback.", "ok")
    return redirect(url_for("student.view", reference=reference))
