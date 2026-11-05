"""Authorised download of encrypted evidence files."""
import os

from flask import Blueprint, Response, abort, current_app, g

import db
import rbac
from core import audit, login_required, vault

bp = Blueprint("files", __name__)


@bp.get("/attachments/<int:attachment_id>")
@login_required
def download(attachment_id):
    row = db.get_db().execute(
        "SELECT a.*, c.student_id, c.assigned_role, c.reference FROM attachments a "
        "JOIN complaints c ON c.id = a.complaint_id WHERE a.id = ?", (attachment_id,)).fetchone()
    if row is None:
        abort(404)
    if not (rbac.can_student_view(g.user, row) or rbac.can_staff_view(g.user, row)):
        audit("access_denied", complaint_ref=row["reference"], detail="attachment %d" % attachment_id)
        abort(404)
    path = os.path.join(current_app.config["UPLOAD_FOLDER"], row["stored_name"])
    if not os.path.exists(path):
        abort(404)
    with open(path, "rb") as handle:
        data = vault().decrypt_bytes(handle.read())
    audit("attachment_downloaded", complaint_ref=row["reference"], detail=row["original_name"])
    return Response(data, mimetype=row["mime"], headers={
        "Content-Disposition": 'attachment; filename="%s"' % row["original_name"].replace('"', "")})
