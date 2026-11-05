from urllib.parse import urlparse

from flask import Blueprint, abort, g, redirect, render_template, url_for

import db
from core import login_required

bp = Blueprint("notify", __name__)


@bp.get("/notifications")
@login_required
def list_all():
    rows = db.get_db().execute(
        "SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100", (g.user["id"],)).fetchall()
    return render_template("notifications.html", rows=rows)


@bp.post("/notifications/read-all")
@login_required
def read_all():
    conn = db.get_db()
    conn.execute("UPDATE notifications SET is_read = 1 WHERE user_id = ?", (g.user["id"],))
    conn.commit()
    return redirect(url_for("notify.list_all"))


@bp.get("/notifications/<int:note_id>")
@login_required
def open_one(note_id):
    conn = db.get_db()
    row = conn.execute("SELECT * FROM notifications WHERE id = ? AND user_id = ?", (note_id, g.user["id"])).fetchone()
    if row is None:
        abort(404)
    conn.execute("UPDATE notifications SET is_read = 1 WHERE id = ?", (note_id,))
    conn.commit()
    link = row["link"] or ""
    if link and not urlparse(link).netloc and link.startswith("/"):      # only links inside this site
        return redirect(link)
    return redirect(url_for("notify.list_all"))
