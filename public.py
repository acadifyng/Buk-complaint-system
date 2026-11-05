from flask import Blueprint, g, redirect, render_template

import rbac
from core import home_for

bp = Blueprint("public", __name__)


@bp.route("/")
def home():
    if g.user:
        return redirect(home_for(g.user))
    return render_template("landing.html", categories=rbac.CATEGORY_LABELS, hints=rbac.CATEGORY_HINTS)


@bp.route("/healthz")
def healthz():
    return {"ok": True}
