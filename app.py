"""Secure Web-Based Student Complaint Management System for Bayero University, Kano.

Run with:  python app.py
"""
import hmac
import os
import secrets
import time
from datetime import datetime

from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for

import db
import rbac
import security as sec


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    os.makedirs(app.instance_path, exist_ok=True)

    app.config.update(
        DATABASE=os.path.join(app.instance_path, "complaints.db"),
        UPLOAD_FOLDER=os.path.join(app.instance_path, "uploads"),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE", "0") == "1",
        MAX_FAILED_LOGINS=5,
        LOCK_MINUTES=15,
        IDLE_MINUTES=30,
        MAX_COMPLAINTS_PER_HOUR=5,
        MAX_CONTENT_LENGTH=8 * 1024 * 1024,
        HASH_METHOD=None,
    )
    if test_config:
        app.config.update(test_config)

    app.config["SECRET_KEY"] = app.config.get("SECRET_KEY") or sec.load_or_create_secret(
        os.path.join(app.instance_path, "secret.key"), os.environ.get("SECRET_KEY"))
    app.extensions["vault"] = sec.Vault(app.config.get("DATA_KEY") or sec.load_or_create_data_key(
        os.path.join(app.instance_path, "data.key"), os.environ.get("DATA_KEY")))

    app.teardown_appcontext(db.close_db)
    with app.app_context():
        db.init_db()

    # ------------------------------------------------------------ templates
    def csrf_token():
        if "csrf" not in session:
            session["csrf"] = secrets.token_urlsafe(32)
        return session["csrf"]

    def logo_url():
        static_dir = os.path.join(app.root_path, "static", "img")
        for name in ("buk-logo.png", "buk-logo.jpg", "buk-logo.svg"):
            if os.path.exists(os.path.join(static_dir, name)):
                return url_for("static", filename="img/" + name)
        return url_for("static", filename="img/buk-logo.svg")

    @app.context_processor
    def inject():
        unread = 0
        if g.get("user"):
            unread = db.get_db().execute("SELECT COUNT(*) FROM notifications WHERE user_id = ? AND is_read = 0",
                                         (g.user["id"],)).fetchone()[0]
        return {"unread_count": unread, "idle_minutes": app.config["IDLE_MINUTES"]}

    app.jinja_env.globals.update(
        csrf_token=csrf_token, role_label=rbac.role_label, logo_url=logo_url,
        category_label=lambda c: rbac.CATEGORY_LABELS.get(c, c), STAFF_ROLES=rbac.STAFF_ROLES)

    @app.template_filter("slug")
    def slug(value):
        return str(value).lower().replace(" ", "-")

    @app.template_filter("when")
    def when(value):
        """2026-10-31 14:20:05 -> 31 Oct 2026, 14:20"""
        try:
            return datetime.strptime(value, sec.TIME_FORMAT).strftime("%d %b %Y, %H:%M")
        except (TypeError, ValueError):
            return value or "-"

    # ------------------------------------------------------- request lifecycle
    @app.before_request
    def load_user():
        g.user = None
        uid = session.get("uid")
        if not uid:
            return
        now = time.time()
        if now - session.get("last_seen", 0) > app.config["IDLE_MINUTES"] * 60:
            session.clear()
            if request.method == "GET" and not request.path.startswith("/static/"):
                return redirect(url_for("auth.login", expired=1))
            return
        row = db.get_db().execute("SELECT * FROM users WHERE id = ? AND is_active = 1", (uid,)).fetchone()
        if row is None:
            session.clear()
            return
        g.user = row
        session["last_seen"] = now
        allowed = ("auth.change_password", "auth.logout", "auth.session_ping", "static")
        if row["must_change_password"] and request.endpoint not in allowed:
            flash("Please choose a new password before you continue.", "warn")
            return redirect(url_for("auth.change_password"))

    @app.before_request
    def csrf_protect():
        if request.method == "POST":
            sent = request.form.get("csrf_token", "") or request.headers.get("X-CSRF-Token", "")
            expected = session.get("csrf", "")
            if not expected or not hmac.compare_digest(sent, expected):
                abort(400)

    @app.after_request
    def security_headers(response):
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; img-src 'self' data:; frame-ancestors 'none'; "
            "form-action 'self'; base-uri 'self'")
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if request.is_secure or request.headers.get("X-Forwarded-Proto") == "https":
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if not request.path.startswith("/static/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    # ---------------------------------------------------------------- errors
    def error_page(code, title, message):
        return render_template("error.html", code=code, title=title, message=message), code

    @app.errorhandler(400)
    def bad_request(_e):
        return error_page(400, "Request could not be verified",
                          "Your session may have expired. Please go back, refresh the page and try again.")

    @app.errorhandler(403)
    def forbidden(_e):
        return error_page(403, "Access denied", "You do not have permission to open this page.")

    @app.errorhandler(404)
    def not_found(_e):
        return error_page(404, "Page not found", "The page you asked for does not exist or is not available to you.")

    @app.errorhandler(413)
    def too_large(_e):
        return error_page(413, "Upload too large", "The files you sent are too large. Each file must be 2 MB or smaller.")

    @app.errorhandler(500)
    def server_error(_e):
        return error_page(500, "Something went wrong", "An unexpected error occurred. No details are shown for security reasons.")

    # ------------------------------------------------------------ blueprints
    import admin, auth, files, notify, public, staff, student
    for module in (public, auth, student, staff, files, notify, admin):
        app.register_blueprint(module.bp)

    return app


if __name__ == "__main__":
    # For development. For real use, run behind HTTPS (see README).
    create_app().run(host="127.0.0.1", port=5000, debug=False)
