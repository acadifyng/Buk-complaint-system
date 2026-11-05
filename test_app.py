"""Functional and access-control tests.  Run with:  python -m unittest -v"""
import html
import io
import os
import re
import sqlite3
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from cryptography.fernet import Fernet  # noqa: E402

import db  # noqa: E402
import security as sec  # noqa: E402
from app import create_app  # noqa: E402

PW = "GoodPass123"
PNG = b"\x89PNG\r\n\x1a\n" + b"fake-image-data" * 20
TOKEN_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.dbfile = os.path.join(self.tmp, "test.db")
        self.app = create_app({"TESTING": True, "DATABASE": self.dbfile, "SECRET_KEY": "test-secret",
                               "DATA_KEY": Fernet.generate_key(), "MAX_COMPLAINTS_PER_HOUR": 100,
                               "UPLOAD_FOLDER": os.path.join(self.tmp, "uploads"),
                               "HASH_METHOD": "pbkdf2:sha256:1000"})
        with self.app.app_context():
            db.add_user("Admin", "admin@t.local", "admin", PW)
            db.add_user("Hostel Officer", "hostel@t.local", "hostel_officer", PW)
            db.add_user("Security Officer", "security@t.local", "security_officer", PW)
            db.add_user("Academic Officer", "academic@t.local", "academic_affairs_officer", PW)
            db.add_user("Exams Officer", "exams@t.local", "exams_records_officer", PW)
            db.add_user("Welfare Officer", "welfare@t.local", "student_affairs_officer", PW)
            db.add_user("Student One", "s1@t.local", "student", PW, "CST/20/001")
            db.add_user("Student Two", "s2@t.local", "student", PW, "CST/20/002")

    def token(self, client, path="/login"):
        return TOKEN_RE.search(client.get(path).get_data(as_text=True)).group(1)

    def login(self, email, password=PW):
        client = self.app.test_client()
        resp = client.post("/login", data={"email": email, "password": password, "csrf_token": self.token(client)})
        return client, resp

    def post(self, client, path, page, **data):
        data["csrf_token"] = self.token(client, page)
        return client.post(path, data=data)

    def submit(self, client, category="hostel", sub="", title="Broken locker in my room",
               description="The locker in my hostel room is broken and cannot be locked.", **extra):
        data = dict(category=category, subcategory=sub, title=title, description=description, **extra)
        data["csrf_token"] = self.token(client, "/complaints/new")
        resp = client.post("/complaints/new", data=data, content_type="multipart/form-data")
        self.assertEqual(resp.status_code, 302, resp.get_data(as_text=True)[:500])
        return resp.headers["Location"].rsplit("/", 1)[1]

    def raw(self, sql, params=()):
        conn = sqlite3.connect(self.dbfile)
        try:
            return conn.execute(sql, params).fetchall()
        finally:
            conn.close()

    def run_sql(self, sql, params=()):
        conn = sqlite3.connect(self.dbfile)
        conn.execute(sql, params)
        conn.commit()
        conn.close()


class AuthenticationTests(Base):
    def test_login_redirects_by_role(self):
        for email, target in [("s1@t.local", "/student"), ("hostel@t.local", "/staff"), ("admin@t.local", "/admin")]:
            _, resp = self.login(email)
            self.assertEqual(resp.status_code, 302)
            self.assertTrue(resp.headers["Location"].endswith(target), email)

    def test_wrong_password_and_unknown_user_give_the_same_message(self):
        for email in ("s1@t.local", "nobody@t.local"):
            _, resp = self.login(email, "WrongPass999")
            self.assertEqual(resp.status_code, 200)
            self.assertIn("Invalid email or password", resp.get_data(as_text=True))

    def test_account_locks_after_repeated_failures(self):
        for _ in range(5):
            self.login("s2@t.local", "WrongPass999")
        _, resp = self.login("s2@t.local", PW)
        self.assertIn("temporarily locked", resp.get_data(as_text=True))

    def test_sql_injection_in_login_fails(self):
        for attempt in ("' OR 1=1 --", "s1@t.local' --"):
            _, resp = self.login(attempt, "x")
            self.assertEqual(resp.status_code, 200)

    def test_passwords_are_stored_hashed(self):
        for (stored,) in self.raw("SELECT password_hash FROM users"):
            self.assertNotEqual(stored, PW)
            self.assertTrue(stored.startswith(("scrypt:", "pbkdf2:")))

    def test_registration_rules(self):
        client = self.app.test_client()
        base = {"full_name": "New Student", "email": "new@t.local", "matric_no": "CST/21/009"}
        for weak in ("short1", "alllowercaseletters", "NoDigitsHereAtAll"):
            t = self.token(client, "/register")
            resp = client.post("/register", data=dict(base, password=weak, confirm=weak, csrf_token=t))
            self.assertEqual(resp.status_code, 200, weak)
        t = self.token(client, "/register")
        ok = client.post("/register", data=dict(base, password=PW, confirm=PW, csrf_token=t))
        self.assertEqual(ok.status_code, 302)

    def test_protected_pages_require_login(self):
        client = self.app.test_client()
        for path in ["/student", "/staff", "/admin", "/complaints/new", "/admin/audit", "/notifications", "/account"]:
            resp = client.get(path)
            self.assertEqual(resp.status_code, 302, path)
            self.assertIn("/login", resp.headers["Location"])

    def test_post_without_csrf_token_is_rejected(self):
        client, _ = self.login("s1@t.local")
        self.assertEqual(client.post("/complaints/new", data={"category": "hostel"}).status_code, 400)
        self.assertEqual(client.post("/logout", data={}).status_code, 400)

    def test_logout_ends_the_session(self):
        client, _ = self.login("s1@t.local")
        self.post(client, "/logout", "/student")
        self.assertEqual(client.get("/student").status_code, 302)

    def test_idle_timeout_signs_the_user_out(self):
        client, _ = self.login("s1@t.local")
        with client.session_transaction() as s:
            s["last_seen"] = time.time() - 31 * 60
        resp = client.get("/student")
        self.assertEqual(resp.status_code, 302)
        self.assertIn("expired=1", resp.headers["Location"])

    def test_security_headers_present(self):
        resp = self.app.test_client().get("/login")
        self.assertIn("default-src 'self'", resp.headers["Content-Security-Policy"])
        self.assertEqual(resp.headers["X-Frame-Options"], "DENY")
        self.assertEqual(resp.headers["X-Content-Type-Options"], "nosniff")
        self.assertEqual(resp.headers["Cache-Control"], "no-store")

    def test_last_login_is_recorded_and_shown(self):
        self.login("s1@t.local")
        client, _ = self.login("s1@t.local")
        page = client.get("/account").get_data(as_text=True)
        self.assertIn("Last sign-in before this one", page)
        self.assertEqual(len(self.raw("SELECT 1 FROM users WHERE email='s1@t.local' AND prev_login_at IS NOT NULL")), 1)


class PasswordExperienceTests(Base):
    def test_every_password_field_has_the_eye_button(self):
        client, _ = self.login("s1@t.local")
        for path, anon in (("/login", True), ("/register", True), ("/account/password", False)):
            page = (self.app.test_client() if anon else client).get(path).get_data(as_text=True)
            self.assertIn("data-toggle-password", page, path)
            self.assertIn("pw-toggle", page, path)

    def test_registration_page_has_the_strength_meter(self):
        page = self.app.test_client().get("/register").get_data(as_text=True)
        self.assertIn('data-meter="password-meter"', page)
        self.assertIn("Password strength", page)

    def test_pages_have_no_inline_scripts_or_styles(self):
        client, _ = self.login("s1@t.local")
        self.submit(client)
        pages = [self.app.test_client().get(p).get_data(as_text=True) for p in ("/", "/login", "/register")]
        pages += [client.get(p).get_data(as_text=True) for p in ("/student", "/complaints/new", "/account", "/notifications")]
        admin, _ = self.login("admin@t.local")
        pages += [admin.get(p).get_data(as_text=True) for p in ("/admin", "/admin/users", "/admin/audit")]
        for page in pages:
            self.assertNotRegex(page, r"<script(?![^>]*\bsrc=)[^>]*>")
            self.assertNotRegex(page, r"\son\w+\s*=")
            self.assertNotIn(' style="', page)

    def test_admin_created_staff_must_change_password_first(self):
        admin, _ = self.login("admin@t.local")
        self.post(admin, "/admin/users", "/admin/users", full_name="New Officer", email="new.officer@t.local",
                  role="hostel_officer", password="TempPass#2026x")
        staff, resp = self.login("new.officer@t.local", "TempPass#2026x")
        self.assertIn("/account/password", resp.headers["Location"])
        self.assertIn("/account/password", staff.get("/staff").headers["Location"])
        bad = self.post(staff, "/account/password", "/account/password", current="WrongOne123", new="BrandNew#2026a",
                        confirm="BrandNew#2026a")
        self.assertEqual(bad.status_code, 200)
        reuse = self.post(staff, "/account/password", "/account/password", current="TempPass#2026x",
                          new="TempPass#2026x", confirm="TempPass#2026x")
        self.assertEqual(reuse.status_code, 200)
        ok = self.post(staff, "/account/password", "/account/password", current="TempPass#2026x", new="BrandNew#2026a",
                       confirm="BrandNew#2026a")
        self.assertEqual(ok.status_code, 302)
        self.assertEqual(staff.get("/staff").status_code, 200)

    def test_admin_password_reset_shows_temporary_password_once(self):
        admin, _ = self.login("admin@t.local")
        uid = self.raw("SELECT id FROM users WHERE email='hostel@t.local'")[0][0]
        resp = self.post(admin, "/admin/users/%d/reset" % uid, "/admin/users")
        temp = html.unescape(re.search(r'<code id="temp-pw">([^<]+)</code>', resp.get_data(as_text=True)).group(1))
        self.assertEqual(sec.validate_password(temp), [])
        old, _ = self.login("hostel@t.local", PW)
        self.assertEqual(old.get("/staff").status_code, 302)
        staff, login = self.login("hostel@t.local", temp)
        self.assertIn("/account/password", login.headers["Location"])
        self.assertNotIn(temp, admin.get("/admin/users").get_data(as_text=True))

    def test_admin_can_unlock_a_locked_account(self):
        for _ in range(5):
            self.login("s2@t.local", "WrongPass999")
        admin, _ = self.login("admin@t.local")
        uid = self.raw("SELECT id FROM users WHERE email='s2@t.local'")[0][0]
        self.post(admin, "/admin/users/%d/unlock" % uid, "/admin/users")
        _, resp = self.login("s2@t.local", PW)
        self.assertEqual(resp.status_code, 302)

    def test_generated_passwords_meet_the_rules(self):
        for _ in range(25):
            self.assertEqual(sec.validate_password(sec.generate_password()), [])


class TwoFactorTests(Base):
    def enable(self, email="hostel@t.local"):
        client, _ = self.login(email)
        page = client.get("/account/2fa").get_data(as_text=True)
        secret = re.search(r'<code id="secret-key">([^<]+)</code>', page).group(1).replace(" ", "")
        resp = self.post(client, "/account/2fa", "/account/2fa", code=sec.totp_now(secret))
        codes = re.findall(r"<li>([A-Z0-9]{5}-[A-Z0-9]{5})</li>", resp.get_data(as_text=True))
        return secret, codes

    def test_totp_matches_the_rfc_6238_test_vector(self):
        import base64
        secret = base64.b32encode(b"12345678901234567890").decode()
        self.assertEqual(sec._hotp(secret, 59 // 30, 8), "94287082")

    def test_enabling_and_signing_in_with_a_code(self):
        secret, codes = self.enable()
        self.assertEqual(len(codes), 8)
        client, resp = self.login("hostel@t.local")
        self.assertIn("/login/2fa", resp.headers["Location"])
        self.assertEqual(client.get("/staff").status_code, 302)
        bad = self.post(client, "/login/2fa", "/login/2fa", code="000000")
        self.assertEqual(bad.status_code, 200)
        good = self.post(client, "/login/2fa", "/login/2fa", code=sec.totp_now(secret, at=time.time() + 30))
        self.assertEqual(good.status_code, 302)
        self.assertEqual(client.get("/staff").status_code, 200)

    def test_a_used_code_cannot_be_replayed(self):
        secret, _ = self.enable()
        code = sec.totp_now(secret, at=time.time() + 30)
        for expected in (302, 200):
            client, _ = self.login("hostel@t.local")
            resp = self.post(client, "/login/2fa", "/login/2fa", code=code)
            self.assertEqual(resp.status_code, expected)

    def test_backup_code_works_once(self):
        _, codes = self.enable()
        client, _ = self.login("hostel@t.local")
        self.assertEqual(self.post(client, "/login/2fa", "/login/2fa", code=codes[0]).status_code, 302)
        client, _ = self.login("hostel@t.local")
        self.assertEqual(self.post(client, "/login/2fa", "/login/2fa", code=codes[0]).status_code, 200)

    def test_secret_is_encrypted_and_disabling_needs_the_password(self):
        secret, _ = self.enable()
        blob = self.raw("SELECT totp_secret_enc FROM users WHERE email='hostel@t.local'")[0][0]
        self.assertNotIn(secret.encode(), bytes(blob))
        client, _ = self.login("hostel@t.local")
        code = sec.totp_now(secret, at=time.time() + 30)
        self.post(client, "/login/2fa", "/login/2fa", code=code)
        self.post(client, "/account/2fa/disable", "/account", password="wrong")
        self.assertEqual(self.raw("SELECT totp_enabled FROM users WHERE email='hostel@t.local'")[0][0], 1)
        self.post(client, "/account/2fa/disable", "/account", password=PW)
        self.assertEqual(self.raw("SELECT totp_enabled FROM users WHERE email='hostel@t.local'")[0][0], 0)

    def test_repeated_wrong_codes_lock_the_account(self):
        self.enable()
        for _ in range(5):
            client, _ = self.login("hostel@t.local")
            self.post(client, "/login/2fa", "/login/2fa", code="123456")
        _, resp = self.login("hostel@t.local")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("temporarily locked", resp.get_data(as_text=True))


class RoutingAndValidationTests(Base):
    def test_each_category_is_routed_to_the_right_role(self):
        student, _ = self.login("s1@t.local")
        cases = [("hostel", "", "hostel_officer"), ("security", "", "security_officer"),
                 ("welfare", "", "student_affairs_officer"), ("academic", "course_registration", "academic_affairs_officer"),
                 ("academic", "other_academic", "academic_affairs_officer"), ("academic", "result_issue", "exams_records_officer"),
                 ("academic", "records_discrepancy", "exams_records_officer")]
        for category, sub, role in cases:
            ref = self.submit(student, category, sub)
            self.assertEqual(self.raw("SELECT assigned_role FROM complaints WHERE reference=?", (ref,))[0][0], role)

    def test_input_validation(self):
        student, _ = self.login("s1@t.local")
        bad = [dict(category="nonsense", title="Valid title", description="d" * 30),
               dict(category="hostel", title="abc", description="d" * 30),
               dict(category="hostel", title="Valid title", description="too short"),
               dict(category="academic", subcategory="", title="Valid title", description="d" * 30)]
        for data in bad:
            data.setdefault("subcategory", "")
            data["csrf_token"] = self.token(student, "/complaints/new")
            resp = student.post("/complaints/new", data=data)
            self.assertEqual(resp.status_code, 200)
        self.assertEqual(self.raw("SELECT COUNT(*) FROM complaints")[0][0], 0)

    def test_submission_is_rate_limited(self):
        self.app.config["MAX_COMPLAINTS_PER_HOUR"] = 3
        student, _ = self.login("s1@t.local")
        for _ in range(3):
            self.submit(student)
        data = dict(category="hostel", subcategory="", title="One too many", description="d" * 30,
                    csrf_token=self.token(student, "/complaints/new"))
        resp = student.post("/complaints/new", data=data)
        self.assertIn("several complaints recently", resp.get_data(as_text=True))

    def test_priority_defaults_and_deadlines(self):
        student, _ = self.login("s1@t.local")
        normal = self.submit(student, "hostel")
        security = self.submit(student, "security")
        urgent = self.submit(student, "welfare", urgent="1")
        rows = {r[0]: r[1:] for r in self.raw("SELECT reference, priority, due_at, created_at FROM complaints")}
        self.assertEqual(rows[normal][0], "Normal")
        self.assertEqual(rows[security][0], "High")
        self.assertEqual(rows[urgent][0], "Urgent")
        hours = lambda r: (sec.parse_iso(r[1]) - sec.parse_iso(r[2])).total_seconds() / 3600
        self.assertEqual(round(hours(rows[urgent])), 24)
        self.assertEqual(round(hours(rows[security])), 48)
        self.assertEqual(round(hours(rows[normal])), 120)


class AccessControlTests(Base):
    def setUp(self):
        super().setUp()
        self.s1, _ = self.login("s1@t.local")
        self.s2, _ = self.login("s2@t.local")
        self.hostel_ref = self.submit(self.s1, "hostel", title="Broken bed in block A")
        self.security_ref = self.submit(self.s1, "security", title="Threatening messages received",
                                        description="I have been receiving threatening messages from a person.")

    def test_student_cannot_open_another_students_complaint(self):
        self.assertEqual(self.s2.get("/complaints/" + self.hostel_ref).status_code, 404)
        self.assertEqual(self.s1.get("/complaints/" + self.hostel_ref).status_code, 200)

    def test_student_cannot_reach_staff_or_admin_pages(self):
        for path in ["/staff", "/admin", "/admin/audit", "/admin/users", "/staff/complaints/" + self.hostel_ref]:
            self.assertEqual(self.s1.get(path).status_code, 403, path)

    def test_hostel_officer_sees_only_hostel_cases(self):
        hostel, _ = self.login("hostel@t.local")
        listing = hostel.get("/staff").get_data(as_text=True)
        self.assertIn(self.hostel_ref, listing)
        self.assertNotIn(self.security_ref, listing)
        self.assertEqual(hostel.get("/staff/complaints/" + self.hostel_ref).status_code, 200)
        self.assertEqual(hostel.get("/staff/complaints/" + self.security_ref).status_code, 404)

    def test_staff_cannot_change_or_reply_to_another_offices_case(self):
        hostel, _ = self.login("hostel@t.local")
        for action, data in (("status", dict(status="Under Review")), ("respond", dict(message="Not mine to answer")),
                             ("note", dict(message="Nope")), ("priority", dict(priority="Low")),
                             ("reassign", dict(target="hostel_officer"))):
            resp = self.post(hostel, "/staff/complaints/%s/%s" % (self.security_ref, action), "/staff", **data)
            self.assertEqual(resp.status_code, 404, action)
        self.assertEqual(self.raw("SELECT status, priority FROM complaints WHERE reference=?", (self.security_ref,))[0],
                         ("Submitted", "High"))

    def test_admin_cannot_read_complaint_content(self):
        admin, _ = self.login("admin@t.local")
        self.assertEqual(admin.get("/staff/complaints/" + self.security_ref).status_code, 403)
        self.assertEqual(admin.get("/complaints/" + self.security_ref).status_code, 403)
        for path in ("/admin", "/admin/users", "/admin/audit"):
            self.assertNotIn("threatening", admin.get(path).get_data(as_text=True).lower())
        self.assertNotIn("threatening", admin.get("/admin/stats.csv").get_data(as_text=True).lower())

    def test_malformed_reference_is_404(self):
        hostel, _ = self.login("hostel@t.local")
        self.assertEqual(hostel.get("/staff/complaints/1%27%20OR%201=1").status_code, 404)
        self.assertEqual(self.s1.get("/complaints/not-a-reference").status_code, 404)

    def test_unauthorised_attempts_are_logged(self):
        hostel, _ = self.login("hostel@t.local")
        hostel.get("/staff/complaints/" + self.security_ref)
        self.s2.get("/complaints/" + self.hostel_ref)
        actions = [r[0] for r in self.raw("SELECT action FROM audit_log")]
        self.assertGreaterEqual(actions.count("access_denied"), 2)


class WorkflowTests(Base):
    def setUp(self):
        super().setUp()
        self.student, _ = self.login("s1@t.local")
        self.staff, _ = self.login("hostel@t.local")
        self.ref = self.submit(self.student, "hostel")
        self.page = "/staff/complaints/" + self.ref

    def status(self, new):
        return self.post(self.staff, self.page + "/status", self.page, status=new)

    def test_full_workflow_with_student_confirmation_and_rating(self):
        self.status("Closed")
        self.assertEqual(self.raw("SELECT status FROM complaints")[0][0], "Submitted")
        self.status("Under Review")
        self.post(self.staff, self.page + "/respond", self.page, message="A technician will visit on Monday.")
        self.status("Resolved")
        view = self.student.get("/complaints/" + self.ref).get_data(as_text=True)
        self.assertIn("A technician will visit on Monday.", view)
        self.assertIn("Is this resolved?", view)
        self.post(self.student, "/complaints/%s/close" % self.ref, "/student")
        self.assertEqual(self.raw("SELECT status FROM complaints")[0][0], "Closed")
        self.post(self.student, "/complaints/%s/rate" % self.ref, "/student", rating="5", comment="Fast and polite")
        self.post(self.student, "/complaints/%s/rate" % self.ref, "/student", rating="1")
        self.assertEqual(self.raw("SELECT rating FROM complaints")[0][0], 5)
        self.assertEqual(len(self.raw("SELECT 1 FROM status_history WHERE complaint_id=1")), 4)

    def test_student_can_reopen_a_resolved_complaint(self):
        self.status("Under Review"); self.status("Resolved")
        self.post(self.student, "/complaints/%s/reopen" % self.ref, "/student")
        self.assertEqual(self.raw("SELECT status, resolved_at FROM complaints")[0], ("In Progress", None))

    def test_student_cannot_rate_before_resolution(self):
        self.post(self.student, "/complaints/%s/rate" % self.ref, "/student", rating="5")
        self.assertIsNone(self.raw("SELECT rating FROM complaints")[0][0])

    def test_internal_notes_are_hidden_from_the_student(self):
        self.post(self.staff, self.page + "/note", self.page, message="Student seems distressed, handle gently")
        self.assertIn("handle gently", self.staff.get(self.page).get_data(as_text=True))
        self.assertNotIn("handle gently", self.student.get("/complaints/" + self.ref).get_data(as_text=True))

    def test_student_follow_up_reaches_the_office(self):
        self.post(self.student, "/complaints/%s/reply" % self.ref, "/student", message="Any update please? It is urgent.")
        self.assertIn("Any update please", self.staff.get(self.page).get_data(as_text=True))
        notes = self.raw("SELECT message FROM notifications WHERE user_id=(SELECT id FROM users WHERE email='hostel@t.local')")
        self.assertTrue(any("replied" in n[0] for n in notes))

    def test_priority_change_updates_the_deadline(self):
        before = self.raw("SELECT due_at FROM complaints")[0][0]
        self.post(self.staff, self.page + "/priority", self.page, priority="Urgent")
        after = self.raw("SELECT priority, due_at FROM complaints")[0]
        self.assertEqual(after[0], "Urgent")
        self.assertLess(after[1], before)

    def test_overdue_complaints_are_flagged_and_filterable(self):
        self.run_sql("UPDATE complaints SET due_at = '2020-01-01 00:00:00'")
        self.assertIn("Overdue", self.staff.get("/staff").get_data(as_text=True))
        self.assertIn(self.ref, self.staff.get("/staff?overdue=1").get_data(as_text=True))
        self.run_sql("UPDATE complaints SET status='Resolved'")
        self.assertNotIn(self.ref, self.staff.get("/staff?overdue=1").get_data(as_text=True))

    def test_staff_search_and_filters(self):
        self.submit(self.student, "hostel", title="Leaking tap in the bathroom")
        found = self.staff.get("/staff?q=leaking").get_data(as_text=True)
        self.assertIn("Leaking tap", found)
        self.assertNotIn("Broken locker", found)
        self.assertIn(self.ref, self.staff.get("/staff?q=" + self.ref.lower()).get_data(as_text=True))
        self.assertNotIn("Leaking tap", self.staff.get("/staff?status=Closed").get_data(as_text=True))

    def test_reassignment_moves_access_and_notifies(self):
        self.post(self.staff, self.page + "/reassign", self.page, target="student_affairs_officer", reason="Needs the Dean")
        self.assertEqual(self.staff.get(self.page).status_code, 404)
        dean, _ = self.login("welfare@t.local")
        self.assertEqual(dean.get(self.page).status_code, 200)
        self.assertEqual(self.raw("SELECT escalated FROM complaints")[0][0], 1)
        dean_notes = self.raw("SELECT message FROM notifications WHERE user_id=(SELECT id FROM users WHERE email='welfare@t.local')")
        self.assertTrue(any("sent to your office" in n[0] for n in dean_notes))

    def test_notifications_are_created_listed_and_marked_read(self):
        self.post(self.staff, self.page + "/respond", self.page, message="We are looking into it now.")
        self.assertIn("1", re.search(r'bell-count">(\d+)', self.student.get("/student").get_data(as_text=True)).group(1))
        nid = self.raw("SELECT id FROM notifications WHERE user_id=(SELECT id FROM users WHERE email='s1@t.local') ORDER BY id DESC")[0][0]
        resp = self.student.get("/notifications/%d" % nid)
        self.assertEqual(resp.status_code, 302)
        self.assertIn("/complaints/" + self.ref, resp.headers["Location"])
        self.assertEqual(self.raw("SELECT is_read FROM notifications WHERE id=?", (nid,))[0][0], 1)
        self.assertEqual(self.staff.get("/notifications/%d" % nid).status_code, 404)

    def test_csv_export_is_safe(self):
        self.submit(self.student, "hostel", title="=HYPERLINK(\"http://evil\",\"x\") formula")
        resp = self.staff.get("/staff/export.csv")
        self.assertEqual(resp.mimetype, "text/csv")
        body = resp.get_data(as_text=True)
        self.assertIn("Reference,Category,Priority", body)
        self.assertNotIn("HYPERLINK", body)
        self.assertEqual(sec.safe_csv_cell("=1+1"), "'=1+1")
        self.assertEqual(sec.safe_csv_cell("@SUM(A1)"), "'@SUM(A1)")


class AnonymityAndFilesTests(Base):
    def setUp(self):
        super().setUp()
        self.student, _ = self.login("s1@t.local")
        self.other, _ = self.login("s2@t.local")
        self.security, _ = self.login("security@t.local")
        self.hostel, _ = self.login("hostel@t.local")

    def test_anonymous_complaint_hides_the_name_from_staff(self):
        ref = self.submit(self.student, "security", anonymous="1")
        page = self.security.get("/staff/complaints/" + ref).get_data(as_text=True)
        self.assertIn("Anonymous student", page)
        self.assertNotIn("Student One", page)
        self.assertNotIn("CST/20/001", page)
        named = self.submit(self.student, "security")
        self.assertIn("Student One", self.security.get("/staff/complaints/" + named).get_data(as_text=True))

    def upload(self, client, data, name, category="security"):
        form = dict(category=category, subcategory="", title="With evidence", description="x" * 30,
                    csrf_token=self.token(client, "/complaints/new"))
        form["attachments"] = (io.BytesIO(data), name)
        return client.post("/complaints/new", data=form, content_type="multipart/form-data", follow_redirects=True)

    def test_valid_evidence_is_stored_encrypted_and_access_controlled(self):
        resp = self.upload(self.student, PNG, "photo.png")
        self.assertIn("photo.png", resp.get_data(as_text=True))
        att = self.raw("SELECT id, stored_name FROM attachments")[0]
        with open(os.path.join(self.tmp, "uploads", att[1]), "rb") as handle:
            on_disk = handle.read()
        self.assertNotIn(b"PNG", on_disk)
        owner = self.student.get("/attachments/%d" % att[0])
        self.assertEqual(owner.status_code, 200)
        self.assertEqual(owner.data, PNG)
        self.assertIn("attachment", owner.headers["Content-Disposition"])
        self.assertEqual(self.security.get("/attachments/%d" % att[0]).status_code, 200)
        self.assertEqual(self.other.get("/attachments/%d" % att[0]).status_code, 404)
        self.assertEqual(self.hostel.get("/attachments/%d" % att[0]).status_code, 404)
        admin, _ = self.login("admin@t.local")
        self.assertEqual(admin.get("/attachments/%d" % att[0]).status_code, 404)

    def test_fake_and_oversized_files_are_rejected(self):
        for data, name in ((b"MZ" + b"\x00" * 200, "evil.png"), (b"<?php echo 1; ?>", "shell.pdf"),
                           (PNG + b"x" * (2 * 1024 * 1024 + 10), "huge.png")):
            resp = self.upload(self.student, data, name)
            self.assertIn("Attachment skipped", resp.get_data(as_text=True), name)
        self.assertEqual(self.raw("SELECT COUNT(*) FROM attachments")[0][0], 0)
        self.assertEqual(sec.detect_upload_type(b"%PDF-1.4 ..."), ("pdf", "application/pdf"))
        self.assertEqual(sec.detect_upload_type(b"\xff\xd8\xff\xe0 data"), ("jpg", "image/jpeg"))


class DataProtectionTests(Base):
    def test_complaint_text_is_encrypted_in_the_database(self):
        student, _ = self.login("s1@t.local")
        self.submit(student, "security", title="Very private title",
                    description="Very private description about a harassment incident.")
        title_blob, desc_blob = self.raw("SELECT title_enc, description_enc FROM complaints")[0]
        self.assertNotIn(b"private", bytes(title_blob))
        self.assertNotIn(b"harassment", bytes(desc_blob))

    def test_html_in_complaint_is_escaped(self):
        student, _ = self.login("s1@t.local")
        ref = self.submit(student, "welfare", title="<script>alert(1)</script> title",
                          description="<img src=x onerror=alert(1)> plus enough words to pass")
        body = student.get("/complaints/" + ref).get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", body)
        self.assertNotIn("<img src=x", body)
        self.assertIn("&lt;script&gt;", body)

    def test_reference_numbers_are_random(self):
        student, _ = self.login("s1@t.local")
        refs = {self.submit(student) for _ in range(3)}
        self.assertEqual(len(refs), 3)
        for ref in refs:
            self.assertRegex(ref, r"^BUK-[0-9A-F]{8}$")

    def test_old_databases_are_upgraded_automatically(self):
        old = os.path.join(self.tmp, "old.db")
        conn = sqlite3.connect(old)
        conn.executescript("""CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, full_name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE, matric_no TEXT UNIQUE, password_hash TEXT NOT NULL, role TEXT NOT NULL,
            is_active INTEGER NOT NULL DEFAULT 1, failed_logins INTEGER NOT NULL DEFAULT 0, locked_until TEXT,
            created_at TEXT NOT NULL);
            CREATE TABLE complaints (id INTEGER PRIMARY KEY AUTOINCREMENT, reference TEXT NOT NULL UNIQUE,
            student_id INTEGER NOT NULL, category TEXT NOT NULL, subcategory TEXT, title_enc BLOB NOT NULL,
            description_enc BLOB NOT NULL, status TEXT NOT NULL DEFAULT 'Submitted', assigned_role TEXT NOT NULL,
            created_at TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE responses (id INTEGER PRIMARY KEY AUTOINCREMENT, complaint_id INTEGER NOT NULL,
            author_id INTEGER NOT NULL, message_enc BLOB NOT NULL, created_at TEXT NOT NULL);""")
        conn.commit(); conn.close()
        create_app({"TESTING": True, "DATABASE": old, "SECRET_KEY": "k", "DATA_KEY": Fernet.generate_key(),
                    "UPLOAD_FOLDER": os.path.join(self.tmp, "u2")})
        conn = sqlite3.connect(old)
        cols = {r[1] for r in conn.execute("PRAGMA table_info(complaints)")}
        self.assertTrue({"priority", "anonymous", "due_at", "rating"} <= cols)
        self.assertIn("is_internal", {r[1] for r in conn.execute("PRAGMA table_info(responses)")})
        conn.close()


class AuditAndAdminTests(Base):
    def test_important_actions_are_logged_and_visible_to_the_admin(self):
        student, _ = self.login("s1@t.local")
        ref = self.submit(student)
        staff, _ = self.login("hostel@t.local")
        page = "/staff/complaints/" + ref
        staff.get(page)
        self.post(staff, page + "/status", page, status="Under Review")
        self.post(staff, page + "/respond", page, message="We are looking into it now.")
        self.login("s2@t.local", "WrongPass999")
        actions = {r[0] for r in self.raw("SELECT action FROM audit_log")}
        for expected in ("login_success", "login_failed", "complaint_submitted", "complaint_viewed",
                         "status_changed", "response_added"):
            self.assertIn(expected, actions)
        admin, _ = self.login("admin@t.local")
        listing = admin.get("/admin/audit?action=status_changed").get_data(as_text=True)
        self.assertIn("status_changed", listing)
        self.assertNotIn("<code>login_failed</code>", listing)
        csv = admin.get("/admin/audit.csv")
        self.assertEqual(csv.mimetype, "text/csv")
        self.assertNotIn("Broken locker", csv.get_data(as_text=True))

    def test_admin_dashboard_reports_statistics(self):
        student, _ = self.login("s1@t.local")
        self.submit(student, "hostel"); self.submit(student, "security")
        self.run_sql("UPDATE complaints SET due_at='2020-01-01 00:00:00' WHERE id=1")
        admin, _ = self.login("admin@t.local")
        page = admin.get("/admin").get_data(as_text=True)
        self.assertIn('data-count="2"', page)
        self.assertIn("Overdue", page)
        self.assertIn("Complaints by category", page)
        self.assertIn("Status mix", page)

    def test_admin_account_management(self):
        admin, _ = self.login("admin@t.local")
        self.post(admin, "/admin/users", "/admin/users", full_name="Short Pw", email="short@t.local",
                  role="hostel_officer", password="weak")
        self.assertEqual(self.raw("SELECT COUNT(*) FROM users WHERE email='short@t.local'")[0][0], 0)
        uid = self.raw("SELECT id FROM users WHERE email='hostel@t.local'")[0][0]
        self.post(admin, "/admin/users/%d/toggle" % uid, "/admin/users")
        _, resp = self.login("hostel@t.local")
        self.assertEqual(resp.status_code, 200)
        me = self.raw("SELECT id FROM users WHERE email='admin@t.local'")[0][0]
        self.post(admin, "/admin/users/%d/toggle" % me, "/admin/users")
        self.assertEqual(self.raw("SELECT is_active FROM users WHERE id=?", (me,))[0][0], 1)

    def test_landing_page_is_public_and_branded(self):
        page = self.app.test_client().get("/").get_data(as_text=True)
        self.assertIn("Speak up", page)
        self.assertIn("buk-logo", page)
        self.assertEqual(self.app.test_client().get("/healthz").get_json(), {"ok": True})


if __name__ == "__main__":
    unittest.main(verbosity=2)
