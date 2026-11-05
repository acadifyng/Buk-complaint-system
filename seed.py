"""Creates the first accounts. Run it once after installing:   python seed.py

Passwords are typed privately (nothing appears on the screen) or generated for you.
A generated password must be changed by its owner the first time they sign in.

Other ways to run it:
  python seed.py --demo                  sample accounts and sample complaints, to try the system
  python seed.py --generate              no questions; every password is generated and printed once
  python seed.py --set-password EMAIL    change one person's password privately
"""
import argparse
import getpass
import random
import sqlite3
import sys
from datetime import datetime, timedelta, timezone

import db
import rbac
import security as sec
from app import create_app
from core import due_at_for

ACCOUNTS = [
    ("System Administrator", "admin", "admin"),
    ("Hostel Officer", "hostel", "hostel_officer"),
    ("Security Officer", "security", "security_officer"),
    ("Academic Affairs Officer", "academic", "academic_affairs_officer"),
    ("Exams and Records Officer", "exams", "exams_records_officer"),
    ("Student Affairs Officer", "welfare", "student_affairs_officer"),
]


def create_account(full_name, email, role, password=None, matric_no=None):
    """Returns (password, was_generated). Generated passwords must be changed at first sign-in."""
    generated = password is None
    password = password or sec.generate_password(14)
    db.add_user(full_name, email, role, password, matric_no, must_change=generated)
    return password, generated


def ask_password(email):
    while True:
        first = getpass.getpass("  Password for %s (hidden; press Enter to generate one): " % email)
        if not first:
            return None
        problems = sec.validate_password(first, email)
        if problems:
            print("   ", " ".join(problems))
            continue
        if getpass.getpass("  Type it again to confirm: ") != first:
            print("    The two entries did not match. Try again.")
            continue
        return first


def interactive(domain):
    print("\nCreate the administrator and staff accounts. Nothing you type as a password is shown.\n")
    created = []
    for full_name, local, role in ACCOUNTS:
        email = "%s@%s" % (local, domain)
        try:
            password, generated = create_account(full_name, email, role, ask_password(email))
        except sqlite3.IntegrityError:
            print("  %s already exists, skipped." % email)
            continue
        created.append((email, role, password if generated else None))
    print_summary(created)


def print_summary(created):
    generated = [c for c in created if c[2]]
    print("\nDone. %d account(s) created." % len(created))
    if generated:
        print("\nGenerated passwords (shown only now; each person must change theirs at first sign-in):\n")
        for email, role, password in generated:
            print("  %-34s %-28s %s" % (email, rbac.role_label(role), password))
    print()


def demo(domain):
    """Accounts with random passwords plus realistic sample complaints, so every screen has something to show."""
    created = []
    for full_name, local, role in ACCOUNTS:
        email = "%s@%s" % (local, domain)
        try:
            password, _ = create_account(full_name, email, role, sec.generate_password(14))
            db.get_db().execute("UPDATE users SET must_change_password = 0 WHERE email = ?", (email,))
        except sqlite3.IntegrityError:
            continue
        created.append((email, role, password))
    for i, name in enumerate(["Aisha Bello", "Musa Ibrahim", "Fatima Sani"], start=1):
        email = "student%d@%s" % (i, domain)
        try:
            password, _ = create_account(name, email, "student", sec.generate_password(14), "CST/22/CYB/%04d" % i)
            db.get_db().execute("UPDATE users SET must_change_password = 0 WHERE email = ?", (email,))
            created.append((email, "student", password))
        except sqlite3.IntegrityError:
            pass
    conn = db.get_db()
    conn.commit()
    ids = {r["email"]: r["id"] for r in conn.execute("SELECT id, email FROM users")}
    vault = __import__("flask").current_app.extensions["vault"]
    samples = [
        ("hostel", None, "Broken ceiling fan in Block C", "The ceiling fan in room C12 stopped working two weeks ago and the room is unbearably hot at night.", "Normal", 0, 6, ["Under Review", "In Progress", "Resolved"], 5),
        ("security", None, "Harassment near the library path", "A group of people have been following female students on the path behind the library after 9pm.", "High", 1, 3, ["Under Review"], None),
        ("academic", "result_issue", "Missing CS101 result", "My CS101 result does not appear on the portal although I sat the exam last semester.", "Normal", 0, 9, ["Under Review", "In Progress"], None),
        ("welfare", None, "Scholarship payment delay", "My scholarship stipend for this session has not been paid and I cannot afford feeding.", "Urgent", 0, 2, [], None),
        ("academic", "course_registration", "Unable to register COM 301", "The portal rejects my COM 301 registration saying there is a clash that does not exist.", "Normal", 0, 12, ["Under Review", "Resolved", "Closed"], 4),
    ]
    staff_for = {"hostel_officer": "hostel", "security_officer": "security", "academic_affairs_officer": "academic",
                 "exams_records_officer": "exams", "student_affairs_officer": "welfare"}
    for n, (cat, sub, title, text, prio, anon, days_ago, steps, rating) in enumerate(samples):
        role = rbac.route_complaint(cat, sub)
        student_id = ids["student%d@%s" % (n % 3 + 1, domain)]
        staff_id = ids["%s@%s" % (staff_for[role], domain)]
        created_at = (datetime.now(timezone.utc) - timedelta(days=days_ago)).strftime(sec.TIME_FORMAT)
        cur = conn.execute(
            "INSERT INTO complaints (reference, student_id, category, subcategory, title_enc, description_enc, status, "
            "assigned_role, created_at, updated_at, priority, anonymous, due_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (sec.new_reference(), student_id, cat, sub, vault.encrypt(title), vault.encrypt(text), "Submitted", role,
             created_at, created_at, prio, anon, due_at_for(prio, created_at)))
        cid = cur.lastrowid
        conn.execute("INSERT INTO status_history (complaint_id, status, changed_by, note, created_at) VALUES (?,?,?,?,?)",
                     (cid, "Submitted", student_id, "Complaint submitted", created_at))
        when = datetime.strptime(created_at, sec.TIME_FORMAT)
        for step in steps:
            when += timedelta(hours=random.randint(5, 30))
            stamp = when.strftime(sec.TIME_FORMAT)
            conn.execute("UPDATE complaints SET status = ?, updated_at = ?, resolved_at = CASE WHEN ? = 'Resolved' THEN ? "
                         "ELSE resolved_at END, closed_at = CASE WHEN ? = 'Closed' THEN ? ELSE closed_at END WHERE id = ?",
                         (step, stamp, step, stamp, step, stamp, cid))
            conn.execute("INSERT INTO status_history (complaint_id, status, changed_by, note, created_at) VALUES (?,?,?,?,?)",
                         (cid, step, staff_id, None, stamp))
            if step == "Under Review":
                conn.execute("INSERT INTO responses (complaint_id, author_id, message_enc, created_at) VALUES (?,?,?,?)",
                             (cid, staff_id, vault.encrypt("We have received your complaint and it is now under review."), stamp))
        if rating:
            conn.execute("UPDATE complaints SET rating = ? WHERE id = ?", (rating, cid))
    conn.commit()
    print_summary(created)
    print("Passwords above are random and belong to these demo accounts only.\n")


def set_password(email):
    row = db.get_db().execute("SELECT id FROM users WHERE email = ?", (email.lower(),)).fetchone()
    if row is None:
        sys.exit("No account with that email.")
    password = ask_password(email)
    if password is None:
        sys.exit("No password entered. Nothing was changed.")
    db.get_db().execute("UPDATE users SET password_hash = ?, must_change_password = 0, failed_logins = 0, "
                        "locked_until = NULL, password_changed_at = ? WHERE id = ?",
                        (sec.hash_password(password), sec.now_iso(), row["id"]))
    db.get_db().commit()
    print("Password updated for %s." % email)


def main():
    parser = argparse.ArgumentParser(description="Create accounts for the BUK complaint system.")
    parser.add_argument("--domain", default="buk.local", help="email domain for staff accounts (default: buk.local)")
    parser.add_argument("--demo", action="store_true", help="create demo accounts and sample complaints")
    parser.add_argument("--generate", action="store_true", help="generate every password, no questions")
    parser.add_argument("--set-password", metavar="EMAIL", help="change one account's password privately")
    args = parser.parse_args()
    app = create_app()
    with app.app_context():
        if args.set_password:
            set_password(args.set_password)
        elif args.demo:
            demo(args.domain)
        elif args.generate or not sys.stdin.isatty():
            created = []
            for full_name, local, role in ACCOUNTS:
                email = "%s@%s" % (local, args.domain)
                try:
                    password, _ = create_account(full_name, email, role)
                    created.append((email, role, password))
                except sqlite3.IntegrityError:
                    pass
            print_summary(created)
        else:
            interactive(args.domain)


if __name__ == "__main__":
    main()
