"""Role-based access control: roles, complaint categories, priorities and routing rules.

Permissions belong to ROLES, and users receive them only through their role.
Every complaint is routed to exactly one staff role (assigned_role). A staff member
can open a complaint only when it is assigned to their role. Admins manage accounts and
see statistics, but have NO access to complaint content.
"""

ROLE_LABELS = {
    "student": "Student",
    "hostel_officer": "Hostel Management / Maintenance",
    "security_officer": "University Security Unit",
    "academic_affairs_officer": "Academic Affairs",
    "exams_records_officer": "Examinations and Records",
    "student_affairs_officer": "Dean of Student Affairs",
    "admin": "System Administrator",
}

STAFF_ROLES = [
    "hostel_officer",
    "security_officer",
    "academic_affairs_officer",
    "exams_records_officer",
    "student_affairs_officer",
]

CATEGORY_LABELS = {
    "hostel": "Hostel maintenance",
    "security": "Security and harassment",
    "academic": "Academic issues",
    "welfare": "General student welfare",
}

CATEGORY_HINTS = {
    "hostel": "Broken facilities, water, power, cleanliness",
    "security": "Harassment, threats, theft, safety concerns",
    "academic": "Registration, results, records, lecturers",
    "welfare": "Health, finance, accommodation, general support",
}

# Academic complaints are routed to different offices depending on the issue.
ACADEMIC_SUBTYPES = {
    "course_registration": ("Course registration / academic administration", "academic_affairs_officer"),
    "result_issue": ("Examination result issue", "exams_records_officer"),
    "records_discrepancy": ("Records discrepancy", "exams_records_officer"),
    "other_academic": ("Other academic matter", "academic_affairs_officer"),
}

CATEGORY_ROLE = {
    "hostel": "hostel_officer",
    "security": "security_officer",
    "welfare": "student_affairs_officer",
}

STATUSES = ["Submitted", "Under Review", "In Progress", "Resolved", "Closed"]
OPEN_STATUSES = ["Submitted", "Under Review", "In Progress"]

# Which statuses a staff member may move a case to, from the current one.
NEXT_STATUSES = {
    "Submitted": ["Under Review"],
    "Under Review": ["In Progress", "Resolved"],
    "In Progress": ["Resolved"],
    "Resolved": ["In Progress", "Closed"],
    "Closed": [],
}

# Priorities and the time an office has to respond (service-level targets, in hours).
PRIORITIES = ["Low", "Normal", "High", "Urgent"]
PRIORITY_RANK = {name: i for i, name in enumerate(PRIORITIES)}
SLA_HOURS = {"Urgent": 24, "High": 48, "Normal": 120, "Low": 168}

QUICK_REPLIES = [
    "We have received your complaint and it is now under review.",
    "Please visit our office with a valid ID and your matriculation number so we can assist you.",
    "We need more information. Please reply with the date, place and people involved.",
    "Your complaint has been resolved. Please confirm that you are satisfied with the outcome.",
    "We have forwarded your complaint to the office responsible. They will contact you shortly.",
]

MAX_ATTACHMENTS = 3
MAX_ATTACHMENT_BYTES = 2 * 1024 * 1024


def role_label(role):
    return ROLE_LABELS.get(role, role)


def route_complaint(category, subcategory=None):
    """Return the staff role that must handle this complaint, or None if invalid."""
    if category == "academic":
        entry = ACADEMIC_SUBTYPES.get(subcategory)
        return entry[1] if entry else None
    return CATEGORY_ROLE.get(category)


def default_priority(category, urgent=False):
    if urgent:
        return "Urgent"
    return "High" if category == "security" else "Normal"


def can_staff_view(user, complaint):
    return user["role"] in STAFF_ROLES and complaint["assigned_role"] == user["role"]


def can_student_view(user, complaint):
    return user["role"] == "student" and complaint["student_id"] == user["id"]
