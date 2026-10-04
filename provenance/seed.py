"""Startup data: schema, company drive and the admin account. Demo users/activity are for tests."""
import os
import random

from . import auth
from .company import COMPANY_OWNER, seed_company_drive
from .db import init_db, reset_db

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
DEMO_USERS = [("alice", "alice123", "192.168.1.21"), ("bob", "bob12345", "10.0.0.42")]


def seed(conn, fresh=False):
    """Create the schema, the shared company drive and the admin account.
    The audit log starts with one event: the admin's Register."""
    if fresh:
        reset_db(conn)
    else:
        init_db(conn)
    seed_company_drive(conn)
    if not conn.execute("SELECT COUNT(*) FROM Users").fetchone()[0]:
        auth.register_user(conn, ADMIN_USERNAME, ADMIN_PASSWORD, "127.0.0.1", role="admin")


def _user_session(conn, username, password, ip, actions):
    user, sid = auth.login(conn, username, password, ip, "test-script")
    session = {"user_id": user["user_id"], "session_id": sid}
    doc = conn.execute("SELECT name FROM Documents WHERE owner_id IN (?, ?) AND deleted=0",
                       (user["user_id"], COMPANY_OWNER)).fetchone()
    for action in actions:
        details = "query=my_activity" if action == "Database Access" else f"doc={doc['name']}"
        auth.capture(conn, session, action, ip, details)
    auth.logout(conn, sid, ip)


def demo_data(conn):
    """Test fixture: two users with a few normal sessions and one failed login."""
    seed(conn)
    for username, password, ip in DEMO_USERS:
        auth.register_user(conn, username, password, ip)
    _user_session(conn, "alice", "alice123", "192.168.1.21", ["Open File", "Edit File"])
    _user_session(conn, "bob", "bob12345", "10.0.0.42", ["Database Access", "Open File"])
    try:
        auth.login(conn, "alice", "wrong-password", "203.0.113.9")
    except auth.AuthError:
        pass
    _user_session(conn, "alice", "alice123", "192.168.1.21", ["Open File", "Edit File", "Edit File"])


def simulate_activity(conn, rounds=1):
    """More normal sessions for the demo users (requires demo_data)."""
    flows = [["Open File", "Edit File"], ["Database Access", "Open File"],
             ["Open File", "Edit File", "Edit File"], ["Open File", "Database Access"]]
    for _ in range(rounds):
        for username, password, ip in DEMO_USERS:
            _user_session(conn, username, password, ip, random.choice(flows))
