"""Demo users and normal activity."""
import os
import random

from . import auth
from .db import init_db, reset_db

ADMIN_USERNAME = os.environ.get("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "admin123")
DEMO_USERS = [("alice", "alice123", "192.168.1.21"), ("bob", "bob12345", "10.0.0.42")]


def _user_session(conn, username, password, ip, actions):
    user, sid = auth.login(conn, username, password, ip, "seed-script")
    session = {"user_id": user["user_id"], "session_id": sid}
    docs = conn.execute("SELECT * FROM Documents WHERE owner_id=? AND deleted=0",
                        (user["user_id"],)).fetchall()
    for action in actions:
        doc = docs[0]["name"] if docs else "none"
        if action == "Database Access":
            auth.capture(conn, session, action, ip, "query=my_activity")
        else:
            auth.capture(conn, session, action, ip, f"doc={doc}")
    auth.logout(conn, sid, ip)


def simulate_activity(conn, rounds=1):
    """Generate realistic, valid sessions for the demo users."""
    flows = [["Open File", "Edit File"], ["Database Access", "Open File"],
             ["Open File", "Edit File", "Edit File"], ["Open File", "Database Access"]]
    for _ in range(rounds):
        for username, password, ip in DEMO_USERS:
            _user_session(conn, username, password, ip, random.choice(flows))


def seed(conn, fresh=False):
    if fresh:
        reset_db(conn)
    else:
        init_db(conn)
    if conn.execute("SELECT COUNT(*) FROM Users").fetchone()[0]:
        return
    auth.register_user(conn, ADMIN_USERNAME, ADMIN_PASSWORD, "127.0.0.1", role="admin")
    for username, password, ip in DEMO_USERS:
        auth.register_user(conn, username, password, ip)
    _user_session(conn, "alice", "alice123", "192.168.1.21", ["Open File", "Edit File"])
    _user_session(conn, "bob", "bob12345", "10.0.0.42", ["Database Access", "Open File"])
    try:
        auth.login(conn, "alice", "wrong-password", "203.0.113.9")
    except auth.AuthError:
        pass  # failed login is logged as a security event
    _user_session(conn, "alice", "alice123", "192.168.1.21", ["Open File", "Edit File", "Edit File"])
