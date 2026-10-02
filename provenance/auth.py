"""Module 1 — authentication, sessions and event capture."""
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash

from .context import record_event
from .db import now, transaction

SESSION_TIMEOUT = timedelta(minutes=30)
SAMPLE_FILES = [("notes.txt", "Meeting notes"), ("report.txt", "Quarterly report draft")]


class AuthError(Exception):
    pass


def register_user(conn, username, password, ip=None, role="user"):
    username = (username or "").strip()
    if len(username) < 3 or len(password or "") < 6:
        raise AuthError("Username must be 3+ chars and password 6+ chars.")
    with transaction(conn):
        if conn.execute("SELECT 1 FROM Users WHERE username=?", (username,)).fetchone():
            raise AuthError("Username already taken.")
        cur = conn.execute(
            "INSERT INTO Users (username, password_hash, role, created_at) VALUES (?,?,?,?)",
            (username, generate_password_hash(password), role, now()))
        user_id = f"U{100 + cur.lastrowid}"
        conn.execute("UPDATE Users SET user_id=? WHERE id=?", (user_id, cur.lastrowid))
        for name, content in SAMPLE_FILES:
            conn.execute("INSERT INTO Documents (owner_id, name, content, updated_at) "
                         "VALUES (?,?,?,?)", (user_id, name, content, now()))
        record_event(conn, "Register", user_id=user_id, ip_address=ip,
                     details=f"username={username}")
    return user_id


def open_session(conn, user_id, ip=None, user_agent=None):
    """Create a session and log Login -> Authentication."""
    with transaction(conn):
        ts = now()
        cur = conn.execute(
            "INSERT INTO Sessions (user_id, ip_address, user_agent, created_at, last_seen) "
            "VALUES (?,?,?,?,?)", (user_id, ip, (user_agent or "")[:200], ts, ts))
        session_id = f"S{5000 + cur.lastrowid}"
        conn.execute("UPDATE Sessions SET session_id=? WHERE id=?", (session_id, cur.lastrowid))
        record_event(conn, "Login", user_id, session_id, ip, "login requested")
        record_event(conn, "Authentication", user_id, session_id, ip, "password verified")
    return session_id


def login(conn, username, password, ip=None, user_agent=None):
    """Returns (user_row, session_id) or raises AuthError (failed attempt is logged)."""
    user = conn.execute("SELECT * FROM Users WHERE username=?", ((username or "").strip(),)).fetchone()
    if user is None or not check_password_hash(user["password_hash"], password or ""):
        record_event(conn, "Login Failed", user_id=user["user_id"] if user else None,
                     ip_address=ip, details=f"username={(username or '')[:50]}")
        raise AuthError("Invalid username or password.")
    return user, open_session(conn, user["user_id"], ip, user_agent)


def logout(conn, session_id, ip=None, reason="user logout"):
    with transaction(conn):
        s = conn.execute("SELECT * FROM Sessions WHERE session_id=? AND is_active=1",
                         (session_id,)).fetchone()
        if s is None:
            return
        record_event(conn, "Logout", s["user_id"], session_id, ip, reason)
        conn.execute("UPDATE Sessions SET is_active=0, ended_at=? WHERE session_id=?",
                     (now(), session_id))


def get_active_session(conn, session_id, ip=None):
    """Return the session row if still valid; expires idle sessions (logged as Logout)."""
    if not session_id:
        return None
    s = conn.execute("SELECT * FROM Sessions WHERE session_id=? AND is_active=1",
                     (session_id,)).fetchone()
    if s is None:
        return None
    last = datetime.strptime(s["last_seen"], "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)
    if datetime.now(timezone.utc) - last > SESSION_TIMEOUT:
        logout(conn, session_id, ip, reason="session timeout")
        return None
    conn.execute("UPDATE Sessions SET last_seen=? WHERE session_id=?", (now(), session_id))
    return s


def capture(conn, session, event_type, ip=None, details=None):
    """Log a file/database event inside an authenticated session."""
    return record_event(conn, event_type, session["user_id"], session["session_id"], ip, details)
