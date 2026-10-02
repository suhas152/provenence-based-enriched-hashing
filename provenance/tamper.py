"""The 5 tampering scenarios. Each edits the database directly, like an attacker
with raw DB access would, bypassing record_event()."""
from .db import transaction
from .hashchain import compute_hash, context_of


class TamperError(Exception):
    pass


def _pick(conn, sql, params=()):
    row = conn.execute(sql, params).fetchone()
    if row is None:
        raise TamperError("No suitable event found - generate some activity first.")
    return dict(row)


# An Authentication event that is followed by more events in its session.
_AUTH_WITH_NEXT = """
    SELECT a.* FROM AuditEvents a
    WHERE a.event_type='Authentication' AND EXISTS (
        SELECT 1 FROM AuditEvents b WHERE b.session_id=a.session_id
        AND b.sequence_number > a.sequence_number AND b.event_type != 'Logout')
    ORDER BY a.sequence_number LIMIT 1"""


def modification(conn):
    """Open File -> Delete File."""
    with transaction(conn):
        ev = _pick(conn, "SELECT * FROM AuditEvents WHERE event_type='Open File' "
                         "ORDER BY sequence_number LIMIT 1")
        conn.execute("UPDATE AuditEvents SET event_type='Delete File' WHERE event_id=?",
                     (ev["event_id"],))
    return f"Modified event #{ev['event_id']}: 'Open File' changed to 'Delete File'"


def deletion(conn):
    """Login -> [Authentication] -> Open File : remove Authentication."""
    with transaction(conn):
        ev = _pick(conn, _AUTH_WITH_NEXT)
        conn.execute("DELETE FROM AuditEvents WHERE event_id=?", (ev["event_id"],))
    return f"Deleted event #{ev['event_id']} (Authentication, session {ev['session_id']})"


def insertion(conn):
    """Insert a forged 'Delete File' event right after an Authentication event.
    The attacker even computes a correct SHA-256 for the fake record."""
    with transaction(conn):
        after = _pick(conn, _AUTH_WITH_NEXT)
        seq = after["sequence_number"] + 1
        conn.execute("UPDATE AuditEvents SET sequence_number = sequence_number + 1 "
                     "WHERE sequence_number >= ?", (seq,))
        fake = {"user_id": after["user_id"], "session_id": after["session_id"],
                "previous_event": "Authentication", "sequence_number": seq,
                "timestamp": after["timestamp"], "ip_address": after["ip_address"],
                "details": "doc=payroll.xlsx"}
        h = compute_hash("Delete File", context_of(fake), after["current_hash"])
        cur = conn.execute(
            "INSERT INTO AuditEvents (user_id, session_id, event_type, previous_event, "
            "sequence_number, timestamp, ip_address, details, previous_hash, current_hash, batch_id) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (fake["user_id"], fake["session_id"], "Delete File", "Authentication", seq,
             fake["timestamp"], fake["ip_address"], fake["details"], after["current_hash"], h,
             after["batch_id"]))
    return f"Inserted fake 'Delete File' event #{cur.lastrowid} at sequence {seq}"


def reordering(conn):
    """Login -> Authentication -> Open File  becomes  Login -> Open File -> Authentication."""
    with transaction(conn):
        a = _pick(conn, """
            SELECT a.event_id AS a_id, a.sequence_number AS a_seq,
                   b.event_id AS b_id, b.sequence_number AS b_seq, b.event_type AS b_type
            FROM AuditEvents a JOIN AuditEvents b
              ON b.session_id = a.session_id AND b.sequence_number = a.sequence_number + 1
            WHERE a.event_type='Authentication' ORDER BY a.sequence_number LIMIT 1""")
        conn.execute("UPDATE AuditEvents SET sequence_number=? WHERE event_id=?", (a["b_seq"], a["a_id"]))
        conn.execute("UPDATE AuditEvents SET sequence_number=? WHERE event_id=?", (a["a_seq"], a["b_id"]))
    return (f"Swapped event #{a['a_id']} (Authentication) with #{a['b_id']} ({a['b_type']}) "
            f"- sequences {a['a_seq']} <-> {a['b_seq']}")


def context_forgery(conn):
    """Re-attribute an event to a different user."""
    with transaction(conn):
        ev = _pick(conn, "SELECT * FROM AuditEvents WHERE session_id IS NOT NULL AND event_type "
                         "IN ('Edit File','Delete File','Open File') ORDER BY sequence_number LIMIT 1")
        other = _pick(conn, "SELECT user_id FROM Users WHERE user_id != ? ORDER BY id LIMIT 1",
                      (ev["user_id"],))
        conn.execute("UPDATE AuditEvents SET user_id=? WHERE event_id=?",
                     (other["user_id"], ev["event_id"]))
    return f"Forged event #{ev['event_id']}: user {ev['user_id']} changed to {other['user_id']}"


SCENARIOS = {
    "modification": modification,
    "deletion": deletion,
    "insertion": insertion,
    "reordering": reordering,
    "context_forgery": context_forgery,
}
