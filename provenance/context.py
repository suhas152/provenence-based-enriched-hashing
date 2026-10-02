"""Module 2 — context enrichment, provenance and allowed transitions.

record_event() is the single write path into the audit log: it enriches the
event with context, links it into the hash chain (Module 3) and seals Merkle
batches (Module 4).
"""
from . import hashchain, merkle
from .db import now, transaction

# Events that happen outside a session (security events).
SESSIONLESS_EVENTS = {"Register", "Login Failed"}

_WORK = {"Open File", "Create File", "Database Access", "Logout"}
ALLOWED_TRANSITIONS = {
    None:              {"Login"},
    "Login":           {"Authentication"},
    "Authentication":  set(_WORK),
    "Open File":       _WORK | {"Edit File", "Delete File"},
    "Edit File":       _WORK | {"Edit File", "Delete File"},
    "Delete File":     set(_WORK),
    "Create File":     set(_WORK),
    "Database Access": set(_WORK),
    "Logout":          set(),
}
EVENT_TYPES = sorted({e for v in ALLOWED_TRANSITIONS.values() for e in v} | SESSIONLESS_EVENTS)


class TransitionError(Exception):
    pass


def is_allowed(previous_event, event_type, has_session=True):
    if event_type in SESSIONLESS_EVENTS:
        return not has_session
    if not has_session:
        return False
    return event_type in ALLOWED_TRANSITIONS.get(previous_event, set())


def last_session_event(conn, session_id):
    if not session_id:
        return None
    row = conn.execute(
        "SELECT event_type FROM AuditEvents WHERE session_id=? "
        "ORDER BY sequence_number DESC, event_id DESC LIMIT 1", (session_id,)).fetchone()
    return row["event_type"] if row else None


def record_event(conn, event_type, user_id=None, session_id=None, ip_address=None, details=None):
    """Capture + enrich + hash + store one audit event. Returns the stored record."""
    with transaction(conn):
        previous_event = last_session_event(conn, session_id)
        if not is_allowed(previous_event, event_type, bool(session_id)):
            raise TransitionError(f"{previous_event or 'START'} -> {event_type} is not allowed")
        last_seq, previous_hash = hashchain.chain_tail(conn)
        record = {
            "user_id": user_id,
            "session_id": session_id,
            "previous_event": previous_event,
            "sequence_number": last_seq + 1,
            "timestamp": now(),
            "ip_address": ip_address,
            "details": details,
        }
        current_hash = hashchain.compute_hash(event_type, record, previous_hash)
        cur = conn.execute(
            "INSERT INTO AuditEvents (user_id, session_id, event_type, previous_event, "
            "sequence_number, timestamp, ip_address, details, previous_hash, current_hash) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (user_id, session_id, event_type, previous_event, record["sequence_number"],
             record["timestamp"], ip_address, details, previous_hash, current_hash))
        event_id = cur.lastrowid
        conn.execute(
            "INSERT INTO HashChain (event_id, sequence_number, previous_hash, current_hash, "
            "recorded_at) VALUES (?,?,?,?,?)",
            (event_id, record["sequence_number"], previous_hash, current_hash, record["timestamp"]))
        merkle.create_pending_batches(conn)
    return dict(record, event_id=event_id, event_type=event_type,
                previous_hash=previous_hash, current_hash=current_hash)
