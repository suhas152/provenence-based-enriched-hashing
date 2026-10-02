"""Module 3 — SHA-256 hash chain.

Hn = SHA-256(Event + Context + H(n-1)), H0 = GENESIS_HASH.
"""
import hashlib
import json

GENESIS_HASH = hashlib.sha256(b"PROVENANCE-PRO-GENESIS-BLOCK").hexdigest()

# Context fields bound into every hash (everything except the event type and hashes).
CONTEXT_FIELDS = ("user_id", "session_id", "previous_event", "sequence_number",
                  "timestamp", "ip_address", "details")


def context_of(record):
    return {k: record[k] for k in CONTEXT_FIELDS}


def compute_hash(event_type, context, previous_hash):
    payload = "|".join([
        event_type,
        json.dumps(context, sort_keys=True, separators=(",", ":")),
        previous_hash,
    ])
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def hash_of_record(record):
    """Recalculate the hash of a stored AuditEvents row."""
    return compute_hash(record["event_type"], context_of(record), record["previous_hash"])


def chain_tail(conn):
    """(last sequence number, last hash) — the point the next event links to."""
    row = conn.execute(
        "SELECT sequence_number, current_hash FROM AuditEvents "
        "ORDER BY sequence_number DESC, event_id DESC LIMIT 1").fetchone()
    if row is None:
        return 0, GENESIS_HASH
    return row["sequence_number"], row["current_hash"]


def verify_chain(conn):
    """Recalculate every hash and check linkage. Returns the first failed record."""
    rows = conn.execute(
        "SELECT * FROM AuditEvents ORDER BY sequence_number, event_id").fetchall()
    prev = GENESIS_HASH
    for row in rows:
        if hash_of_record(row) != row["current_hash"]:
            return {"valid": False, "checked": len(rows), "first_failed": dict(row),
                    "failure": "HASH_MISMATCH"}
        if row["previous_hash"] != prev:
            return {"valid": False, "checked": len(rows), "first_failed": dict(row),
                    "failure": "PREVIOUS_HASH_MISMATCH"}
        prev = row["current_hash"]
    return {"valid": True, "checked": len(rows), "first_failed": None, "failure": None}
