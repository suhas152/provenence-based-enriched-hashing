"""Module 5 — provenance verification engine (8 checks)."""
import json

from .context import is_allowed
from .db import now
from .hashchain import GENESIS_HASH, hash_of_record
from .merkle import merkle_root

CHECKS = {
    1: "Recalculate SHA-256 hash",
    2: "Previous hash linkage",
    3: "User identity",
    4: "Session validity",
    5: "Previous event",
    6: "Sequence number",
    7: "Allowed event transition",
    8: "Merkle root",
}


def verify_all(conn, save=True):
    rows = [dict(r) for r in conn.execute(
        "SELECT * FROM AuditEvents ORDER BY sequence_number, event_id")]
    users = {r["user_id"]: dict(r) for r in conn.execute("SELECT * FROM Users")}
    sessions = {r["session_id"]: dict(r) for r in conn.execute("SELECT * FROM Sessions")}
    ledger = {r["event_id"]: dict(r) for r in conn.execute("SELECT * FROM HashChain")}
    batches = [dict(r) for r in conn.execute("SELECT * FROM MerkleBatches ORDER BY batch_id")]
    batch_ids = {b["batch_id"] for b in batches}

    recomputed = {}
    prev_hash, prev_seq, prev_event_id = GENESIS_HASH, 0, 0
    last_in_session = {}

    for ev in rows:
        fails = []

        def fail(check, code, msg):
            fails.append({"check": check, "check_name": CHECKS[check], "code": code, "message": msg})

        sid, uid, seq = ev["session_id"], ev["user_id"], ev["sequence_number"]

        # 1. Hash recalculation (+ cross-check against the HashChain ledger)
        h = recomputed[ev["event_id"]] = hash_of_record(ev)
        if h != ev["current_hash"]:
            fail(1, "HASH_MISMATCH", "Recalculated hash differs from stored hash")
        led = ledger.get(ev["event_id"])
        if led is None:
            fail(1, "NOT_IN_HASH_CHAIN", "Event has no entry in the HashChain ledger (inserted)")
        elif led["current_hash"] != ev["current_hash"]:
            fail(1, "LEDGER_HASH_MISMATCH", "Stored hash differs from HashChain ledger")

        # 2. Previous hash linkage
        if ev["previous_hash"] != prev_hash:
            fail(2, "PREVIOUS_HASH_MISMATCH", "previous_hash does not match the preceding record")

        # 3. User identity
        if uid is not None and uid not in users:
            fail(3, "UNKNOWN_USER", f"User {uid} does not exist")
        sess = sessions.get(sid) if sid else None
        if sess and sess["user_id"] != uid:
            fail(3, "USER_SESSION_MISMATCH", f"Session {sid} belongs to {sess['user_id']}, not {uid}")

        # 4. Session validity
        if sid:
            if sess is None:
                fail(4, "UNKNOWN_SESSION", f"Session {sid} does not exist")
            elif ev["timestamp"] < sess["created_at"] or (
                    sess["ended_at"] and ev["timestamp"] > sess["ended_at"]):
                fail(4, "OUTSIDE_SESSION", "Event timestamp is outside the session lifetime")
            elif last_in_session.get(sid) == "Logout":
                fail(4, "AFTER_LOGOUT", "Event occurs after the session logged out")
        elif ev["event_type"] not in ("Register", "Login Failed"):
            fail(4, "MISSING_SESSION", "Session-bound event has no session")

        # 5. Previous event (provenance)
        actual_prev = last_in_session.get(sid) if sid else None
        if sid and ev["previous_event"] != actual_prev:
            fail(5, "PREVIOUS_EVENT_MISMATCH",
                 f"Recorded previous event '{ev['previous_event']}' but actual is '{actual_prev}'")

        # 6. Sequence number
        if seq == prev_seq:
            fail(6, "SEQUENCE_DUPLICATE", f"Sequence {seq} is duplicated")
        elif seq != prev_seq + 1:
            fail(6, "SEQUENCE_GAP", f"Expected sequence {prev_seq + 1}, found {seq}")
        if led is not None and led["sequence_number"] != seq:
            fail(6, "SEQUENCE_ALTERED", f"Ledger sequence {led['sequence_number']}, found {seq}")
        if ev["event_id"] < prev_event_id:
            fail(6, "SEQUENCE_REORDERED", "Event appears before an event recorded earlier")

        # 7. Allowed transition
        if not is_allowed(actual_prev, ev["event_type"], bool(sid)):
            fail(7, "INVALID_TRANSITION", f"{actual_prev or 'START'} -> {ev['event_type']} not allowed")

        # 8. (event-level part) batch reference must exist
        if ev["batch_id"] is not None and ev["batch_id"] not in batch_ids:
            fail(8, "UNKNOWN_BATCH", f"Batch {ev['batch_id']} does not exist")

        ev["failures"] = fails
        ev["status"] = "TAMPERED" if fails else "VALID"
        prev_hash, prev_seq = ev["current_hash"], seq
        prev_event_id = max(prev_event_id, ev["event_id"])
        if sid:
            last_in_session[sid] = ev["event_type"]

    # 8. Merkle root per batch (built from *recalculated* hashes)
    batch_report = []
    for b in batches:
        members = [e for e in rows if e["batch_id"] == b["batch_id"]]
        computed = merkle_root([recomputed[e["event_id"]] for e in members])
        ok = (computed == b["merkle_root"] and len(members) == b["event_count"]
              and [e["event_id"] for e in members][:1] == [b["start_event"]]
              and [e["event_id"] for e in members][-1:] == [b["end_event"]])
        batch_report.append(dict(b, computed_root=computed, members=len(members),
                                 status="VALID" if ok else "TAMPERED"))

    # Events present in the HashChain ledger but missing from AuditEvents
    present = {e["event_id"] for e in rows}
    deleted = [{"event_id": eid, "sequence_number": l["sequence_number"],
                "code": "EVENT_DELETED", "check": 2, "check_name": CHECKS[2],
                "message": "Ledger entry has no matching audit event"}
               for eid, l in sorted(ledger.items()) if eid not in present]

    tampered = [e for e in rows if e["failures"]]
    failure_types = sorted({f["code"] for e in tampered for f in e["failures"]}
                           | ({"MERKLE_ROOT_MISMATCH"} if any(b["status"] != "VALID" for b in batch_report) else set())
                           | ({"EVENT_DELETED"} if deleted else set()))
    first = tampered[0] if tampered else (
        {"event_id": deleted[0]["event_id"], "sequence_number": deleted[0]["sequence_number"],
         "event_type": "(deleted)", "failures": [deleted[0]], "status": "DELETED"} if deleted else None)
    if first is None:
        bad_batch = next((b for b in batch_report if b["status"] != "VALID"), None)
        if bad_batch:
            first = {"event_id": bad_batch["start_event"], "batch_id": bad_batch["batch_id"],
                     "event_type": "(batch)", "status": "TAMPERED",
                     "failures": [{"check": 8, "check_name": CHECKS[8], "code": "MERKLE_ROOT_MISMATCH",
                                   "message": "Stored Merkle root does not match"}]}

    check_summary = {n: 0 for n in CHECKS}
    for e in tampered:
        for c in {f["check"] for f in e["failures"]}:
            check_summary[c] += 1
    check_summary[2] += len(deleted)
    check_summary[8] += sum(b["status"] != "VALID" for b in batch_report)

    report = {
        "status": "TAMPERING DETECTED" if failure_types else "VALID",
        "verified_at": now(),
        "total_events": len(rows),
        "valid_logs": len(rows) - len(tampered),
        "tampered_logs": len(tampered) + len(deleted),
        "events": rows,
        "batches": batch_report,
        "deleted": deleted,
        "first_failed": first,
        "failure_types": failure_types,
        "checks": [{"id": n, "name": CHECKS[n], "failures": check_summary[n]} for n in CHECKS],
    }
    if save:
        conn.execute(
            "INSERT INTO VerificationResults (verified_at, status, total_events, valid_logs, "
            "tampered_logs, first_failed_event, failure_types) VALUES (?,?,?,?,?,?,?)",
            (report["verified_at"], report["status"], report["total_events"], report["valid_logs"],
             report["tampered_logs"], first["event_id"] if first else None, json.dumps(failure_types)))
    return report
