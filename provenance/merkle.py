"""Module 4 — Merkle tree batching."""
import hashlib
import os

from .db import now

BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "4"))


def merkle_root(hex_hashes):
    """Binary Merkle root over event hashes (odd node is paired with itself)."""
    if not hex_hashes:
        return hashlib.sha256(b"").hexdigest()
    level = [bytes.fromhex(h) for h in hex_hashes]
    while len(level) > 1:
        if len(level) % 2:
            level.append(level[-1])
        level = [hashlib.sha256(level[i] + level[i + 1]).digest()
                 for i in range(0, len(level), 2)]
    return level[0].hex()


def create_pending_batches(conn):
    """Seal every full group of BATCH_SIZE unbatched events into a Merkle batch."""
    pending = conn.execute(
        "SELECT event_id, sequence_number, current_hash FROM AuditEvents "
        "WHERE batch_id IS NULL ORDER BY sequence_number, event_id").fetchall()
    created = []
    while len(pending) >= BATCH_SIZE:
        chunk, pending = pending[:BATCH_SIZE], pending[BATCH_SIZE:]
        root = merkle_root([r["current_hash"] for r in chunk])
        cur = conn.execute(
            "INSERT INTO MerkleBatches (start_event, end_event, start_sequence, end_sequence, "
            "event_count, merkle_root, created_at) VALUES (?,?,?,?,?,?,?)",
            (chunk[0]["event_id"], chunk[-1]["event_id"], chunk[0]["sequence_number"],
             chunk[-1]["sequence_number"], len(chunk), root, now()))
        batch_id = cur.lastrowid
        conn.executemany("UPDATE AuditEvents SET batch_id=? WHERE event_id=?",
                         [(batch_id, r["event_id"]) for r in chunk])
        created.append(batch_id)
    return created
