import pytest

from provenance import auth, hashchain, merkle, seed, tamper
from provenance.context import TransitionError, record_event
from provenance.db import connect, init_db
from provenance.verify import verify_all


@pytest.fixture
def conn(tmp_path):
    c = connect(str(tmp_path / "test.db"))
    init_db(c)
    yield c
    c.close()


@pytest.fixture
def seeded(conn):
    seed.seed(conn)
    return conn


def events(conn):
    return conn.execute("SELECT * FROM AuditEvents ORDER BY sequence_number").fetchall()


# ---- Module 1: authentication & capture --------------------------------------
def test_register_login_logout_logged(conn):
    uid = auth.register_user(conn, "carol", "secret1", "1.2.3.4")
    assert uid == "U101"
    user, sid = auth.login(conn, "carol", "secret1", "1.2.3.4")
    assert sid == "S5001"
    auth.logout(conn, sid, "1.2.3.4")
    assert [e["event_type"] for e in events(conn)] == ["Register", "Login", "Authentication", "Logout"]
    assert all(e["ip_address"] == "1.2.3.4" and e["timestamp"] for e in events(conn))
    assert conn.execute("SELECT is_active FROM Sessions").fetchone()[0] == 0


def test_failed_login_is_security_event(conn):
    auth.register_user(conn, "carol", "secret1")
    with pytest.raises(auth.AuthError):
        auth.login(conn, "carol", "nope", "9.9.9.9")
    assert events(conn)[-1]["event_type"] == "Login Failed"


# ---- Module 2: context & transitions ------------------------------------------
def test_context_fields_and_transitions(conn):
    auth.register_user(conn, "carol", "secret1")
    user, sid = auth.login(conn, "carol", "secret1")
    s = {"user_id": user["user_id"], "session_id": sid}
    ev = auth.capture(conn, s, "Open File")
    assert ev["previous_event"] == "Authentication" and ev["sequence_number"] == 4
    assert ev["user_id"] == "U101" and ev["session_id"] == "S5001"
    with pytest.raises(TransitionError):
        auth.capture(conn, s, "Login")
    with pytest.raises(TransitionError):
        record_event(conn, "Open File", "U101", None)


# ---- Module 3: hash chain ------------------------------------------------------
def test_hash_chain_links_from_genesis(seeded):
    rows = events(seeded)
    assert rows[0]["previous_hash"] == hashchain.GENESIS_HASH
    for prev, cur in zip(rows, rows[1:]):
        assert cur["previous_hash"] == prev["current_hash"]
    assert hashchain.verify_chain(seeded)["valid"]


def test_verify_chain_reports_first_failed(seeded):
    target = events(seeded)[5]
    seeded.execute("UPDATE AuditEvents SET details='x' WHERE event_id=?", (target["event_id"],))
    result = hashchain.verify_chain(seeded)
    assert not result["valid"] and result["first_failed"]["event_id"] == target["event_id"]


# ---- Module 4: Merkle -----------------------------------------------------------
def test_merkle_root_and_batches(seeded):
    h = [hashchain.compute_hash("x", {}, str(i)) for i in range(3)]
    assert merkle.merkle_root(h) == merkle.merkle_root(h + [h[-1]])  # odd node duplicated
    assert merkle.merkle_root(h) != merkle.merkle_root(list(reversed(h)))
    n = len(events(seeded))
    batches = seeded.execute("SELECT * FROM MerkleBatches").fetchall()
    assert len(batches) == n // merkle.BATCH_SIZE
    assert all(b["event_count"] == merkle.BATCH_SIZE for b in batches)


# ---- Module 5: verification + tampering --------------------------------------
def test_clean_log_is_valid(seeded):
    seed.simulate_activity(seeded, rounds=2)
    report = verify_all(seeded)
    assert report["status"] == "VALID", report["failure_types"]
    assert report["tampered_logs"] == 0 and report["first_failed"] is None


EXPECTED = {
    "modification": {"HASH_MISMATCH", "MERKLE_ROOT_MISMATCH"},
    "deletion": {"PREVIOUS_HASH_MISMATCH", "SEQUENCE_GAP", "PREVIOUS_EVENT_MISMATCH",
                 "INVALID_TRANSITION", "MERKLE_ROOT_MISMATCH", "EVENT_DELETED"},
    "insertion": {"PREVIOUS_HASH_MISMATCH", "NOT_IN_HASH_CHAIN", "SEQUENCE_ALTERED",
                  "INVALID_TRANSITION", "MERKLE_ROOT_MISMATCH"},
    "reordering": {"HASH_MISMATCH", "SEQUENCE_REORDERED", "PREVIOUS_EVENT_MISMATCH",
                   "INVALID_TRANSITION"},
    "context_forgery": {"HASH_MISMATCH", "USER_SESSION_MISMATCH"},
}


@pytest.mark.parametrize("scenario", list(tamper.SCENARIOS))
def test_tampering_detected(seeded, scenario):
    assert verify_all(seeded)["status"] == "VALID"
    tamper.SCENARIOS[scenario](seeded)
    report = verify_all(seeded)
    assert report["status"] == "TAMPERING DETECTED"
    assert EXPECTED[scenario] <= set(report["failure_types"]), report["failure_types"]
    assert report["first_failed"] is not None and report["tampered_logs"] > 0


def test_log_keeps_working_after_tamper(seeded):
    tamper.modification(seeded)
    seed.simulate_activity(seeded)  # new events still chain from the stored tail
    assert verify_all(seeded)["status"] == "TAMPERING DETECTED"
