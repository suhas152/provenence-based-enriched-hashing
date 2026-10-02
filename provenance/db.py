"""Database connection and schema (Module 4 storage)."""
import os
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timezone

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_PATH = os.environ.get("PROV_DB", os.path.join(BASE_DIR, "data", "provenance.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS Users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id       TEXT UNIQUE,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'user',
    created_at    TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS Sessions (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id  TEXT UNIQUE,
    user_id     TEXT NOT NULL,
    ip_address  TEXT,
    user_agent  TEXT,
    created_at  TEXT NOT NULL,
    last_seen   TEXT NOT NULL,
    ended_at    TEXT,
    is_active   INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS AuditEvents (
    event_id        INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         TEXT,
    session_id      TEXT,
    event_type      TEXT NOT NULL,
    previous_event  TEXT,
    sequence_number INTEGER NOT NULL,
    timestamp       TEXT NOT NULL,
    ip_address      TEXT,
    details         TEXT,
    previous_hash   TEXT NOT NULL,
    current_hash    TEXT NOT NULL,
    batch_id        INTEGER
);
CREATE INDEX IF NOT EXISTS idx_events_seq ON AuditEvents(sequence_number);
CREATE INDEX IF NOT EXISTS idx_events_session ON AuditEvents(session_id);
CREATE INDEX IF NOT EXISTS idx_events_batch ON AuditEvents(batch_id);
CREATE TABLE IF NOT EXISTS HashChain (
    event_id        INTEGER PRIMARY KEY,
    sequence_number INTEGER NOT NULL,
    previous_hash   TEXT NOT NULL,
    current_hash    TEXT NOT NULL,
    recorded_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS MerkleBatches (
    batch_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    start_event    INTEGER NOT NULL,
    end_event      INTEGER NOT NULL,
    start_sequence INTEGER NOT NULL,
    end_sequence   INTEGER NOT NULL,
    event_count    INTEGER NOT NULL,
    merkle_root    TEXT NOT NULL,
    created_at     TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS VerificationResults (
    result_id          INTEGER PRIMARY KEY AUTOINCREMENT,
    verified_at        TEXT NOT NULL,
    status             TEXT NOT NULL,
    total_events       INTEGER NOT NULL,
    valid_logs         INTEGER NOT NULL,
    tampered_logs      INTEGER NOT NULL,
    first_failed_event INTEGER,
    failure_types      TEXT
);
CREATE TABLE IF NOT EXISTS Documents (
    doc_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id   TEXT NOT NULL,
    name       TEXT NOT NULL,
    content    TEXT NOT NULL DEFAULT '',
    updated_at TEXT NOT NULL,
    deleted    INTEGER NOT NULL DEFAULT 0
);
"""


def now():
    """UTC timestamp, fixed-width so string comparison == time comparison."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")


def connect(path=None):
    path = path or DB_PATH
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    conn = sqlite3.connect(path, timeout=15, isolation_level=None)  # explicit transactions
    conn.row_factory = sqlite3.Row
    return conn


def init_db(conn):
    conn.executescript(SCHEMA)


@contextmanager
def transaction(conn):
    """Serialised write transaction (BEGIN IMMEDIATE locks the chain tail)."""
    if conn.in_transaction:
        yield conn
        return
    conn.execute("BEGIN IMMEDIATE")
    try:
        yield conn
        conn.execute("COMMIT")
    except Exception:
        conn.execute("ROLLBACK")
        raise


def reset_db(conn):
    for table in ("Users", "Sessions", "AuditEvents", "HashChain", "MerkleBatches",
                  "VerificationResults", "Documents"):
        conn.execute(f"DROP TABLE IF EXISTS {table}")  # also clears its AUTOINCREMENT counter
    init_db(conn)
