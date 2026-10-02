# Provenance-Pro — Tamper-Evident, Provenance-Aware Audit Logging

Every user and system action is captured, enriched with provenance context, linked into a
SHA-256 hash chain, sealed into Merkle batches, and verified with 8 integrity checks.

## Run locally
```bash
pip install -r requirements.txt
python app.py            # http://localhost:5000
python -m pytest -q      # 14 tests incl. all 5 tampering scenarios
```
Demo accounts (created on first start): `admin / admin123` (set `ADMIN_PASSWORD` to change),
`alice / alice123`, `bob / bob12345`.

## Modules
| # | Module | File |
|---|--------|------|
| 1 | Event capture & authentication (register, login, sessions, file/DB events, IP, failed logins) | `provenance/auth.py` |
| 2 | Context enrichment & allowed transitions | `provenance/context.py` |
| 3 | SHA-256 hash chain, genesis hash, first-failed-record detection | `provenance/hashchain.py` |
| 4 | Merkle batches (4 events each) & SQLite storage | `provenance/merkle.py`, `provenance/db.py` |
| 5 | 8-check verification engine & security dashboard | `provenance/verify.py`, `templates/dashboard.html` |

**Hash:** `Hn = SHA-256(event_type | JSON(user, session, previous event, sequence, timestamp, IP, details) | H(n-1))`, `H0 = SHA-256("PROVENANCE-PRO-GENESIS-BLOCK")`.
Each hash is also stored in the separate `HashChain` ledger, so deleted or inserted rows are detectable.

**Allowed transitions:** `START → Login → Authentication → {Open File, Create File, Database Access, Logout}`;
`Open File / Edit File → Edit File, Delete File, …`; `Logout` ends the session. Illegal actions are refused at capture time.

## The 8 checks
1. Recalculate SHA-256 hash (and compare to HashChain ledger) 2. Previous hash linkage 3. User identity
4. Session validity 5. Previous event 6. Sequence number 7. Allowed transition 8. Merkle root.
Result: **VALID** or **TAMPERING DETECTED**, plus failure types and the first failed record.

## Demo flow
1. Log in as `admin` → dashboard shows **VALID**.
2. Click **Generate normal activity** (or log in as alice in another browser and open/edit files) → still VALID.
3. Click a tamper button — each edits the SQLite DB directly:

| Scenario | What it does | Detected as |
|---|---|---|
| Modification | `Open File` → `Delete File` | HASH_MISMATCH, MERKLE_ROOT_MISMATCH |
| Deletion | removes an `Authentication` event | EVENT_DELETED, PREVIOUS_HASH_MISMATCH, SEQUENCE_GAP, PREVIOUS_EVENT_MISMATCH, INVALID_TRANSITION, MERKLE_ROOT_MISMATCH |
| Insertion | adds a fake `Delete File` (with a correctly computed hash) | NOT_IN_HASH_CHAIN, PREVIOUS_HASH_MISMATCH, SEQUENCE_ALTERED, INVALID_TRANSITION, MERKLE_ROOT_MISMATCH |
| Reordering | swaps `Authentication` and `Open File` | HASH_MISMATCH, SEQUENCE_REORDERED, PREVIOUS_EVENT_MISMATCH, INVALID_TRANSITION |
| Context forgery | changes an event's User ID | HASH_MISMATCH, USER_SESSION_MISMATCH |

4. **Reset demo** restores a clean log.

## Deploy (Render, free)
1. Push this folder to a GitHub repo.
2. On render.com → **New → Blueprint** → select the repo (uses `render.yaml`).
3. Set `ADMIN_PASSWORD` when prompted. `SECRET_KEY` is generated automatically.

Note: the free plan's disk is ephemeral, so the SQLite DB resets to the demo data on each redeploy/restart.
Run with a single gunicorn worker (as configured) since SQLite is the store.
