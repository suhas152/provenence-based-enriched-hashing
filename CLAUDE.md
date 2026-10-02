# Provenance-Pro — tamper-evident audit logging

Stack: Python 3.12 + Flask + SQLite (stdlib `sqlite3`, no ORM). Deployed with gunicorn (1 worker) on Render.

## Layout
- `provenance/db.py` — connection, schema (Users, Sessions, AuditEvents, HashChain, MerkleBatches, VerificationResults, Documents)
- `provenance/auth.py` — Module 1: register/login/logout, sessions, event capture helpers
- `provenance/context.py` — Module 2: context enrichment, allowed transitions, `record_event()`
- `provenance/hashchain.py` — Module 3: SHA-256 chain, genesis hash, `verify_chain()`
- `provenance/merkle.py` — Module 4: Merkle roots, batching (BATCH_SIZE events per batch)
- `provenance/verify.py` — Module 5: 8-check verification engine
- `provenance/tamper.py` — the 5 tampering scenarios (edit the DB directly)
- `provenance/seed.py` — demo users + activity
- `app.py` — Flask routes; `templates/` — plain HTML

## Rules
- Keep scope to SPEC.md. No extra features, no fancy UI.
- Library functions take a `conn` argument; Flask opens one per request.
- Run tests: `python -m pytest -q`
- Run locally: `python app.py` → http://localhost:5000 (admin / admin123 unless ADMIN_PASSWORD set)
