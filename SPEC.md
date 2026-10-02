# SPEC — Provenance-Aware Tamper-Evident Audit Logging

1. **Event Capture & Authentication** — registration, login, sessions, login/logout, file open/edit/delete, database access, IP + timestamp on every event, security events (failed logins, registrations).
2. **Context Enrichment & Provenance** — each record holds Event ID, User ID, Session ID, Current Event, Previous Event (in the same session), Sequence Number, Timestamp, Previous Hash. Allowed transitions are enforced at capture time (e.g. Login → Authentication → Open File → Edit File → Logout).
3. **SHA-256 Hash Chain** — `Hn = SHA-256(Event + Context + H(n-1))`, first event uses a fixed genesis hash. Verification returns the first failed record.
4. **Merkle Tree & Storage** — events grouped into batches of 4; a Merkle root is stored per batch. Tables: Users, Sessions, AuditEvents, HashChain, MerkleBatches, VerificationResults.
5. **Verification & Dashboard** — 8 checks (hash recalculation, previous hash, user identity, session validity, previous event, sequence number, allowed transition, Merkle root) → VALID or TAMPERING DETECTED. Dashboard shows totals, valid/tampered counts, batch ID, first failed record, failure type, timestamp, user, session, status.

Tampering demos: modification, deletion, insertion, reordering, context forgery — each must be detected.
