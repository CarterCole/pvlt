# Decisions log

Working defaults taken while drafting M0 (2026-11-14). Each one is open until the maintainer confirms it. The numbers
refer to REQUIREMENTS.md section 6 ("Open decisions").

| # | Decision | Default taken | Status |
|---|---|---|---|
| 1 | Project name and repo | Working name `pvlt` (from the format's magic bytes) | **open**. Renaming does not change the magic bytes or labels in FORMAT.md. |
| 2 | License | Apache-2.0 | open |
| 3 | Key store default | Postgres only, no embedded backend. The reference deployment already runs Postgres. | **settled**, 2026-11-15. See PLAN.md 3.6. |
| 4 | Policy engine | Small purpose-built evaluator | open |
| 5 | Token format | Biscuit | open |
| 6 | Default AEAD | XChaCha20-Poly1305 for server-side data; AES-256-GCM (suite `0x0003`) required for browser blob uploads | open, see D1 |

## Staging versus production (2026-11-15)

A plaintext listener and an env-var root key were accepted for the testing MVP ("fine as long as prod is
secure"). To make that condition structural and not a promise:

- Every insecure convenience lives behind one Cargo feature, `dev-insecure`: the plaintext listener
  (`--insecure-dev-listener`) and the env/file root-key provider. It is off by default and the release image
  never enables it, so the production binary cannot open a plaintext socket or read a root key from the
  environment. A server built with it logs a warning at every start, and `/readyz` reports `"insecure": true`.
- CI builds the default feature set and fails if either symbol is present in the binary.

**Production gates.** No real PII goes into any deployment until every one of these is true:

| # | Gate | Milestone |
|---|---|---|
| 1 | TLS 1.3 listener only; binary built without `dev-insecure` | M1 |
| 2 | Root key sealed by Shamir shares or a KMS, never in an env var or file | M1 (unseal) |
| 3 | Key and process hardening in `pvlt-mem` (locked arena, no core dumps) | before cutover. **Written and tested on macOS 2026-11-15; Linux is compile-checked only, so not met until it runs on Linux.** |
| 4 | Shred ledger and restore replay, so a shred survives a key-store restore | M2. **Built and tested** (replay on start, restore replay, separate ledger bucket); the ledger bucket must be operated as never-restored. |
| 5 | Delegated, short-lived tokens and vault-side policy; the static compat token is refused (or confined to a narrow policy) | M3. **Built and tested**: the static token is governed by a `compat` policy role. |
| 6 | Audit entry durable before every read; reads fail closed | M4. **Built and tested**, including rollback detection against signed checkpoints. |
| 7 | Key-store WAL archiving, dump retention bounded and `age`-encrypted, volume encryption under Postgres | M2 / ops. Encrypted backups (`age`) are built; WAL archiving and volume encryption are operations work, not done. |
| 8 | Format frozen and an independent cryptography review closed | **open:** before cutover (M6) or only before 1.0 (M7)? Recommend before cutover, since the data is KYC. |

## Key store decisions (2026-11-15)

Taken while writing the Postgres store. None changes FORMAT.md. PLAN.md has the detail.

- A shredded fact or subject stays as a tombstone row with a zeroed key, so a read can say "shredded" and not
  "not found". Open: whether the id and the two HMACs on a tombstone are acceptable metadata about an erased
  person, or the ledger should replace them (M2).
- A shredded subject is not reopened by a later write. Re-admission needs an explicit admin operation.
- The database refuses a malformed, resurrected or half-shredded row, as well as the vault code checking it.
## Postgres version (2026-11-16)

Decision: **the vault's baseline is PostgreSQL 17**, and it also runs on older and newer majors.

- **Tested on** 15.20, 16, 17.10 and 18.1 (the full suite on each, plus repeats); the default test database is
  17. Version 18.1 was run on a third-party build of Postgres 18, not the stock image, so for 18 it is a
  compatibility check only.
- **No gate on the host's Postgres version.** The vault passes its tests on 15, so it can be deployed beside an
  application before or after that application upgrades its own database.
- **Open, not blocking:** a separate Postgres for the vault instead of a database in the application's.
  Reasons to separate: its own credentials and network, so one leaked application database password does not
  reach the key store (threat T2); its own backup retention and WAL archiving, which the 35-day bound on key-store
  dumps needs; and a version chosen for the vault. Reason to share: one fewer thing to run.
- **If the key store shares a server with an application:** its database must be added to that server's backup
  job, and plain SQL dumps of it must be encrypted (threat T3) before the vault holds real keys.

## Format changes after the first draft (2026-11-15)

Made while planning the Rust implementation and writing the Python reference. All are in FORMAT.md and covered
by the vectors; none is frozen. PLAN.md section 1.2 has the reasons.

- `shred.scope` lists `fact_ids` and `object_ids`, and replay shreds by object id.
- `shred.scope` and `shred.subject` carry `bik_version`.
- A wrap context for Ed25519 signing keys (`"sign"`).
- Fact ids MUST be UUIDs.
- Audit entry types and one audit body are specified.
- Blob readers MUST reject non-canonical Padmé padding.

## Deviations from REQUIREMENTS.md

- **D1. KDF and key commitment use HKDF-SHA-256, not BLAKE3** (REQUIREMENTS 3.4). The browser has to derive the
  same keys for direct uploads, and WebCrypto has HKDF-SHA-256 and AES-GCM but not BLAKE3, XChaCha20 or GCM-SIV.
  So v1 has one KDF and a browser suite (AES-256-GCM), which is safe because every unit gets its own derived key
  (FORMAT.md section 3).
- **D2. The object header carries a random `object_id`, not the fact id** (REQUIREMENTS 3.3). Fact ids can be
  supplied by the caller on OPV import (C3), so the bucket key and header use an id the vault always makes itself.
- **D3. Backups use `age` with a hybrid post-quantum recipient**, not raw HPKE (REQUIREMENTS 3.6.4). It is the
  a common tool for bucket backups. The `age` pq recipient version still needs checking.
