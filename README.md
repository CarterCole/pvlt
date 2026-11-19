# pvlt

A PII vault in Rust. Personal data is stored as ciphertext in ordinary S3-compatible buckets, with the wrapped
keys and metadata in Postgres. Erasure is **crypto-shredding**: destroy a key and everything it protected is
unreadable, including in copies and backups of the ciphertext. It is meant as a maintained replacement for
Open Privacy Vault (OPV), and serves an OPV-compatible subset of
`/api/v1/facts` so existing clients can switch by changing a URL and a token.

> **Status: pre-alpha. Do not put real personal data in it.**
> There has been no independent cryptography or security review, the format is not frozen, and some production
> gates in [`docs/DECISIONS.md`](docs/DECISIONS.md) are not met (the Linux hardening paths have never been run).

## What works today

- The byte formats ([`docs/FORMAT.md`](docs/FORMAT.md)) with a Python reference and shared test vectors, including a
  streaming format for large documents.
- Key hierarchy (root, domain, subject, data keys), Shamir unseal, and locked key memory (`pvlt-mem`).
- A Postgres key store whose schema refuses malformed or resurrected rows.
- Crypto-shredding of a fact, subject, scope or domain, recorded in a signed, hash-chained **ledger** that is replayed
  after a restore, so erased data stays erased. Expiry, retention and legal hold.
- A signed, hash-chained **audit log**, written before every disclosure; reads fail closed; rollback detection.
- Delegated Biscuit tokens, a registry of issuers, a default-deny JSON policy, dual control for restricted data,
  rate limits, and separate admin and data listeners.
- Large documents encrypted in the browser (TypeScript client), uploaded straight to the bucket, decrypted by the
  holder of the key or streamed by the server.
- Encrypted backups, restore and scrub (`age`), and `pvlt import-opv` with a cutover guide
  ([`docs/MIGRATING.md`](docs/MIGRATING.md)).
- A TLS 1.3-only server with the OPV-compatible `/api/v1/facts` subset and the `/v2` API; Python and TypeScript clients.

How to run it is in [`docs/RUNNING.md`](docs/RUNNING.md). What is planned, and in what order, is in [`docs/PLAN.md`](docs/PLAN.md); the requirements and threat model are
in [`REQUIREMENTS.md`](REQUIREMENTS.md).

## Layout

| Path | What |
|---|---|
| `crates/pvlt-format` | the format, and nothing else: no I/O, no clock, no async |
| `crates/pvlt-mem` | locked key memory and process hardening (the only crate with `unsafe`) |
| `crates/pvlt-core` | key hierarchy, seal/unseal, the engine, the signed logs, the store traits |
| `crates/pvlt-policy` | the access policy language, evaluator and rate limiter (pure logic) |
| `crates/pvlt-server` | the `pvlt` binary, with the Postgres store (`pg`), object store (`bucket`) and Biscuit tokens (`tokens`) as modules |
| `clients/` | Python and TypeScript clients |
| `spec/` | the Python reference implementation and the test vectors |
| `scripts/` | `test-db.sh` (throwaway Postgres), `smoke.sh` (end-to-end run of the real binary), `fake_opv.py` (stand-in for the migration rehearsal) |

## Build and test

```bash
cargo test --workspace                       # database tests are skipped without a database
scripts/test-db.sh start                     # throwaway Postgres in Docker
PVLT_TEST_DATABASE_URL=$(scripts/test-db.sh url) cargo test --workspace -- --include-ignored
scripts/smoke.sh                             # real binary + Postgres + MinIO containers
(cd spec/reference && uv run gen_vectors.py --check)
```

Running the server is described in [`docs/RUNNING.md`](docs/RUNNING.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE).
