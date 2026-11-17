# Rust implementation plan

Status: M0 to M6 implemented 2026-11-16 (see each milestone's note); M7 open. Drafted 2026-11-15. Follows REQUIREMENTS.md (milestones M0 to M7), FORMAT.md and DECISIONS.md. `pvlt` is
still the working name. Crate versions were checked against crates.io on 2026-11-15 with Rust 1.96.

The plan has four parts: what blocks the first line of Rust, the workspace, the design rules that shape the
code, and the build order.

---

## 1. Before any Rust: finish M0

Two of the three blockers were cleared on 2026-11-15. What remains is the maintainer's review and the freeze.

**1.1 The reference and vectors: done.** `spec/reference/pvlt_ref.py` implements every construction in
FORMAT.md, and `spec/reference/gen_vectors.py` writes 100 vectors to `spec/vectors/` (31 of them `must_fail`).
The generator opens everything it seals, confirms each `must_fail` case fails, and checks HKDF against RFC 5869.
`uv run spec/reference/gen_vectors.py --check` confirms the files regenerate byte for byte. They stay
independent of the Rust code, so the format crate is checked against a second implementation, not itself.

Limit: the reference has only been checked against itself and the libraries under it. Nothing outside it has
reproduced the vectors yet; the Rust crate will be the first.

**1.2 Format holes found while planning: fixed in FORMAT.md**, pending review. H7 turned up while writing the
reference.

| # | Hole | Proposed fix |
|---|---|---|
| H1 | `shred.scope` records only `scope_hmac`. A fact re-bound (F8) to scope B after a backup, then shredded with B, survives a restore: the backup still files it under scope A, so replay misses it. | `shred.scope` also lists the `object_ids` it destroyed. Replay shreds by object id. |
| H2 | Ledger entries hold `subject_hmac` and `scope_hmac` with no BIK version. After a BIK rotation, replay cannot match old entries. | Add `bik_version` to those bodies, or state that the BIK does not rotate in v1. |
| H3 | No wrap context for the ledger signing key and the checkpoint key. | Add `tuple("sign", domain_id, purpose, key_id, root_key_id, u32(root_key_version))` to section 5. |
| H4 | Caller-supplied fact ids (C3) go into ledger entries as strings. A free-form id could carry PII into a log that is never deleted. | Fact ids MUST be UUIDs. The reference deployment's are. |
| H5 | Section 3 points to "section 5" for streams; streams are section 4.2. | Fix the reference. |
| H6 | The audit entry is written before the read, so it cannot hold the outcome. | Define two entry types: `read.grant` (before) and `read.fail` (after, best effort). The audit body is now specified in section 8. |
| H7 | Blob readers checked that padding was zero but not that it was the Padmé length, so one blob had many valid encodings. | Readers MUST check `len(P) == padme(8 + len(data))`. |

The fact vector sizes also changed, to 0, 254, 255, 256, 1023 and 1024 bytes: the old list (254, 255, 1022,
1023) never crossed a size class boundary.

**1.3 Decisions that change the code.** DECISIONS.md 4 to 6 are still open and the plan assumes the defaults
taken there. Decision 3 is settled: the key store is Postgres only (see 3.6).

---

## 2. Workspace

One Cargo workspace, six crates. The split follows review boundaries, not tidiness: the format crate and the
unsafe crate are the two pieces an outside reviewer reads line by line.

```
pvlt/
├─ Cargo.toml                workspace, shared lints, pinned versions
├─ deny.toml                 cargo-deny: licences, advisories, banned crates
├─ spec/                     Python reference, vectors (M0)
├─ crates/
│  ├─ pvlt-format/           FORMAT.md and nothing else. No I/O, no async, no clock.
│  ├─ pvlt-mem/              the only crate with `unsafe`: locked key arena, process hardening
│  ├─ pvlt-core/             engine: key hierarchy, traits, fact/blob/shred paths, logs, policy
│  ├─ pvlt-store/            the Postgres key store and its migrations
│  ├─ pvlt-server/           the `pvlt` binary: listeners, HTTP APIs, CLI subcommands
│  └─ pvlt-client/           Rust SDK (uses pvlt-format for client-side blob encryption)
├─ fuzz/                     cargo-fuzz targets
└─ tests/                    end-to-end tests against Postgres and MinIO containers
```

| Crate | Owns | Must not |
|---|---|---|
| `pvlt-format` | suites, seal/open, object header, fact padding, Padmé, STREAM, wrapped keys, blind ids, log entries, canonical JSON, entry hashes, signatures | touch the network, disk, clock or an async runtime |
| `pvlt-mem` | `KeyArena` (one `mmap`ed, `mlock`ed, no-dump region with guard pages, 32-byte slots), core-dump and ptrace disabling | know what the keys are for |
| `pvlt-core` | `Vault` engine, `KeyStore` and `RootKeyProvider` traits, unseal, logs, policy evaluation, token verification, sweepers | know about HTTP |
| `pvlt-store` | Postgres SQL, migrations, the linearizable-write guarantee | hold plaintext or unwrapped keys |
| `pvlt-server` | axum routers, TLS, extractors, error mapping, config, CLI | contain crypto or policy logic |
| `pvlt-client` | typed client for `/v2`, blob encrypt and decrypt | |

Every crate except `pvlt-mem` has `#![forbid(unsafe_code)]`. Workspace lints deny `clippy::unwrap_used`,
`clippy::expect_used`, `clippy::indexing_slicing` and `clippy::dbg_macro` outside tests.

### 2.1 Dependencies

| Need | Crate | Version | Note |
|---|---|---|---|
| XChaCha20-Poly1305 | `chacha20poly1305` | 0.11 | RustCrypto |
| AES-256-GCM | `aes-gcm` | 0.11 | suite `0x0003` |
| AES-256-GCM-SIV | `aes-gcm-siv` | 0.12 | behind a feature, off by default |
| HKDF, SHA-256, HMAC | `hkdf` 0.13, `sha2` 0.11, `hmac` 0.13 | | |
| Ed25519 | `ed25519-dalek` | 3.0 | |
| Constant time, wiping | `subtle` 2.6, `zeroize` 1.9 | | |
| NFC | `unicode-normalization` | 0.1 | subjects and scopes |
| Shamir | `blahaj` | 0.7 | **Chosen (2026-11-15).** Not `sharks`: RUSTSEC-2024-0398 (biased polynomial coefficients, unpatched, maintainer unreachable) is real, and `blahaj` is the fork made to fix it. I read its 640 lines: coefficients are drawn uniformly from 0..=255, the share format is `x ‖ y`, and `recover` does no integrity checking, which is why `pvlt-core` wraps each share with a version, root-key id and checksum and verifies the shares at `init`. It draws randomness from `rand`'s thread RNG (a ChaCha seeded from the OS), not directly from the OS. `vsss-rs` was not evaluated. |
| Passphrase seal (dev) | `argon2` | 0.6 | |
| Object store | `object_store` | 0.14 | S3, MinIO, R2, B2, local dir. Presigning through its `Signer` trait. |
| HTTP | `axum` 0.8, `hyper-util`, `tower` | | |
| TLS | `rustls` 0.23, `tokio-rustls` 0.26 | | 0.24 is still a dev release. `aws-lc-rs` provider, TLS 1.3 only. |
| SQL | `sqlx` | 0.9 | `postgres` feature only, runtime-checked queries (no macros that need a live DB at build time) |
| Tokens | `biscuit-auth` | 6.x | 7.0 is alpha. `biscuit-python` can mint compatible tokens. |
| OpenAPI | `utoipa` | 6.0 | spec generated from the handlers; M0's hand-written spec becomes a test fixture |
| Backups | `age` | 0.12 | marked beta, and the hybrid recipient needs checking (FORMAT.md section 9) |
| Tests | `proptest`, `cargo-fuzz`, `testcontainers` | | |

Deferred to M7: `hpke` 0.15, `ml-kem` 0.3.

Two choices differ from the requirements' crate list:

- **No YAML parser in the server.** `serde_yaml` is archived and its successors are young. Policy is hashed and
  signed, so it already needs a canonical form, and that form is the same canonical JSON the logs use. The CLI
  (`pvlt policy compile`) turns reviewed YAML into canonical JSON; the server only reads JSON.
- **Canonical JSON is written by hand** in `pvlt-format`, about 100 lines over fixed structs. FORMAT.md
  restricts entries to ASCII keys, strings, booleans, null and integers below 2^53, so full RFC 8785 number
  formatting is never needed. Tests cross-check it against `serde_json_canonicalizer` and the Python vectors.

---

## 3. Design rules that shape the code

### 3.1 Secrets in an async program

- **No key crosses an `.await`.** A future is a struct that the runtime moves, and moved bytes are not wiped.
  All crypto in `pvlt-format` is synchronous. The engine fetches rows (async), then calls one synchronous
  function that unwraps the chain, decrypts and drops every key before returning.
- Long-lived keys (root, domain KEKs, blind-index keys, signing keys) live in the `Arena`. Short-lived keys
  (subject keys, DEKs) are `EphemeralKey`s: a `Box<[u8; 32]>` wiped on drop. They are boxed, not `Zeroizing<[u8;
  32]>` on the stack as first planned, because moving a stack array copies the bytes and leaves the old copy
  behind, while moving a `Box` moves a pointer.
- Key types have no `Display`, `Clone` or `Serialize`, and a **redacted** `Debug` (`SecretKey(..)`), changed from
  "no `Debug`" so structs that hold keys can still derive `Debug` without a way to print a key. Values are a
  `Plaintext` newtype whose `Debug` prints the length only. Error types never hold a value or key.
- Stated limit: bytes that passed through hyper's and serde's buffers are not wiped. That is documented, not
  hidden.

### 3.2 No subject-key cache

The requirements describe a short-TTL cache that a shred evicts. That only works inside one process; a second
replica would keep serving a shredded key until its TTL ran out. Unwrapping costs one HKDF and one AEAD call
on 32 bytes, and the read needs a key-store query anyway. So the read runs one query that returns the fact
row, the subject-key row and the domain row with their states, and unwraps every time. The key store is the
only authority on whether a key exists. Only domain KEKs are cached, and the same query checks their version
and state.

### 3.3 The key store is the sequencer

Postgres gives the ordering for everything. The bucket is a store of ciphertext and a copy of the
logs that is never rolled back.

- **Create.** Check that the subject key exists and is active, make it if not. Encrypt. `PUT` the object.
  Then one transaction inserts the DEK row and re-checks the subject key with `FOR SHARE`. If a subject shred
  won the race, the insert fails and the object is unkeyed waste for the sweeper.
- **Read.** Authorize, append `read.grant` to the audit log and wait for commit, run the query from 3.2,
  fetch the object, open it.
- **Shred.** Transaction 1 takes the next ledger sequence number and stores the signed entry as `pending`.
  `PUT` the entry to the ledger prefix. Transaction 2 zeroes the wrapped keys, marks the rows and marks the
  entry `applied`. Return. Object deletion follows, best effort. A crash at any point leaves a `pending`
  entry that startup re-applies; every step is idempotent.
- **Restore.** If the bucket's ledger is ahead of the key store's recorded head, apply the missing entries
  before any listener opens. If it is behind or the hashes disagree, refuse to start.

### 3.4 Logs

One module serves the shred ledger and the audit log: entry structs, canonical JSON, the hash chain, a
per-domain head row locked in the transaction that appends. Audit appends are group-committed (one writer
task per domain batches waiting requests into one transaction), because the chain is serial and every read
waits on it. A separate task writes signed checkpoints every 60 s or 1000 entries.

Build this once, in M2, for the ledger. M4 then adds audit entry types, the query API and the tamper test.
Until M4 the engine calls an `Auditor` trait whose M1 implementation writes structured log lines.

### 3.5 Listeners and identity

A hand-written accept loop over `tokio-rustls` and `hyper-util` (about 60 lines) instead of a wrapper crate,
because the client certificate has to reach the request as an extension. Two routers, two sockets:
`data` and `admin`. An extractor turns (client cert or signed assertion, Biscuit token, compat header) into a
`Principal`; handlers cannot be written without one. There is no plaintext listener, not even for health.

Consequence for the "change one URL" promise: an OPV deployment's default is `http://opv-dataplane:28000`. The compat
cutover is a URL, a token and a CA bundle for `httpx`.

### 3.6 Key store: Postgres only (decision 3, settled 2026-11-15)

The reference deployment already runs Postgres, so the key store is a database in that server and there is no embedded backend.
Dev and tests use a Postgres container. The `KeyStore` trait stays, as the seam the engine's unit tests fake,
but it has one real implementation.

Tables (M1 has `seal_config`, `domains`, `subject_keys` and `facts`; the rest arrive with their milestones):
`domains`, `subject_keys`, `facts`, `blobs`, `ledger`, `audit`, `log_heads`, `issuers`, `policies`,
`root_keys`, `sign_keys`.

**What Postgres holds at rest.** The vault does not rely on Postgres or its disk for confidentiality.

| Data | Form in Postgres |
|---|---|
| Fact and blob contents | not there at all; ciphertext is in the bucket |
| Every key (KEK, blind-index, subject, DEK, signing) | wrapped by its parent (FORMAT.md section 5) |
| Root key | wrapped by the unseal key, which exists only as Shamir shares or in a KMS |
| Subject and scope | HMAC under the domain's blind-index key |
| Fact id, type, size class, state, timestamps, legal hold | clear |
| Audit and ledger entries (principal, caller id, roles, purpose, fact id, outcome) | clear, hash-chained |

So a dump of the database decrypts nothing (T2), and that holds for every `pg_dump` too. What a dump does
show is the last two rows: metadata, and who accessed which fact id and when. The audit log has to stay
readable to be queried and verified, so it is not encrypted by the vault. Cover it with volume encryption
(LUKS or the provider's encrypted disks) under the Postgres data directory, and keep the existing `age`
encryption of dumps.

The types enforce the first four rows: no `KeyStore` method takes a `Plaintext` or an unwrapped key, so
writing one in clear does not compile.

### 3.7 Object store

`object_store` covers every target bucket. Three things it does not give for free:

- The local-directory backend cannot presign, so dev mode proxies blob upload and download through the vault.
- A presigned `PUT` cannot cap the upload size. `complete` checks the size with `HEAD`, reads the first 104
  bytes with a ranged `GET`, and checks that the length is a valid chunk layout for that header.
- Writes set `application/octet-stream` and no user metadata (FORMAT.md section 7); a test lists a bucket and
  asserts it.

### 3.8 Errors

One `enum VaultError` in `pvlt-core` with the six public codes (`not_found`, `shredded`, `denied`, `sealed`,
`rate_limited`, `unavailable`) plus `invalid`. Commitment mismatch and tag failure are a single variant, as
FORMAT.md section 3 requires. The server maps variants to status codes in one place. The compat router maps
them again to what an OPV client accepts: any 2xx with `id` on store, `value` on get, and 200, 204 or 404 on
delete.

---

## 4. Build order

Each step ends in something that runs. Steps inside a milestone are in dependency order.

### M0 — close out (no Rust)

1. ~~Python reference and vectors (1.1).~~ Done.
2. ~~Fix H1 to H7 in FORMAT.md.~~ Done. The changes were accepted and the Rust started, 2026-11-15.
3. Freeze the format and confirm decisions 4 to 6. Not frozen yet: the Rust crate matched the draft, so a
   later change means regenerating the vectors and updating both implementations.
4. OpenAPI for the compat routes and the M1 slice of `/v2`.

### M1 — core, to "a staging OPV client passes its PII tests"

1. Workspace, lints, CI: `fmt`, `clippy`, tests, `cargo-deny`, `cargo-audit`. **Partly done (2026-11-15):**
   the workspace and lints exist and `cargo fmt`, `cargo clippy -D warnings` and the tests pass locally. Still
   to do: the CI workflow, `deny.toml`, and `cargo-audit`.
2. `pvlt-format`: derive, seal/open, header, fact padding, wrapped keys, blind ids. Done when every vector in
   `derive`, `fact`, `wrap`, `blind` and the matching `tamper` cases pass, with `proptest` round-trips and
   fuzz targets for the header and wrapped-key parsers. **Done except the fuzz targets (2026-11-15):** the crate
   also covers blobs (whole-buffer only) and the signed logs (canonical JSON, hash chain, signatures), and
   passes all 100 Python vectors plus 17 property tests, with and without the `gcm-siv` feature. Details
   below.
3. `pvlt-mem`: arena and process hardening, tested on Linux and macOS. **Done on macOS (2026-11-15):** 17 tests
   pass here. **Linux is compile- and lint-checked only** (`aarch64-unknown-linux-gnu`): the Linux-specific
   calls (`MADV_DONTDUMP`, `MADV_WIPEONFORK`, `prctl`) have not run. Run the suite on a Linux host or in CI
   before the production gate in DECISIONS.md counts it as met.
4. `pvlt-core` key hierarchy: root, KEK, BIK, subject key, DEK; seal and unseal with Shamir shares. **Done
   (2026-11-15)**, with two changes: there is no `RootKeyProvider` trait yet (nothing needs a second provider,
   and the KMS provider is M7), and the passphrase mode is behind the `dev-insecure` feature, to match gate 2 of
   the production gates. Details below.
5. `KeyStore` trait, migrations, the Postgres backend and its test suite. **Done for the M1 slice
   (2026-11-15):** seal config, domains, subject keys and facts, with fact and subject shred. 25 database tests
   pass on PostgreSQL 15.20, 16, 17.10 and 18.1 (the full workspace, plus 10 repeats of the store suite on each of
   15, 17 and 18). The default test database is 17, and 17 is the baseline (DECISIONS.md, "Postgres version").
   The vault works on 15 as well, so the host's Postgres version is not a precondition. Details below.
6. Engine: create, read, shred one fact, as in 3.3 (ledger stubbed), and the orphan-object sweeper. **Done
   (2026-11-16)**, with the shred of a subject as well. Details below.
7. `pvlt-server`: TLS listener, `/healthz`, `/readyz`, compat routes, static compat token mapped to a fixed
   principal, `pvlt init | serve | unseal | seal`. **Done except the `unseal` and `seal` commands** (2026-11-16):
   `init` and `serve` are commands; unsealing and sealing are HTTP calls on the admin listener (`curl` works),
   because a client command needs an HTTPS client in the binary. Details below.
8. Container image and a Compose file with MinIO and Postgres. **Not done.** `scripts/smoke.sh` runs the real
   binary against Postgres and MinIO containers instead, which is the same stack without the image.
9. Run a real OPV client's PII tests against it in staging. **Not done.** What has run is `scripts/smoke.sh`, which
   makes the same three calls such a client makes; it is not a client's own test suite.

M1 has the same access model as OPV (one token). It is for staging only.

**What `pvlt-format` does and does not do yet** (state at the end of the first Rust session):

- It takes the salt as an argument and never reads the OS RNG. The caller generates 24 fresh bytes per seal.
  This keeps the crate free of I/O and makes the vectors reproducible; the cost is that the engine must get
  this right, so `pvlt-core` wraps every call in one function that draws the salt itself.
- Blob `seal` and `open` work on whole buffers. The constant-memory streaming reader and writer are M5.
- Log entries are `serde_json::Value`s. Typed ledger and audit bodies are M2 and M4.
- `Key` is a plain `[u8; 32]` here, and this crate returns keys in `Zeroizing`. The key types that enforce the
  "no `Clone` or `Serialize`, redacted `Debug`" rule from section 3.1 are in `pvlt-mem` and `pvlt-core`.
- Tests: `tests/vectors.rs` replays the Python vectors, including rebuilding every wrap context with the
  crate's builders; `tests/properties.rs` covers round trips, any-bit-flip, truncation (including on chunk
  boundaries), chunk swaps, Padmé bounds, NFC, and a cross-check of the hand-written canonical JSON against
  `serde_json_canonicalizer`.
- The vectors now agree between two independent implementations (Python and Rust), which was the open limit
  in 1.1. The reference and the prose could still share a misreading of the spec; the external review is what
  covers that.

**What `pvlt-mem` and `pvlt-core` do and do not do yet** (2026-11-15):

- `pvlt-mem`: one mapping with guard pages on both sides, 32-byte slots, `mlock`, wipe on drop, and
  `harden_process` (core dumps off; debugger attach denied). Tests prove the slot is zero after a drop and that
  a read of either guard page ends a child process with a signal. `Arena::report()` says which protections it
  actually got, for `/readyz`. Not done: nothing yet refuses to start in production when a protection is off;
  that belongs to the server. A forked child gets a copy of the arena: Linux wipes it in the child
  (`MADV_WIPEONFORK`, not yet run), macOS does not, so the process must not fork.
  `PT_DENY_ATTACH` ends the process if a debugger is already attached, so `harden_process(true)` must not be
  called under `lldb`.
- `pvlt-core::keys`: root key wrapped by an unseal key; per-domain KEK, BIK and BIX wrapped by the root; subject
  keys wrapped by the KEK; DEKs wrapped by the subject key. All wrap contexts come from FORMAT.md section 5, so
  a wrapped key moved to another domain, object, generation, subject or slot fails to open. Every salt is drawn
  here from the OS RNG. Nothing calls `fact::seal` or `blob::seal` yet; the engine does that with the keys.
- `pvlt-core::seal`: `init_shamir` (2 ≤ threshold ≤ shares ≤ 255) returns the shares once and the root key
  unsealed, drops the unseal key, and checks two different share subsets before returning. Shares are 55 bytes
  with a version, threshold, root-key id and 4-byte checksum, printed as `pvlt-share-v1:<hex>`. A mistyped
  character, a share from another vault and two shares with one number and different contents are each refused
  by name. A well-formed but wrong share cannot produce a wrong root key: it fails to open the wrapped root
  (`OpenFailed`). Limit: the unseal key and `blahaj`'s polynomials pass through ordinary heap memory during a
  ceremony and are not wiped.
- `pvlt-core::keyring`: sealed or unsealed state. There is no way to take a `DomainKeys` out of it: `with_domain`
  lends it to a synchronous closure under a read lock, so `seal()` waits for work in flight and afterwards no key
  is left anywhere. The domain cache is only used when the wrapped bytes still match what the key store holds,
  so a shredded or rotated domain is never served from it. Not done: the cache has no size limit (domains are
  few), and nothing yet evicts an entry when the key store changes without a read (a version bump is caught on
  the next read).
- The salt-drawing wrapper the format section promises exists for key wrapping only; the object-sealing
  wrapper comes with the fact path in M1 step 6.
- Tests: 48 in `pvlt-core` (52 with `dev-insecure`), 17 in `pvlt-mem`. They include every 3-subset of a 3-of-5
  ceremony recovering the same root key and every 2-subset being refused, a single-character typo caught at all
  110 positions, shred-a-subject across a fact and a blob, and the limit that a restored backup of a wrapped key
  brings the data back (the reason the ledger exists). The keyring and arena concurrency tests ran 25 times in a
  row without a failure.

**What the `KeyStore` trait and `pvlt-store` do and do not do yet** (2026-11-15):

- **The trait** is in `pvlt-core::store`, with its records. The records can only hold wrapped keys, ids and 32-byte
  blind identifiers, so a plaintext value, subject, scope or unwrapped key cannot be passed to a store. Methods
  return `impl Future + Send`, so engine code can use any implementation from any task, and engine unit tests
  can fake it. `MemKeyStore` in `pvlt-core::memory` is that fake: it keeps the trait's guarantees inside one process
  and one lock, so it tests the engine's logic and not the database's concurrency.
- **The schema** (`migrations/0001_init.sql`): `seal_config`, `domains`, `subject_keys`, `facts`. The database
  enforces what it can, so a vault bug cannot corrupt it: exact byte lengths on every id, hash and wrapped key;
  size classes; a shredded row must hold zeros where its key was; and a trigger that rejects any change to a
  shredded row, so nothing can write a key back. Tested by trying each of those by hand and checking the SQLSTATE
  and constraint name, not just that the statement failed.
- **Shredded rows stay as tombstones** (state `shredded`, key zeroed) instead of being deleted, so a read can tell
  "gone for good" from "never existed", which PLAN.md 3.8 requires. The cost is that the id, subject hash and
  scope hash of a shredded fact stay in the table. They are HMACs, but they are still metadata about a person who
  asked to be erased; decide in M2 whether the ledger or a retention sweep removes them.
- **Ordering of insert against subject shred is proved, not just exercised.** Two tests hold the row lock the way
  the other side would and check that each waits for the other, and one was checked by deleting `FOR SHARE` from
  `insert_fact`: it failed. A third test runs 60 real races as a smoke test only, because both orders leave the
  same final state. `fact_for_read` is one SQL statement so it reads one snapshot, but nothing can test that
  today: with no key rotation, every cross-row inconsistency it would prevent cannot happen yet.
- **A shredded subject is never silently reopened.** `get_or_insert_subject_key` hands back the shredded record
  and inserts nothing, and `insert_fact` under it fails with `SubjectShredded`. Bringing a subject back needs an
  explicit admin operation that does not exist yet.
- **Subject shred was planned for M2 and is here** because it is one UPDATE and the ordering tests need it. It
  does not yet write to a ledger, so **a shred is not safe against restoring an older database until M2**. That
  is the limit `a_restored_backup_of_the_wrapped_key_brings_the_data_back` records at the key level.
- **Not built yet:** the ledger and its append in the shred transaction (M2); scope shred, re-bind, expiry sweep
  and legal-hold changes (M2); `sign_keys` (M2); audit and head tables (M4); issuers and policies (M3); blobs
  (M5). Nothing yet uses two database roles (one that migrates, one that runs), statement timeouts or pool tuning.
  `PgStore::connect` returns the driver's error text, which for a malformed URL could name the host.
- **sqlx 0.9 refuses dynamic SQL** unless it is wrapped in `AssertSqlSafe`. The store has none: every statement is a
  literal with bind parameters. Only the test helpers use it, for database and table names they generate.
- **Dependencies:** TLS for the database link is rustls with `aws-lc-rs` (`ring` and SQLite are not compiled in).
  Passphrase seal config is read and written only with the `dev-insecure` feature; a build without it that finds a
  passphrase-sealed vault refuses with a clear error instead of misreading it.
- **Running the database tests.** They are `#[ignore]`d so `cargo test` is green without a server, which also means
  a plain run reports "25 ignored" and proves nothing about the store. Run `scripts/test-db.sh start`, then
  `PVLT_TEST_DATABASE_URL=$(scripts/test-db.sh url) cargo test -p pvlt-store -- --include-ignored`. The script
  starts a throwaway container on `127.0.0.1:54329` from a local image (default `postgres:17-alpine`), in memory
  and with `fsync` off. Each test gets its own database. `PVLT_TEST_PG_IMAGE=postgres:15-alpine` (or `:18-alpine`)
  tests another major version once that image is pulled. The 18.1 run used the nhost build of Postgres 18 that was
  already on disk, started by hand on port 54330, because the official 18 image was not. It is a real 18.1 server
  but with nhost's configuration, so it is a compatibility check and not a run on the stock image. CI must set the
  variable and pass `--include-ignored`, or the store is untested there.
- **Tests:** 25 with all features. 15 repeats of the suite with six threads: no failures. One test goes through
  the whole path: init with Shamir, store, restart with three shares, read the value back, shred, and see
  `Shredded`.

**What the engine, the object store and the server do and do not do yet** (2026-11-16):

- **Engine** (`pvlt-core::engine`): `create_fact`, `read_fact`, `shred_fact`, `shred_subject`, `ensure_domain` and
  `sweep_orphans`, generic over a `KeyStore`, an `ObjectStore` and an `Auditor`. Every method fetches rows with
  `.await`, then does all key work in one synchronous closure, so no subject key or data key exists while a
  future is suspended. A fact shred works while the vault is sealed (erasure must not wait for an unseal); a
  create, a read and a subject shred need it unsealed.
- **Facts without a subject** (compat, REQUIREMENTS C4) are filed under a pseudo-subject made from the scope, so
  they have a key of their own and a subject shred of the same string does not reach them. Tested.
- **A read of an expired fact is `NotFound`.** Setting `expires_at` is only possible through the engine today;
  the sweeper that shreds due facts is M2.
- **Sweeper:** deletes objects in a domain's prefix that no readable fact holds a key for (a failed create, a
  fact shred whose delete failed, a subject shred), once they are older than a grace period, because a create
  writes the object before the row. Anything under the prefix that the layout did not write is never listed, so
  never deleted. New `KeyStore` method `live_object_ids`; it treats a fact whose subject key is shredded as dead.
- **Object store:** trait in `pvlt-core::objects`; `pvlt-objects` implements it on the `object_store` crate for
  S3-compatible buckets (run against MinIO), a local directory and memory. Not checked: the `Content-Type` and
  metadata a real S3 service attaches (FORMAT.md section 7 asks for none), and presigning (M5).
- **Server** (`pvlt-server`, binary `pvlt`): TLS 1.3 only on its own accept loop; a data listener (`/healthz`,
  `/readyz`, `/api/v1/facts`) and a separate admin listener (`/v2/sys/status`, `/v2/sys/unseal`,
  `/v2/sys/seal`) that binds loopback by default. A default build has no plaintext listener, no local-directory
  store and no secret in an environment variable: the types have no such variant, and the smoke script checks the
  binary for the symbols. Settings come from the environment, secrets from `*_FILE`.
- **Compat routes differ from OPV on purpose:** four fact types only (`ascii`, `printableascii`, `base64`,
  `json`; OPV has about 55 and the rest are a 400); a shredded fact is 410, not 404; an optional
  `subject_custom_id` field is a vault extension. Errors are `{"error", "message"}` with fixed text, never an echo
  of the request; request bodies are parsed by hand for that reason.
- **Unseal over HTTP:** shares go to the admin listener one at a time. Each is checked (checksum, which vault)
  before it is held; duplicates do not count; when enough have arrived the vault tries to unseal and **forgets
  the batch whatever happens**. Sealing needs the admin token. A share crosses TLS to the loopback admin
  listener, and a share is a credential, so the admin listener must stay on loopback or a private network.
- **Found by a test:** `submit_share` held the share lock while calling a method that took it again, which
  deadlocked the second share. The unseal test caught it by hanging; it is fixed and the test now has a mutation
  check for the threshold and the duplicate rule.
- **Tests:** 22 engine tests on in-memory stores (three mutations checked), 5 on the bucket, 15 on the HTTP
  surface, 5 on TLS (a TLS 1.2 client and a plaintext client are refused), 7 on config, a Postgres test for
  `live_object_ids` (mutation checked). `scripts/smoke.sh` runs the real binary with Postgres and MinIO: 31
  checks, passed on 7 consecutive runs after two early exits that I could not reproduce (the script now reports
  where it stops).
- **Not done:** a container image and Compose file; `pvlt unseal` and `pvlt seal` as commands; the
  `/v2` API and its OpenAPI; delegated tokens and policy (M3); the durable audit log and fail-closed reads (M4);
  the shred ledger (M2); rate limits; TLS certificate reload; a statement timeout on the key store; graceful
  draining of open connections on stop (it stops accepting, wipes the keys and exits). **Process hardening is
  fatal in a default build, and the Linux paths have never run** (gate 3), so a default build on Linux is
  unproven until it does.
- **Auto-migration:** `serve` and `init` run the migrations at start with the same database role. Production
  wants a separate role for that (this section's earlier note); not done.

### M2 — shredding that survives backups

**Done.** Differences from the plan: a shred needs the vault unsealed (the ledger entry is signed with a key the root key unwraps); restore replay works while sealed; the ledger may live in its own bucket (`SplitStore`); replayed subject shreds leave tombstones.

1. Log module (3.4) and the real ledger, with signing keys.
2. Subject and scope shred, pseudo-subjects for facts without a subject, re-bind (F8).
3. `expires_at`, `retain_days`, `legal_hold`, the expiry sweeper.
4. `pvlt backup | restore | scrub-backup`, ledger replay at startup, head check in `/readyz`.
5. The end-to-end shred test and the restore-replay test from requirements 3.11, plus shred-versus-read and
   shred-versus-create race tests.

### M3 — access control

**Done**, except `pvlt policy compile | check | sign`: policy is validated and stored by the admin API, and "signed by an admin" is attribution only.

1. Issuer registry and Biscuit verification, including the rule that an issuer may assert only the roles its
   registration lists.
2. Policy model, evaluator, canonical JSON form, `pvlt policy compile | check | sign`.
3. `/v2` facts with delegated tokens; atomic multi-fact create (F7).
4. Admin listener, admin credentials, role separation.
5. Rate limits and quotas (in memory per replica first), dual control and break-glass.
6. A typical application's verifier, self-access and fulfillment rules written as policy and tested as a table of allow/deny cases.

### M4 — audit

**Done.** Rollback behind a signed checkpoint leaves the server up with reads disabled until an admin writes a signed `audit-ack` marker naming exactly the lost (seq, head) pairs; tampering stops the server. Unauthenticated denials are capped at 600 audit entries an hour.

Audit entry types on the M2 log module, group commit, fail-closed reads, checkpoints to a second bucket, query
and export API, tamper and truncation tests.

### M5 — blobs

**Done.** Blobs are rows of `facts` (kind, chunk size, length, ready, pending expiry). Server-side streaming decrypt reads chunks asynchronously rather than on `spawn_blocking`, holding a `BlobReader` across awaits: a deliberate, bounded exception to the no-key-across-await rule.

STREAM in `pvlt-format` (`blob` vectors, truncation and reorder cases), blob records and presigning, the
`complete` check, optional server-side streaming decrypt on `spawn_blocking`, a TypeScript WebCrypto
implementation of suite `0x0003` checked against the same vectors, and the KYC flow end to end.

### M6 — migration

**Built and rehearsed against a stand-in OPV; the production cutover and OPV retirement are deployment steps and have not been done.** See MIGRATING.md. The Python client is stdlib-only and does not do blob encryption.

`pvlt import-opv`: resumable, reads ids and subjects from a CSV that the application exports, copies with the same id,
reads back and compares a hash, logs counts and ids only. Then the Python SDK, cutover and OPV retirement.

### M7 — toward 1.0

Drop box with `hpke` and `ml-kem`, threshold review, the blind-index endpoint, a KMS root-key provider,
external review, reproducible builds, SBOM, signed releases.

---

## 5. Tests

| Layer | What | Where |
|---|---|---|
| Known answers | every vector file, every `must_fail` | `pvlt-format` |
| Properties | seal/open round-trip, any single-byte change fails, pad/unpad canonical | `pvlt-format` |
| Fuzzing | header, wrapped key, log entry, token and HTTP body parsers | `fuzz/` |
| Differential | random inputs through the Rust crate and the Python reference | CI, nightly |
| Store | every `KeyStore` method against a Postgres container; a dump of the test database contains no test plaintext, subject or scope | `pvlt-store` |
| Races | shred against read and against create, many iterations | `tests/` |
| End to end | shred test, restore replay, bucket listing leaks nothing, sealed vault refuses everything | `tests/` with containers |
| Compat | an OPV client's own PII test modules | staging |
| Policy | table of allow/deny cases from a typical application's rules | `pvlt-core` |

---

## 6. Risks

- **`age` hybrid recipient** (D3) is unverified, and the Rust `age` crate is marked beta. If it does not hold
  up, backups fall back to X25519 `age` recipients until M7's HPKE work.
- **RustCrypto is mid-migration** (new major lines across `aead`, `sha2`, `hkdf`). Pin exact versions and
  keep every crypto call behind `pvlt-format` so an upgrade touches one crate.
- **`mlock` limits in containers.** The arena is small and fixed-size; if locking fails the vault refuses to
  start unless a dev flag allows it.
- **Audit throughput** depends on group commit. Measure it in M4 before promising a read rate.
- **Data written between a key-store backup and a restore is lost** (objects exist, keys do not). Shredding
  cannot fix that; the operations guide must recommend WAL archiving for the key store, not nightly dumps.
