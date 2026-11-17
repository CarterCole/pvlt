# Open-source PII vault in Rust: what exists, what is needed

Status: draft v0.1, 2026-11-14.

Many applications keep personal data (legal names, dates of birth, ID numbers, shipping addresses, typed
signatures, the keys to encrypted ID photos) in Open Privacy Vault (OPV, image `openprivacyio/opv`), which is no
longer maintained. This document records how such a deployment uses OPV, where that setup falls short, and what a
maintained replacement has to do. The replacement is a Rust service that keeps PII as ciphertext in ordinary
S3-compatible buckets and erases it by **cryptographic shredding**: destroy the key and the data is gone,
wherever copies of the ciphertext ended up. Access is role-based and enforced by the vault, not only by its
callers.

The "reference deployment" below is a web application that runs OPV beside its own Postgres and calls it from a
single backend service. Things that could not be verified are marked **(verify)**. The OPV source was not
checked out, so statements about its internals come from how it is configured and called, not from reading it.

---

## 1. What exists today

### 1.1 Deployment

Two containers from one image, both backed by a database in the application's own Postgres:

| Service | Command | Port | Job |
|---|---|---|---|
| control plane | `controlplane` | 27999 | mints grant tokens (`POST /api/v1/grants`) |
| data plane | `dataplane` | 28000 | stores, reads and deletes facts |

- Config: `OPV_ENCRYPTOR_SECRETBOX_KEYS` (the at-rest encryption keys, an environment variable) and the database
  connection string. The name implies NaCl secretbox encryption of fact values in Postgres **(verify)**.
- The backend reaches the data plane with a URL and one static bearer token, sent as `X-OPV-GRANT-TOKEN`.
- The token is minted once, for methods `POST` and `GET` on `/api/v1/facts` and `/api/v1/facts/*`.
- The database is dumped with the rest of the application's database, so tokens live in the same database as the
  data, and a restored dump leaves the token stale and in need of re-minting.

### 1.2 The API an OPV client calls

A typical client uses only three data-plane calls:

| Call | Request | Response the client relies on |
|---|---|---|
| store | `POST /api/v1/facts` `{fact_type_slug, scope_custom_id, value}` | JSON with `id` (a UUID string) |
| get | `GET /api/v1/facts/{id}` | JSON with `value` (string) |
| delete | `DELETE /api/v1/facts/{id}` | 200, 204 or 404 all count as success |

All values are strings. Binary things (AES keys) are base64 text; structured things (a shipping address) are a
JSON string in a `json` fact. Auth failures, network errors and non-2xx all collapse to `None`/`False` in the
client, and every caller treats `None` on store as "vault unavailable" and aborts without committing.

Fact types in use: `ascii`, `base64`, `json`. OPV validates a value against its fact type and rejects unknown
slugs with 400 (it ships about 55 built-ins such as `email`, `ssn`, `phonenumber`, `address`). The reference
deployment never uses anything past those three.

`scope_custom_id` is a free-form string. Two patterns exist: meaningful scopes (`kyc-doc:<id>`,
`model-release:<id>`, `physical-order:<id>`) and meaningless random UUIDs (legal name and birthdate facts).
OPV is never asked to list or search by scope, and the client never reads it back.

### 1.3 What is stored

The application's own database holds only the opaque fact id (a `*_fact_id` string column). The facts are:

- legal name, date of birth (approved and draft) and ID document number of an account holder;
- for each uploaded document (ID photo, selfie, release form): the AES-256-GCM key, and the bucket key of the
  encrypted file, sometimes a display name and original filename;
- the same identity fields for other people named in a document, plus an email address and a typed signature;
- a shipping address, as one `json` fact: name, line1, line2, city, state, postal code, country, phone.

Fact lifetimes differ: an address is deleted 30 days after an order closes, identity data is deleted when a
verification is cancelled or cleared, and the rest lives until someone deletes it.

### 1.4 How documents (ID photos) work

The vault never holds the image. The flow is:

1. The backend generates a random 32-byte AES-256-GCM key and a bucket key, stores each as a fact (scope
   `kyc-doc:<id>`), and returns a presigned PUT URL.
2. The **browser** encrypts the file with that key and uploads the ciphertext.
3. A verifier asks for access; the backend logs a row, reads both facts, and returns the key plus a presigned GET
   URL. The **browser** downloads and decrypts. Nothing is decrypted server-side.

So the vault's role is to hold the keys and paths to blobs that live in a bucket. That is already the shape of
crypto-shredding, except that the key store is OPV's Postgres and deletion is a row delete.

### 1.5 Access control today

All real policy is in the calling application, not in the vault.

- The vault enforces one thing: a request carries the single grant token. Any code holding the token can read any
  fact in the domain. There is no per-subject check, no role, no per-request identity, and (from the token's
  declared methods) no distinction between callers **(verify)**.
- The application's policy function allows a read for the data subject themselves, for a `verifier` role, or for
  an earned, order-scoped fulfillment grant (a seller reading the address of a paid, undelivered order). Admin
  roles deliberately do **not** grant PII read, and impersonation denies everything. A test walks the code and
  fails the build if any read skips that gate.
- Disclosure logging is application-side, in bespoke tables, and the log row is committed before the key is read
  ("a disclosure that can't be logged doesn't happen"). Other PII reads are not logged **(verify)**.

### 1.6 Known gaps and observations

These are what the replacement has to fix, or at least not repeat.

1. **Deletion is not erasure.** Deleting a fact removes a row. Every earlier database dump still contains the
   deleted value, encrypted under a key that is still in the environment. A 30-day purge therefore does not make
   data unrecoverable until every dump ages out. Dump retention was not checked.
2. **One key for everything.** One secretbox key set protects every fact, and it sits in an environment variable
   next to the database it protects. Nothing can be shredded by subject, and rotating it means re-encrypting
   everything.
3. **Authorization is single-layer.** A leaked or misused grant token, or one bug in the application, reads the
   entire vault. The vault cannot express "only the verifier role" or "only this user's own facts".
4. **Possible grant/method mismatch.** The token is minted for `POST` and `GET` only, but the application calls
   `DELETE`. Either production minted it differently, or OPV did not enforce the method list, or deletes fail with
   403 and callers that purge refuse. Worth testing against a running instance **(verify)**.
5. **Static, non-expiring bearer token** stored in the same database as the data, invalidated on every restore,
   and re-minted by hand.
6. **A startup health check that writes a fact on every boot** leaves a junk fact behind per restart. A health
   check must not write.
7. **Scope is not a subject.** Several scopes are random UUIDs, so "everything about user X" cannot be answered by
   the vault. The caller has to supply the subject explicitly.
8. **Failure is silent in the client.** Every failure mode is `None`/`False`, so callers cannot tell "not found"
   from "denied" from "vault down".
9. **No native audit, retention or TTL.** The application reimplements all three in cron jobs and bespoke tables.
10. **Unmaintained upstream.** No security fixes, and the data plane is a single point of failure for the identity
    data and shipping addresses behind it.
11. Encrypting the bucket backup to an offline recipient (an offline recovery key) is a pattern worth keeping.

---

## 2. What we need

### 2.1 Goals

1. **Crypto-shredding as the erasure primitive.** Erasing a fact, a scope or a whole subject means destroying
   key material. Ciphertext copies in buckets, replicas and backups become permanently unreadable.
2. **Regular buckets.** Ciphertext lives in any S3-compatible store (MinIO, AWS S3, R2, B2), or a local
   directory for dev. No vendor features required: no object lock, KMS, versioning or lifecycle rules for
   correctness.
3. **Role-based access enforced in the vault.** A leaked service credential must not read everything. The vault
   evaluates policy per request, bound to the end user's identity and role, and fails closed.
4. **Complete, tamper-evident audit** that is written before any disclosure.
5. **Small, boring, memory-safe, auditable.** One Rust binary, a small dependency tree, no `unsafe` outside a
   reviewed module.
6. **Drop-in for OPV clients**, then better. An OPV-compatible `/api/v1/facts` subset so a client changes one URL
   and a token, with a native API next to it for the improvements.
7. **Open source and maintained**, reusable by anyone with the same problem (KYC, addresses, signatures).

### 2.2 Non-goals

- Not a general secrets manager or KMS. No dynamic secrets, no TLS CA.
- Not a database: no search or query over plaintext. Lookups are by ID. Optional blind indexes only (see 3.9).
- Not an identity provider. It verifies tokens minted by trusted issuers; it does not authenticate end users.
- No homomorphic or searchable encryption.
- No guarantee against a fully compromised running vault process (it must hold keys in memory to function).
  Limit what that exposes instead (see the threat model).

### 2.3 Threat model

| # | Adversary / event | Required outcome |
|---|---|---|
| T1 | Reads the bucket (misconfigured ACL, leaked bucket creds, provider insider) | Sees only ciphertext of padded, uniform-looking objects. No plaintext, no key, no useful metadata. |
| T2 | Dumps the key store DB but not the root key | Nothing decryptable. |
| T3 | Steals both bucket and key-store backups from before a shred | Cannot recover shredded data (see 3.6, the hard case). |
| T4 | Steals the app's service credential | Can read only what that credential's policy allows, rate-limited and logged. Cannot read other subjects or other domains, cannot administer. |
| T5 | Compromised or buggy calling app | Cannot assert a role it was not delegated. Cannot read a subject's data without a token naming that subject or a role the app is allowed to assert. Bulk reads are rate-limited and alert. |
| T6 | Malicious or curious admin of the vault | Cannot read data by being admin. Administration (roles, shredding, key ops) is separate from reading. Admin actions are in the audit log. Break-glass reads need dual control. |
| T7 | Tampered or truncated audit log | Detected by hash chain and external checkpoints. |
| T8 | Operator or attacker wants to *prevent* a legal erasure by resurrecting keys from backup | Restore tooling re-applies the shred ledger (see 3.6). |
| T9 | Network attacker | TLS 1.3 (rustls) or mTLS only. No plaintext listener. |
| T10 | Harvest-now-decrypt-later | Long-lived confidentiality of stored data does not depend on classical public-key crypto alone (see 3.4). |

Out of scope: a compromised host kernel, a malicious CPU, physical memory attacks beyond mlock/zeroize.

### 2.4 Functional requirements

**Facts (small values: names, DOBs, numbers, addresses, signatures, keys)**

- F1. Create a fact: `{domain, subject, scope, type, value, [retention]}` → `id`. Value is bytes up to a
  configured limit (default 64 KiB); UTF-8 text and JSON are first-class types.
- F2. Read a fact by id. Returns value and metadata.
- F3. Delete (shred) a fact by id. Idempotent. 404 and already-gone return success, matching today.
- F4. Shred by scope (all facts with scope S) and by subject (all facts with subject U). O(1) in key operations
  for subject shred.
- F5. Typed validation: a small built-in set (`text`, `json`, `bytes`/`base64`, `email`, `date`, `phone`,
  `country`) with an optional validator; unknown type → 400. We do not need OPV's full 55.
- F6. Per-fact `expires_at` or `retain_days` with an automatic shred sweep, plus a `legal_hold` flag that blocks
  deletion and expiry. Replaces hand-written purge jobs.
- F7. Atomic multi-fact create (a KYC document's key + path) so callers never leave half a record.
- F8. Re-bind: change a fact's scope without re-encrypting (for example promoting a draft date of birth to an approved one).

**Blobs (ID photos, releases)**

- B1. First-class encrypted blobs in the bucket, so the vault is no longer only a key holder. Chunked AEAD
  streaming for large objects, constant memory.
- B2. Direct client upload and download through presigned URLs, with the client doing the encryption using a
  vault-issued data key, matching today's flow. Server-side streaming decrypt as an option for backends that
  want it.
- B3. Shredding a blob destroys its key; best-effort delete of the object follows.
- B4. Optional public-key "drop box": a client encrypts to a role's public key without ever contacting the
  vault (v2, see 3.8).

**Access and administration**

- A1. Domains (tenants) with separate keys, roles and audit streams.
- A2. Roles and policies, editable by an admin API and declarable as code (YAML) for review in git.
- A3. Tokens: short-lived, scoped, verifiable offline, carrying the end-user's subject and roles (see 3.7).
- A4. Rate limits and quotas per principal and per role. Bulk-read detection with alert hooks.
- A5. Dual-control and break-glass for the most sensitive classes: two distinct approvers, a stated reason, a
  tight TTL.
- A6. Audit query API: "who read subject X in the last 90 days", "everything principal Y touched".

**Operations**

- O1. Seal/unseal with Shamir shares or an external KMS/HSM auto-unseal. Starts sealed. Seal on demand.
- O2. Key rotation: tenant KEK and root key rotate by rewrapping; per-fact re-encryption available but rare.
- O3. Health, readiness and metrics endpoints that never write facts and never log values.
- O4. Backup and restore with the shred ledger replayed on restore (see 3.6).
- O5. Single binary with roles (`data`, `admin`, or both) so admin can sit on a private listener.
- O6. Official container image, Compose example, Kubernetes manifest, and a systemd unit.

### 2.5 Compatibility requirements (OPV clients)

- C1. Serve `POST /api/v1/facts`, `GET /api/v1/facts/{id}`, `DELETE /api/v1/facts/{id}` with the request and
  response shapes in 1.2, and accept `X-OPV-GRANT-TOKEN`. `fact_type_slug` maps `ascii`, `printableascii`,
  `base64`, `json` and the other values clients send onto native types.
- C2. Compat tokens map to a fixed principal and policy, so the existing static-token mode works while a
  client migrates to delegated tokens.
- C3. Accept an admin-supplied fact `id` on import so a client's stored fact-id columns do not need rewriting.
- C4. Optional subject: if the caller does not send one, the vault stores the fact with no subject and subject
  shredding does not cover it. This is a flagged degradation, not a silent default.

---

## 3. Proposed design

### 3.1 Shape of the system

```
                 TLS 1.3 / mTLS
  application backend ────────────────►  vault (Rust, one binary)
  (token issuer)                          ├─ data listener   : facts, blobs, tokens verify, policy eval
                                          ├─ admin listener  : domains, roles, shred, rotate, unseal
                                          ├─ key store       : wrapped keys + metadata (Postgres | embedded)
                                          ├─ audit log       : hash-chained, signed checkpoints
                                          └─ object store    : ciphertext only
                                                      │
                                       S3-compatible bucket(s) (MinIO / S3 / R2 / local dir)
```

The bucket holds only ciphertext. The key store holds only wrapped keys and HMAC-blinded metadata. The root
secret lives in a KMS/HSM or in Shamir shares and is never written to either. Compromising any one of the three
yields nothing.

### 3.2 Key hierarchy

```
 Root key (RK)            KMS/HSM, or sealed by Shamir shares; never stored in the clear
   └─ Domain KEK          one per domain, wrapped by RK, versioned
        └─ Subject key    one per (domain, subject), wrapped by the domain KEK
             └─ Data key (DEK)   one per fact or blob, wrapped by the subject key
```

Why two layers below the domain: **shredding is a key deletion at the right level.**

| To erase | Destroy | Cost |
|---|---|---|
| one fact or blob | its wrapped DEK row | O(1) |
| all of a subject's data | the subject key | O(1), however many facts |
| a whole domain | the domain KEK | O(1) |

Facts created without a subject get a per-scope pseudo-subject so scope shred still works.

Rules:

- All keys are 256-bit, from the OS CSPRNG. KEKs derive nothing from user input.
- Wrapping uses the same committing AEAD as data (3.4). The wrap context binds `domain`, `subject`, `id`,
  `key_version`, so a wrapped key cannot be moved to another fact.
- Key material in memory is `zeroize`d on drop and held in `mlock`ed pages. Core dumps and ptrace disabled.
- Subject keys are cached in memory with a short TTL, so a shred is effective on the next request, not on cache
  expiry (shred evicts the cache entry first).

### 3.3 Storage layout

**Object store**: one object per fact or blob, key `v1/<domain-id>/<2 hex>/<128-bit random id>`, no timestamp, no
user id, no extension. Content is `header || ciphertext`:

```
magic "PVLT" | version | suite id | domain id | fact id | key version | nonce | padded ciphertext | tag
```

The header is also the AEAD associated data, so any edit to it fails authentication. Plaintext is padded to a
size class (Padmé or fixed 256 B / 1 KiB / 4 KiB blocks for facts) so a name and an address are not
distinguishable by length.

**Key store**, one row per fact: `id, domain, subject_hmac, scope_hmac, type, object_key, size_class,
wrapped_dek, subject_key_version, state (active | shredded), created_at, expires_at, legal_hold, shredded_at`.
Subject and scope are stored as keyed HMACs (a domain-level blind-index key), so a key-store dump does not reveal
user ids. The audit log and the admin API take the plain subject and hash it on the way in.

The key store is behind a `KeyStore` trait:

- **Postgres** (default for HA; transactions across rows; `sqlx`).
- **Embedded** (`redb` or SQLite, for single-node and dev).
- Both need linearizable writes: a shred must be visible to every replica before it returns.

The object store is behind the `object_store` crate (S3, GCS, Azure, local FS) so MinIO and others work without
custom code.

### 3.4 Cryptographic choices

Chosen to be current and conservative; all selectable by `suite id` in the header so we can migrate.

| Need | Choice | Notes |
|---|---|---|
| Fact/DEK/KEK encryption | **XChaCha20-Poly1305** (default) or AES-256-GCM-SIV | 192-bit random nonces remove the nonce-reuse problem. GCM-SIV is the nonce-misuse-resistant alternative for FIPS-leaning users. |
| Key commitment | HKDF-BLAKE3 derives `(enc_key, commit_tag)` from each DEK and the tag is stored and checked | Plain AEADs are not key-committing; commitment closes partitioning-oracle style attacks if a wrapped key is ever swapped. |
| Large blobs | STREAM-style chunked AEAD (64 KiB chunks, counter nonce, last-chunk flag) | Same construction family as `age` and Tink streaming AEAD; detects truncation and reordering. |
| Key derivation | HKDF-SHA-256 / BLAKE3 with domain-separation labels | Never reuse a key across purposes. |
| Passphrase sealing | Argon2id (RFC 9106 params), for the dev/embedded seal | |
| Secret sharing | Shamir over GF(256) for unseal shares | Threshold set per deployment, e.g. 3 of 5. |
| Asymmetric wrap (drop box, shares to operators, offline recovery) | **HPKE (RFC 9180)** with a **hybrid KEM: X25519 + ML-KEM-768** | Addresses harvest-now-decrypt-later (T10) for any ciphertext an attacker could collect and later break. |
| Signatures (tokens, audit checkpoints) | Ed25519; ML-DSA as a second signature for audit checkpoints (optional, v2) | |
| Blind index | HMAC-SHA-256 with a per-domain key | Dedup (see 3.9). |
| TLS | rustls, TLS 1.3 only, optional mTLS | |

Symmetric 256-bit keys are already quantum-resistant at a Grover-halved 128-bit margin, so the stored-data path
needs no PQ primitive; PQ only matters where a public key protects a secret that outlives today's algorithms.

Rust crates to evaluate: `chacha20poly1305`, `aes-gcm-siv`, `hkdf`, `blake3`, `argon2`, `hpke`, `ml-kem`,
`ed25519-dalek`, `vsss-rs` or `sharks`, `zeroize`, `secrecy`, `object_store`, `axum`, `rustls`, `sqlx`,
`biscuit-auth`, `proptest`, `cargo-fuzz`. Prefer RustCrypto and audited crates; no home-rolled primitives.

### 3.5 Read, write and shred paths

**Create.** Authorize → generate DEK → pad and encrypt with the AAD header → `PUT` ciphertext to the bucket →
insert wrapped DEK and metadata in one key-store transaction → return `id`. If the bucket write succeeds but the
key-store insert fails, the object is unreachable garbage (no key) and a sweeper deletes it. The reverse order
is forbidden, because a key row pointing at nothing is a visible error and an unkeyed object is merely waste.

**Read.** Authorize → write the audit entry and wait for it to commit → look up row (reject if `shredded`) →
unwrap DEK via subject key → fetch object → verify header and tag → decrypt → return. If the audit write fails
the read fails. Decrypted values never go in logs or error messages.

**Shred.** Authorize → append a signed tombstone to the shred ledger → in one transaction mark rows `shredded`
and overwrite `wrapped_dek` with zeros (or delete the subject key) → evict caches → best-effort delete the
object(s). Return only after the transaction commits. The tombstone holds ids and a timestamp, no data.

### 3.6 Making shredding hold up against backups (the hard case)

Crypto-shredding is only as strong as the weakest surviving copy of the key. Ciphertext copies are harmless; the
risk is a backup of the **key store** from before the shred. Requirements:

1. **Shred ledger.** An append-only, signed list of every shred (fact, scope, subject, domain). It is replicated
   to a place that is never rolled back (a separate bucket, plus the audit stream). It contains no key material
   and no PII.
2. **Restore replays the ledger.** `vault restore` refuses to bring up a key store without applying every
   tombstone newer than the backup: it re-shreds before it opens the listener. A restore that skips the ledger
   fails a startup check (the ledger head hash must match the key store's recorded head).
3. **Bounded backup retention for key-store dumps.** Defaults to 35 days, documented as the outer bound on how
   long a shredded key could exist in a backup, and the answer to "how long until erasure is final".
4. **Backup wrapping.** Key-store backups are encrypted to an offline HPKE recipient (hybrid KEM), the usual pattern
   for bucket backups. A stolen backup is unreadable without that offline key.
5. **Subject keys are the unit of backup scrubbing.** A tool, `vault scrub-backup`, rewrites a backup with
   the shredded subject keys zeroed, so retention can be cut short for a specific erasure request.

State the guarantee plainly in docs: *erasure is complete immediately in the live system, and complete in
backups when replay runs or retention expires, whichever is first.*

### 3.7 Role-based access, enforced by the vault

**Principals.** (a) **Services** (the application's backend) authenticate with mTLS or an Ed25519-signed assertion and are
the only things that talk to the data listener. (b) **End users** never connect; their identity reaches the vault
inside a token a trusted service mints.

**Request token.** For each operation the service presents a short-lived (≤60 s), single-purpose token, e.g.
Biscuit (attenuable, verifiable offline, datalog checks), carrying:

```
issuer: app-backend     subject: user:1234 (the data subject, optional)
caller: user:77        roles: [verifier]      purpose: kyc-review
resource: fact:<id> | scope pattern | subject   request_id   expiry
```

The vault verifies the signature against the issuer's registered public key, then evaluates its **own** policy on
those claims. It does not trust a claim just because it is signed: the issuer is only allowed to assert roles its
registration lists (so a compromised service cannot invent a `root` role the policy does not grant to it).

**Policy.** Roles map to permissions over (domain, fact type or scope pattern, action). Actions: `create`,
`read`, `shred`, `list-meta`, `rotate`, `admin`. Conditions are limited and explicit: `caller == subject` (self
access), `has_role`, `purpose in [...]`, `grant.present` (an order-scoped fulfillment grant carried as a
caveat). A typical application's rules become, in the vault:

```yaml
roles:
  verifier:   # the only staff role that can read identity
    allow: [{ types: [identity, doc_key, doc_path, signature], actions: [read] }]
    require: { purpose: [kyc-review, dispute], reason: true }
  admin:      # no PII read; can act on non-PII only
    allow: []
  data-subject:
    allow: [{ types: ["*"], actions: [read], when: caller == subject }]
  fulfillment:   # seller of a paid, undelivered order
    allow: [{ types: [address], actions: [read], when: grant.order_open }]
  app-backend:   # the service itself: can create and shred, cannot read without a user token
    allow: [{ types: ["*"], actions: [create, shred] }]
    deny_read_without_user_token: true
```

Defaults are deny. Policy is versioned, signed by an admin, and the vault records the policy hash with every
audit entry.

**Limits.** Per-principal and per-role request rates and daily read quotas (a verifier reading 500 documents an
hour is an alert, not a feature). Reads of a configured `restricted` class require **dual control**: a second
distinct approver token (or a time-boxed break-glass token with a reason), valid for minutes. `restricted` is
where ID-document keys and ID numbers go.

**Admin separation.** The admin listener and its credentials are separate from data access. Admin can create
domains, register issuers, edit policy, rotate keys, shred and unseal. Admin cannot read a fact. Granting
oneself a reading role is itself an audited, dual-controlled admin action, matching the "grant yourself
`verifier` first, deliberately" rule applications already follow.

### 3.8 Blobs and the document flow

Keep the reference deployment's good property (the vault never sees the document and the server never decrypts) and make it native:

1. `POST /v2/blobs` → vault creates a DEK, a wrapped record, and a presigned PUT URL. The DEK is returned to the
   uploader **once**.
2. Browser encrypts (STREAM AEAD, same format as the server uses) and uploads straight to the bucket.
3. `POST /v2/blobs/{id}/complete` → vault verifies the object exists and its header and size are well-formed,
   flips state to `ready`.
4. A reader with an allowed role calls `GET /v2/blobs/{id}/access`: the audit entry is committed, then the vault
   returns `{dek, presigned_get_url}`. The browser decrypts.
5. Shredding the blob destroys the wrapped DEK; the object may be deleted afterwards or left.

v2 adds **drop box**: a role publishes an HPKE hybrid public key; a client encrypts directly to it, the bucket
holds the ciphertext, and only an authorized reviewer with the private key (itself shred-able) can decrypt.
This also gives threshold review (M of N reviewers must contribute shares) for the very highest classes.

### 3.9 Audit log

- Append-only, **hash-chained**: each entry commits to the previous entry's hash, the policy hash and the
  request id. Periodic **signed checkpoints** (Ed25519) are written to a separate bucket and optionally to an
  external transparency sink, so truncation or rewriting is detectable.
- Entry: time, domain, principal, caller identity, roles asserted, purpose and reason, action, `fact_id`,
  `subject_hmac`, outcome, denial reason. **Never values.**
- Written and durable **before** a read returns. Reads fail closed if the log is unavailable.
- Query API for per-subject and per-principal history; export for the subject's own access report.
- This replaces an application's own access-log tables as the source of truth. The application may keep its own
  rows for UI, derived from the vault's.
- Optional blind index (`POST /v2/blind-index`, per-domain HMAC key): lets an application detect duplicate identities
  without the plaintext, with the key rotatable and shredable per domain.

### 3.10 API surface

- `/api/v1/facts` OPV-compatible subset (create, get, delete) with the legacy header token, mapped to the
  compat principal. Marked deprecated from day one.
- `/v2/...` native, OpenAPI-described: facts, blobs, shred (fact, scope, subject), subjects, policy, issuers,
  tokens verify, audit query, health/ready/metrics.
- Errors are typed and distinct: `not_found`, `shredded` (gone for good, not a retry), `denied`, `sealed`,
  `rate_limited`, `unavailable`. A caller must be able to tell "vault down" from "denied".
- SDKs: Python, Rust, TypeScript. Generated from the OpenAPI spec.
- `/healthz` and `/readyz` never write a fact. `/readyz` reports sealed state, key-store reachability, bucket
  reachability and ledger head match.

### 3.11 Engineering and trust

- `#![forbid(unsafe_code)]` everywhere except a small reviewed `mem` module (mlock, madvise).
- Tests: known-answer vectors for the format; `proptest` on encrypt/decrypt and header tamper; `cargo-fuzz` on
  the header, token and API parsers; an **end-to-end shred test** (create, snapshot bucket and key store, shred,
  assert the snapshot of bucket + key store minus nothing cannot decrypt; restore the snapshot and assert replay
  re-shreds); concurrency tests for shred versus read races.
- Supply chain: `cargo-deny`, `cargo-audit`, pinned lockfile, reproducible builds, SBOM, signed releases and
  images (sigstore), and CI.
- **Independent cryptography and security review before 1.0.** The format spec (`FORMAT.md`) is written first and
  frozen before the code.
- License: Apache-2.0 recommended (open decision, below). Governance docs: `SECURITY.md` with a disclosure
  address (to be chosen before publication), `CONTRIBUTING.md`.

---

## 4. Migration from OPV

1. **Stand up** the new vault beside OPV with the compat API. Point a staging copy of the application at it and
   run its PII tests.
2. **Inventory** fact ids by reading the `*_fact_id` columns (section 1.3). This is the complete list; OPV has no
   listing call and the application never needed one.
3. **Subject assignment.** For each column the owning user is known from the row. The import script passes that
   user as `subject` and the column as `scope`/type. This is the only point where subject shredding becomes
   possible for existing data, since today's scopes are partly random UUIDs.
4. **Copy.** For each id: `GET` from OPV (needs a token that can read), `POST` to the new vault with the same
   `id` (admin import, C3), read it back and compare a hash. Batch, resumable, no plaintext on disk, logs show
   counts and ids only.
5. **Cut over** the URL and token via configuration. Because ids are preserved, no application table changes.
6. **Switch to delegated tokens** and the native API in a second step: move the application's read-policy rules
   into vault policy (keeping the application check as a second layer), pass `subject` at every `store`, replace
   a startup write with `/readyz`, and use vault TTL for purges.
7. **Retire OPV.** Take a final offline-encrypted backup, then destroy the OPV database, **every dump of it**,
   and `OPV_ENCRYPTOR_SECRETBOX_KEYS`. Until the dumps and that key are gone, deleted PII is still recoverable
   (gap 1).
8. Update backup and restore scripts that name the OPV database.

---

## 5. Milestones

| M | Scope | Done when |
|---|---|---|
| M0 | `FORMAT.md`, threat model, API spec (OpenAPI), key hierarchy doc. No code. | Reviewed and frozen. |
| M1 | Core: key store (Postgres + embedded), object store, facts create/read/delete, XChaCha20-Poly1305 with commitment, seal/unseal, OPV-compat API, health. | A staging deployment of an OPV client passes its PII tests against it. |
| M2 | Shredding complete: subject/scope shred, shred ledger, restore replay, TTL and legal hold, backup tooling. | End-to-end shred test and restore-replay test green. |
| M3 | RBAC: issuers, Biscuit tokens, policy engine, rate limits, dual control, admin listener. | A typical application's verifier, self-access and fulfillment rules pass as vault policy. |
| M4 | Audit: hash chain, checkpoints, query API, fail-closed reads. | Tamper test detects edits and truncation. |
| M5 | Blobs and document flow, STREAM AEAD, presigned upload/download. | KYC upload/review flow works end to end. |
| M6 | Migration tool and cutover in production; OPV retired and dumps destroyed. | Section 4 step 7 complete. |
| M7 | Hybrid-PQ drop box, threshold review, blind index, external security review, 1.0. | Review findings closed. |

M1 to M3 is the minimum that is a real improvement over OPV.

## 6. Open decisions

1. **Project name and repo.** The working name is `pvlt`.
2. **License:** Apache-2.0 (recommended; patent grant, permissive) versus AGPL (forces hosted forks to publish).
3. **Key store default:** Postgres only, or ship the embedded backend from M1. Recommendation: both behind the
   trait, Postgres first.
4. **Policy engine:** a small purpose-built evaluator (recommended for M3, easy to audit) versus Cedar. Revisit
   if policies outgrow roles.
5. **Token format:** Biscuit (offline attenuation, datalog) versus signed JWT/PASETO plus our own caveats.
   Recommendation: Biscuit.
6. **Default AEAD:** XChaCha20-Poly1305 (recommended) versus AES-GCM-SIV, or per-deployment FIPS mode.
7. **Backup retention bound** for key-store dumps (proposed 35 days) and whether deployments want shorter.
8. **Dual control** for `restricted` reads: how many approvers, and who they are in a two-owner company.
9. **Does a deployment need the vault to decrypt documents server-side** (e.g. for automated ID checks), or stay
   browser-decrypt only as today? The latter is the safer default.
10. **How deletions of already-migrated data are proven** to the data subject: an audit export, or a signed
    erasure receipt from the shred ledger (recommended, cheap to add).

## 7. Verify before relying on this document

- Whether OPV enforces the grant's method list, or `DELETE` works in production (gap 4). Test with a throwaway
  fact against the running instance.
- OPV's at-rest scheme and what `OPV_ENCRYPTOR_SECRETBOX_KEYS` actually protects.
- Dump retention for the OPV database, including off-site copies (gap 1).
- Total fact count per column, to size the migration and the quota defaults.
- Which code paths read PII without writing an access-log row (1.5).
