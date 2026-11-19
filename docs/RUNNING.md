# Running pvlt

**Pre-alpha. Do not put real personal data in it.** There has been no independent security review, the format is
not frozen, and several production gates in [`DECISIONS.md`](DECISIONS.md) are not met (see "What is not done").
Everything below was run by `scripts/smoke.sh` against Postgres 17 and MinIO unless it says otherwise.

## What it is, in one paragraph

A server that holds personal data as ciphertext in an S3-compatible bucket and the wrapped keys in Postgres.
Erasing a fact, a scope, a subject or a domain destroys keys, so every copy of the ciphertext, including in
backups, becomes unreadable. A signed, hash-chained **shred ledger** survives restoring an old database, and a
signed, hash-chained **audit log** records every disclosure *before* it happens. Access is by short-lived
delegated tokens checked against registered issuers and a default-deny policy, with dual control for the most
sensitive reads. A deprecated `/api/v1` with one static token serves existing Open Privacy Vault clients.

## Settings

All from the environment. A secret is a file named by `NAME_FILE`; a default build refuses the plain variable.

| Variable | Meaning |
|---|---|
| `PVLT_DATABASE_URL` | key store, `postgres://user:pass@host/db`. Migrations run at start. |
| `PVLT_DOMAIN` | a UUID; the domain every request uses. Created on first write. |
| `PVLT_S3_BUCKET`, `PVLT_S3_REGION` (`us-east-1`), `PVLT_S3_ENDPOINT` | the data bucket |
| `PVLT_S3_ACCESS_KEY_ID_FILE`, `PVLT_S3_SECRET_ACCESS_KEY_FILE` | its credentials |
| `PVLT_S3_PATH_STYLE=true`, `PVLT_S3_ALLOW_HTTP=true` | for MinIO on a private network |
| `PVLT_LEDGER_S3_*` | the same settings for a **separate bucket for the ledger and checkpoints**. See below. |
| `PVLT_TLS_CERT`, `PVLT_TLS_KEY` | PEM files. Required: there is no plaintext listener. The certificate needs the `serverAuth` extended key usage (public CAs issue it; a hand-made one must ask for it). |
| `PVLT_LISTEN` (`0.0.0.0:8443`) | the data listener, which applications call |
| `PVLT_ADMIN_LISTEN` (`127.0.0.1:8444`) | admin: unseal, seal, issuers, policy, approvals, audit, import. Keep it on loopback or a private network. |
| `PVLT_COMPAT_TOKEN_FILE` | the `X-OPV-GRANT-TOKEN` value `/api/v1` clients send. Unset: `/api/v1` refuses everything. |
| `PVLT_ADMIN_TOKENS_FILE` | named admins, one `name:token` per line (tokens at least 16 characters, names and tokens unique). **Dual control needs two.** |
| `PVLT_ADMIN_TOKEN_FILE` | a single admin named `admin`, for simple setups |
| `PVLT_BREAK_GLASS=true` | lets one admin approve their own emergency read, for at most five minutes. Off by default. |
| `PVLT_GDPR_MODE=true` | serves the data-subject access and export routes (see "GDPR mode" below). Off by default. |
| `PVLT_GDPR_EXPORT` (`true`), `PVLT_GDPR_ADMIN_INVENTORY` (`true`) | with GDPR mode on, set either to `false` to drop that route |
| `PVLT_MAX_TOKEN_TTL_SECS` (300) | the longest a request token may live; a longer one is refused even if genuine |
| `PVLT_MAX_VALUE_BYTES` (1 MiB), `PVLT_MAX_BLOB_BYTES` (256 MiB) | limits |
| `PVLT_PRESIGN_TTL_SECS` (900) | how long a presigned upload or download address lives |
| `PVLT_EXPIRY_INTERVAL_SECS` (300) | how often expired facts are shredded and unpublished ledger entries retried; 0 turns it off |
| `PVLT_SWEEP_INTERVAL_SECS` (3600), `PVLT_SWEEP_GRACE_SECS` (3600) | the orphan-object sweeper |
| `PVLT_SCRATCH_DATABASE_URL` | an empty database, only for `pvlt scrub-backup` |

**Use a separate ledger bucket.** The ledger is what makes a shred survive restoring an old backup, so it must be
a bucket that is never restored from a backup, ideally with versioning or object lock. If `PVLT_LEDGER_S3_BUCKET`
is unset the ledger shares the data bucket and the server warns at every start: restoring that bucket would roll
the ledger back too.

## First start

```bash
pvlt init --threshold 3 --shares 5     # prints 5 shares to stdout, once. Nothing stores them.
pvlt serve                             # starts sealed
```

Give each share to a different person. From a host that can reach the admin listener:

```bash
curl --cacert cert.pem https://localhost:8444/v2/sys/unseal -d '{"share":"pvlt-share-v1:..."}'
```

Repeat with different shares until `"sealed": false`. A restart is sealed again and needs the shares again.
`POST /v2/sys/seal` (admin token) wipes the keys without stopping the process. `GET /readyz` on the data listener
says which part is not ready: `sealed`, `key_store`, `object_store`, `ledger_in_sync`, `audit_ok`, `compat_policy`.

**While sealed** the server answers `/healthz`, can replay the ledger and publish pending entries, and refuses
everything else. Creating, reading **and shredding** need it unsealed: a ledger entry is signed with a key the
root key unwraps, so erasure waits for an unseal.

## Who may do what: issuers, tokens, policy

An application backend mints a short-lived [Biscuit](https://www.biscuitsec.org) token for each operation and sends
`Authorization: Bearer <token>`. The vault checks the token against a **registered issuer**, keeps only the roles
that issuer is registered to assert, and asks the **policy**, which denies by default.

```bash
pvlt issuer-keygen > issuer.seed            # prints the seed (keep it in the backend), the public key on stderr
curl --cacert cert.pem -H "Authorization: Bearer $ADMIN" https://localhost:8444/v2/admin/issuers \
  -d '{"name":"backend","public_key":"<hex>","roles":["verifier","app-backend"]}'      # → {"key_id": 1, ...}
```

A token carries (all inside the part only the issuer can write): `expires` (required, within
`PVLT_MAX_TOKEN_TTL_SECS`), `request_id`, optionally `caller`, `subject`, `role` (repeatable), `purpose`, `reason`,
`action`, `resource_fact` / `resource_scope` / `resource_subject` (the one thing the token may touch), `grant`,
and `approval`. A holder can **narrow** a token with attenuation blocks and cannot add anything: facts in later
blocks are never read. The issuer's key id is the token's root key id.

```bash
pvlt mint-token --seed-file issuer.seed --key-id 1 --role verifier --caller user:77 \
  --purpose kyc-review --reason "ticket 4411" --ttl 60        # for tests; real issuers mint their own
```

The policy is JSON, validated strictly (a misspelt field is an error, so it cannot silently allow or deny the
wrong thing), stored in canonical form with its SHA-256 (which every audit entry names), and versioned:

```json
{
  "version": 1,
  "restricted_types": ["id_number"],
  "roles": {
    "verifier":     { "allow": [{ "types": ["identity", "doc_key", "id_number"], "actions": ["read"] }],
                      "require": { "purposes": ["kyc-review"], "reason": true },
                      "limits": { "read_per_hour": 100 } },
    "data-subject": { "allow": [{ "types": ["*"], "actions": ["read"], "when": ["self"] }] },
    "fulfillment":  { "allow": [{ "types": ["address"], "actions": ["read"], "when": ["grant:order_open"] }] },
    "app-backend":  { "allow": [{ "types": ["*"], "actions": ["create", "shred", "rebind"] }] }
  }
}
```

`PUT /v2/admin/policy` (admin) replaces it and takes effect at once on that server, and within 30 seconds on
others. Conditions are `self` (the token's caller is its subject and the fact is filed under that subject) and
`grant:<name>`. A role named `compat` governs the static `/api/v1` token; without one that token may do anything, so while `PVLT_COMPAT_TOKEN_FILE` is set and the policy has no `compat` role, `/readyz` reports `compat_policy: false` and not ready. The actions are `create`, `read`, `shred` and `rebind`; `DELETE /api/v1/facts/{id}` is `shred`. Subjects are limited to 256 bytes.
With no policy at all, `/v2` refuses everything.

**Dual control.** Reading a `restricted_types` fact needs an approval: one admin `POST /v2/admin/approvals
{"fact_id": ...}`, a *different* admin `POST /v2/admin/approvals/{id}/approve`, and the token that reads names it in
`approval`. It covers one fact, once, for at most 15 minutes (the database enforces two people and single use).
With `PVLT_BREAK_GLASS=true` a requester may pass `"break_glass": true` and approve alone for at most 5 minutes; that
is logged at warning level and written to the audit log.

**Rate limits** (`limits` per role, per caller) are counted in memory on each server, so with several servers the
real limit is up to their number times the configured one, and a restart resets them. A limited request is
`429` with `Retry-After`.

## The two APIs

`/v2/facts` (create, batch create atomically, read, shred), `/v2/shred/subject`, `/v2/shred/scope`, and
`/v2/blobs` (below), all with tokens. `/api/v1/facts` (store, get, delete) with `X-OPV-GRANT-TOKEN`, for
existing OPV clients: four fact types (`ascii`, `printableascii`, `base64`, `json`); a deleted fact is `410`, not
`404`; an optional `subject_custom_id` field is an extension. Errors are `{"error", "message"}` with fixed text,
never an echo of the request. `docs/MIGRATING.md` covers moving an OPV client over.

## Shredding, and what survives a restore

Every shred writes one signed entry to the ledger in the same database transaction that destroys the keys, then
copies it to the ledger bucket, and only then reports success. On start the server compares the bucket's ledger
with the key store's, verifies every signature and link, and **replays** what the key store lacks, before any
listener opens. So restoring an older database re-shreds everything erased since the backup. An entry the bucket
has but cannot be verified, a fork, or a published entry that went missing stops the server.

What it does not protect against: copies of the *data bucket's* ciphertext are harmless (the keys are gone), but a
copy of the key store from before a shred still holds the key until it is replayed or scrubbed.

## GDPR mode

`PVLT_GDPR_MODE=true` adds what the vault needs to answer a data subject's requests. Erasure is not part of the
switch, because it is always there: a subject shred is crypto-shredding and the ledger makes it stick.

| Right | How | Notes |
|---|---|---|
| Erasure (art. 17) | `POST /v2/shred/subject {"subject": ...}` with the subject's own token, or `POST /v2/admin/shred/subject` with `"reason": "subject_request"` | Always available. The subject's token needs a `self` shred rule over `*`. One key is destroyed however many facts there are, the ledger entry survives restores, and a shredded subject is not reopened by later writes. |
| Access (art. 15) | `POST /v2/subject/facts {"subject": ...}` | Lists every fact under the subject: id, type, fact or blob, created, expiry, legal hold, active or shredded. **No values.** |
| Access and portability (art. 15(3), 20) | `POST /v2/subject/export {"subject": ...}` | The list plus every value the token may read, as JSON. |
| Who saw my data | `GET /v2/admin/audit?subject=...` | Unchanged; it was already the subject's access report. |
| Admin inventory | `POST /v2/admin/subject/facts {"subject": ...}` on the admin listener | The list, **no values**, for staff answering a request. |

The subject goes in the body, not the URL, so it is not in access logs. Each list is written to the audit log as
an `inventory` entry before it is sent, and each exported value is an ordinary `read.grant`; if the audit log
cannot be written, nothing is sent.

Authorization is the policy's. Listing needs a `read` rule over every type (`*`), which a data subject normally
has as `{"types": ["*"], "actions": ["read"], "when": ["self"]}`. The export then authorizes each fact as a normal
read, so per-type rules, purposes and rate limits all apply. A fact the policy will not release is listed as
`withheld` with the refusal code, and a restricted type is always withheld (its dual-control approval covers one
fact, so release it through the normal read). A blob is listed with status `blob`: fetch it through the blob
routes. A rate limit stops the whole export with 429 rather than returning a partial one that looks complete.

**What to turn off if it is too much:**

- `PVLT_GDPR_EXPORT=false` drops the export. A stolen self token can otherwise take everything about that one
  person in a single request instead of one fact at a time. Turn it off if you answer portability requests
  another way, or keep it and set a `read_per_hour` limit on the data-subject role.
- `PVLT_GDPR_ADMIN_INVENTORY=false` drops the admin inventory. With it, an admin can see which facts (types,
  dates) exist for a named person, which they otherwise cannot. Values stay out of reach either way: there is
  deliberately no admin export.

What GDPR mode does not do: it does not decide your lawful basis, retention periods or response deadlines; it has
no "restrict processing" (art. 18) state yet (a legal hold is the nearest thing, and it blocks shredding, not
reading); and audit entries keep the subject's blinded identifier after erasure, which is pseudonymous, not
anonymous, for as long as the domain's blind-index key exists.

## The audit log

Every read writes a `read.grant` entry **before** the value or key is released, and the read fails (503) if it
cannot be made durable. Entries are hash-chained, and signed checkpoints go to the ledger bucket every 60 seconds
or 1000 entries. `GET /v2/admin/audit?subject=...&principal=...&fact_id=...&kind=...&from=...&to=...&after_seq=...`
queries it (the subject is given in the clear and blinded server-side), and a data subject's own access report is
the same query. `GET /v2/admin/audit/verify` and `pvlt audit-verify` check the chain and every checkpoint.

If a restore leaves the audit log **shorter** than a signed checkpoint, the server starts but **reads stay off**
(`audit_ok: false`) until an admin acknowledges the lost range with `POST /v2/admin/audit/acknowledge-rollback`,
which writes a signed marker and an audit entry under the admin's name. Tampering stops the server.

## Backups

```bash
pvlt backup-keygen                                    # an age key pair: keep the secret offline
pvlt backup --out backup.age --recipient age1... [--recipient age1tagpq1...]
pvlt restore --in backup.age --identity secret.txt    # into an EMPTY key store; replays the ledger
pvlt scrub-backup --in old.age --identity secret.txt --out new.age --recipient age1...   # needs PVLT_SCRATCH_DATABASE_URL
```

A backup is the whole key store (wrapped keys, ledger, audit, issuers, policies, approvals), encrypted with `age`
and written with mode 0600; it is never plaintext. `scrub-backup` rewrites an old backup with everything shredded
since already applied, so it can be kept or handed on without the keys of people who have since been erased. The
`age` crate can encrypt to a hybrid post-quantum recipient (`age1tagpq...`) but not decrypt with one, so give
`pvlt restore` an X25519 identity and use the external `age` tool for the post-quantum copy. The post-quantum
path has not been exercised with a real key.

## Blobs

Documents (ID photos, forms) are encrypted by the client and uploaded straight to the bucket; the vault never sees
them unless asked to.

1. `POST /v2/blobs {type, scope, subject, size}` → the id, the **key (shown once)**, the layout, and an upload address
   (a presigned bucket URL, or `/v2/blobs/{id}/object` on the vault if the bucket cannot presign).
2. The client encrypts with the key (`clients/typescript`) and `PUT`s the object.
3. `POST /v2/blobs/{id}/complete`: the vault checks the object's exact size and its header's key commitment (it does not
   read the chunks) and the blob becomes readable.
4. `GET /v2/blobs/{id}/access`: the disclosure is written to the audit log, then the key and a download address are
   returned. Or `GET /v2/blobs/{id}/content` has the server decrypt and stream the plaintext; a chunk that fails to
   verify ends the transfer in an error, and the caller must discard what it received.
5. `DELETE /v2/facts/{id}` shreds a blob like any fact and deletes its object.

A blob that is never completed expires after a day and is shredded by the retention sweeper. A browser upload
directly to a bucket needs the bucket's CORS rules to allow `PUT` and `GET` from your origin.

## Smoke test

```bash
scripts/smoke.sh
```

Builds the default features and starts Postgres and MinIO containers from images already on the machine (it never
pulls). It then runs the real binary through: TLS 1.3 only, unsealing, the three OPV calls, what is at rest in the
bucket and in a `pg_dump`, shredding and its ledger entry, a restart, delegated tokens and policy, the audit log
and the subject's access report, a TypeScript client uploading an encrypted document directly to MinIO through a
presigned URL and the server decrypting it, a rehearsed migration from a stand-in OPV (with a resume), and the
Python client. It removes both containers.

## What is not done

* **Production gates** (DECISIONS.md): the Linux paths of `pvlt-mem` (locked memory, core dumps) have only been
  compiled, never run; there is no independent cryptography review; the format is not frozen; WAL archiving and
  volume encryption under Postgres are operations work.
* The `Dockerfile` builds (the default feature set, distroless, non-root), and a tagged release pushes it to
  `ghcr.io/<owner>/pvlt`. `compose.yaml` is an example only and has never been run end to end; the image has never run
  in a real deployment. CI and the release workflow have never run on GitHub.
* No KMS root-key provider (Shamir only), no certificate reload, no per-statement database timeouts, no separate
  database role for migrations.
* `pvlt unseal` and `pvlt seal` are HTTP calls, not commands.
* Blob upload from Python (client-side encryption) is not in the Python client.
* Rate limits are per server and in memory. Group commit for the audit log is per server; two servers share one
  chain by retrying, which costs throughput under heavy contention.
* A caller holding any valid token can tell whether a fact id exists. Ids are unguessable UUIDs.
