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
| `PVLT_DATABASE_URL_FILE` | a file holding the key store's URL, `postgres://user:pass@host/db`. Migrations run at start. `PVLT_DATABASE_URL` works too, but a default build refuses it if the URL holds a password. |
| `PVLT_DOMAIN` | a UUID; the domain every request uses. Created on first write. |
| `PVLT_S3_BUCKET`, `PVLT_S3_REGION` (`us-east-1`), `PVLT_S3_ENDPOINT` | the data bucket |
| `PVLT_S3_ACCESS_KEY_ID_FILE`, `PVLT_S3_SECRET_ACCESS_KEY_FILE` | its credentials |
| `PVLT_S3_PATH_STYLE=true`, `PVLT_S3_ALLOW_HTTP=true` | for MinIO on a private network |
| `PVLT_LEDGER_S3_*` | the same settings for a **separate bucket for the ledger and checkpoints**. See below. |
| `PVLT_TLS_CERT`, `PVLT_TLS_KEY` | PEM files. Required: there is no plaintext listener. The certificate needs the `serverAuth` extended key usage (public CAs issue it; a hand-made one must ask for it). |
| `PVLT_LISTEN` (`0.0.0.0:8443`) | the data listener, which applications call |
| `PVLT_ADMIN_LISTEN` (`127.0.0.1:8444`) | admin: unseal, seal, issuers, policy, approvals, audit, import. Keep it on loopback or a private network. |
| `PVLT_COMPAT_TOKEN_FILE` | the `X-OPV-GRANT-TOKEN` value `/api/v1` clients send, at least 16 characters. Unset, or set with no `compat` role in the policy: `/api/v1` refuses everything. |
| `PVLT_ADMIN_TOKENS_FILE` | named admins, one `name:token` per line (tokens at least 16 characters, names and tokens unique). **Dual control needs two**, and with two or more, policy and issuer changes need a second admin's approval. |
| `PVLT_ADMIN_TOKEN_FILE` | a single admin named `admin`, for simple setups |
| `PVLT_BREAK_GLASS=true` | lets one admin approve their own emergency read, for at most five minutes. Off by default. |
| `PVLT_GDPR_MODE=true` | serves the data-subject access and export routes (see "GDPR mode" below). Off by default. |
| `PVLT_GDPR_EXPORT` (`true`), `PVLT_GDPR_ADMIN_INVENTORY` (`true`) | with GDPR mode on, set either to `false` to drop that route |
| `PVLT_MAX_TOKEN_TTL_SECS` (300) | the longest a request token may live; a longer one is refused even if genuine |
| `PVLT_MAX_VALUE_BYTES` (1 MiB), `PVLT_MAX_BLOB_BYTES` (256 MiB) | limits |
| `PVLT_PRESIGN_TTL_SECS` (900) | how long a presigned upload or download address lives |
| `PVLT_EXPIRY_INTERVAL_SECS` (300) | how often expired facts are shredded and unpublished ledger entries retried; 0 turns it off |
| `PVLT_SWEEP_INTERVAL_SECS` (3600), `PVLT_SWEEP_GRACE_SECS` (3600) | the orphan-object sweeper |
| `PVLT_KMS_KEY_ID` | enables auto-unseal: an AWS KMS key ARN or alias (see "Auto-unseal") |
| `PVLT_KMS_REGION`, `PVLT_KMS_ENDPOINT`, `PVLT_KMS_ALLOW_HTTP` | the KMS region (default: the AWS SDK's), an endpoint override (a VPC endpoint), and `true` to allow a plain `http://` endpoint on a private network. Credentials come from the AWS default chain (instance, task or web-identity role). |
| `PVLT_SCRATCH_DATABASE_URL_FILE` | an empty database, only for `pvlt scrub-backup` (or `PVLT_SCRATCH_DATABASE_URL`, with the same password rule) |

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

Repeat with different shares until `"sealed": false`. A restart is sealed again and needs the shares again, unless
you set up auto-unseal (below).
`POST /v2/sys/seal` (admin token) wipes the keys without stopping the process. `GET /readyz` on the data listener
says which part is not ready: `sealed`, `key_store`, `object_store`, `ledger_in_sync`, `audit_ok`, `compat_policy`.

**While sealed** the server answers `/healthz`, can replay the ledger and publish pending entries, and refuses
everything else. Creating, reading **and shredding** need it unsealed: a ledger entry is signed with a key the
root key unwraps, so erasure waits for an unseal.

## Unsealing from a laptop (no KMS)

`pvlt unseal` sends shares, read from files, to the admin listener, so one machine can unseal the server after
every reboot without anyone typing. It needs only the `pvlt` binary (`cargo install pvlt-server` gives you
`pvlt`) and the server's certificate if it is not from a public CA.

```bash
# once: put enough shares (the threshold, e.g. 2) in files, one share per file, mode 600, on an encrypted disk
pvlt unseal --admin-url https://pvlt.internal:8444 --cacert pvlt-ca.pem \
  --share-file ~/.pvlt/share1 --share-file ~/.pvlt/share2 --wait-secs 600
```

* It checks every share locally first, so a typo fails before anything is sent.
* It is safe to repeat: an already unsealed server is left alone, so it can run from a login item, a `launchd` job
  or cron on a timer. `--wait-secs N` keeps trying for N seconds while the server is down or starting.
* The admin URL must be `https://`, because the shares cross it. Shares are never printed or logged.
* **What this trades.** A machine that holds the threshold's worth of shares *is* the unseal key: whoever has the
  laptop (and its disk key) can open the vault, and the server cannot restart unattended while the laptop is off.
  It is still better than shares on the server itself, because a stolen server disk gets nobody in. To keep two
  people in the loop, leave one share with another person or device and let the laptop hold the rest (with a
  threshold of 3 of 5, say: two on the laptop, one with someone else).

## Auto-unseal

By default every restart is sealed until enough people send their shares. With **auto-unseal** the server unseals
itself at start: the unseal key (the one the shares recover) is also wrapped by an AWS KMS key, and the wrapped
copy is kept in the key store. The shares keep working, so the KMS is a convenience and never the only way in.
Pick the share threshold you want at `pvlt init`: `--threshold 2 --shares 3` means any two of three people.

```bash
export PVLT_KMS_KEY_ID=alias/pvlt-unseal        # and PVLT_KMS_REGION; credentials from the instance or task role
pvlt init --threshold 2 --shares 3 --kms        # a new vault: prints the shares and enrols the KMS
# an existing vault: put two shares in two files (one share each), then
pvlt kms-enroll --share-file share1.txt --share-file share2.txt
```

Enrolment recovers the unseal key from the shares once, has the KMS wrap it, **unwraps it again and opens the root
key to prove the whole round trip**, and only then stores the record. A missing `kms:Decrypt` permission shows up
there, not at the next restart. `pvlt kms-remove` forgets the KMS copy; the vault then unseals only with shares.

* **What protects it.** Whoever may call `kms:Decrypt` on the key, with this vault's context, can open the vault.
  Grant `kms:Encrypt` and `kms:Decrypt` on that one key to the server's role (and `Encrypt` to whoever enrols), put
  the vault's root key id in a key policy condition if you like (`kms:EncryptionContext:root_key_id`), and watch
  CloudTrail for `Decrypt` calls. The ciphertext is bound to this vault (the encryption context names the root
  key) and to the key id you configure, so a record copied from another vault, or made under another key, is
  refused.
* **If the KMS is down at start**, the server starts sealed, logs the failure, and retries every 30 seconds until
  it works or someone unseals it by hand. `/readyz` says `sealed` until then.
* **Sealing stays possible.** `POST /v2/sys/seal` still wipes the keys; the vault stays sealed until the next start
  (which unseals it again) or until shares are sent. An emergency seal is therefore not durable against a restart:
  `pvlt kms-remove` first if you need that.
* **A restore does not carry it.** The KMS record is deliberately not in a backup, because it ties the vault to one
  KMS key in one environment. After `pvlt restore`, run `pvlt kms-enroll` again.
* **What it costs.** With shares only, a stolen disk plus a stolen database cannot open the vault. With auto-unseal,
  a stolen disk plus the KMS credentials can. A process that can already run code on the running host gains
  nothing, since the unsealed keys are in its memory anyway. Shredding is unaffected: it destroys per-subject keys.
* Only AWS KMS is supported so far. It is tested here against a protocol stand-in (`local-kms`), not against AWS
  itself.

## Who may do what: issuers, tokens, policy

An application backend mints a short-lived [Biscuit](https://www.biscuitsec.org) token for each operation and sends
`Authorization: Bearer <token>`. The vault checks the token against a **registered issuer**, keeps only the roles
that issuer is registered to assert, and asks the **policy**, which denies by default.

```bash
pvlt issuer-keygen > issuer.seed            # prints the seed (keep it in the backend), the public key on stderr
curl --cacert cert.pem -H "Authorization: Bearer $ALICE" https://localhost:8444/v2/admin/issuers \
  -d '{"name":"backend","public_key":"<hex>","roles":["verifier","app-backend"]}'   # → 202 {"change_id": ...}
curl --cacert cert.pem -H "Authorization: Bearer $BOB" https://localhost:8444/v2/admin/changes/<change_id>
curl --cacert cert.pem -H "Authorization: Bearer $BOB" -X POST \
  https://localhost:8444/v2/admin/changes/<change_id>/approve                      # → {"result": {"key_id": 1, ...}}
```

**Changes to who may do what need two admins.** Registering an issuer, re-enabling one and setting a policy
decide who can read, so with two or more admins configured each is a request (`202 {"change_id"}`) that a
*different* admin approves with `POST /v2/admin/changes/{id}/approve` within 24 hours. `GET
/v2/admin/changes/{id}` shows exactly what will be applied. A policy change is refused at approval if another
policy landed after it was asked for, so an old request cannot quietly undo a newer one. Disabling an issuer only
narrows access and takes effect at once. With a single admin the change applies immediately, and the server warns
at every start that one person can change who reads. Every admin action that changes access, or reads the audit
log, is written to the audit log first and does not happen if that write fails, so these routes need the domain
to exist: unseal once before the first one.

A token carries (all inside the part only the issuer can write): `expires` (required, within
`PVLT_MAX_TOKEN_TTL_SECS`), `request_id`, optionally `caller`, `subject`, `role` (repeatable), `purpose`, `reason`,
`action`, `resource_fact` / `resource_scope` / `resource_subject` (the one thing the token may touch), `grant`,
and `approval`. A holder can **narrow** a token with attenuation blocks and cannot add anything: a later block may
hold only small checks, and a token whose later block holds a fact or a rule is refused. Each check may join at
most two claims, so a check over three or more (say `time`, `action` and `resource_scope`) has to be split into
separate checks; the full limits are in the `pvlt_server::tokens` module docs. An expired token is refused before
any of its checks run. The issuer's key id is the token's root key id.

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
`grant:<name>`. A role named `compat` governs the static `/api/v1` token, and without one that token is refused everything; while `PVLT_COMPAT_TOKEN_FILE` is set and the policy has no `compat` role, `/readyz` also reports `compat_policy: false` and not ready. The compat token can never read a `restricted_types` fact (`403 approval_required`), because it cannot present an approval: release those through `/v2`. The actions are `create`, `read`, `shred` and `rebind`; `DELETE /api/v1/facts/{id}` is `shred`. Subjects are limited to 256 bytes.
With no policy at all, `/v2` refuses everything.

**Dual control.** Reading a `restricted_types` fact needs an approval: one admin `POST /v2/admin/approvals
{"fact_id": ..., "caller": "user:77"}`, a *different* admin `POST /v2/admin/approvals/{id}/approve`, and the token
that reads names it in `approval` and carries that `caller`. It covers one fact, one caller, once, for at most 15
minutes (the database enforces two people, the caller and single use), so an approval id that leaks is no use to
anyone else.
With `PVLT_BREAK_GLASS=true` a requester may pass `"break_glass": true` and approve alone for at most 5 minutes; that
is logged at warning level and written to the audit log.

**Rate limits** are counted in memory on each server, so with several servers the real limit is up to their number
times the configured one, and a restart resets them. A limited request is `429` with `Retry-After`. `read_per_hour`
(and `create_`, `shred_`) count each caller on its own; `total_read_per_hour` (and `total_create_`,
`total_shred_`) count every caller of the role together. The caller is a claim the issuer writes, so a compromised
service that invents a caller name per request is held **only by a total**: set one on every role that reads.
The server warns at start, and when a policy is applied, about roles with a per-caller limit and no total. At most
600 refusals an hour per issuer reach the audit log; the rest reach the log lines only.

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
pvlt backup-signing-keygen > backup-signing.key       # the backup job's signing key; the public key on stderr
pvlt backup --out backup.age --recipient age1... [--recipient age1tagpq1...] --signing-key-file backup-signing.key
pvlt restore --in backup.age --identity secret.txt --verify-key <public hex>   # into an EMPTY key store
pvlt scrub-backup --in old.age --identity secret.txt --verify-key <hex> \
  --out new.age --recipient age1... --signing-key-file backup-signing.key   # needs PVLT_SCRATCH_DATABASE_URL_FILE
```

Every backup is **signed** by the backup job, and restore refuses one it did not sign. `age` alone proves nothing
about who made a file, since anyone with the public recipient can encrypt one; without the signature, someone who
can write to backup storage could have restore load a key store with their own issuer and policy. Keep the
signing key with the backup job, never with the backups. A backup made before backups were signed restores only
with `--allow-unsigned` in place of `--verify-key`, which says so loudly.

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
   (a presigned bucket URL, or `/v2/blobs/{id}/object` on the vault if the bucket cannot presign). The address names
   a staging object, not the one readers get.
2. The client encrypts with the key (`clients/typescript`) and `PUT`s the object.
3. `POST /v2/blobs/{id}/complete`: the vault copies the staging object to the blob's own object, checks the copy's exact
   size and its header's key commitment (it does not read the chunks), and the blob becomes readable. An upload
   address stays valid until it expires, but it can only ever write the staging object again, so nothing uploaded
   after completion reaches a reader. Complete within `PVLT_SWEEP_GRACE_SECS` of the upload, or the sweeper may
   remove the staging object first.
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

* **Production gates** (DECISIONS.md): the Linux paths of `pvlt-mem` (locked memory, core dumps) have run only in
  an amd64 image under emulation on Apple Silicon (`/readyz` reported all three protections true), not yet on
  real x86_64 hardware; there is no independent cryptography review; the format is not frozen; WAL archiving and
  volume encryption under Postgres are operations work.
* CI and the release workflow run on GitHub; a tagged release pushes the image to `ghcr.io/cartercole/pvlt` (public,
  amd64 only) and the crates to crates.io. The image has been smoke-tested from a compose stack and from a
  downstream deployment's compose project, with fake data; it has not run in a real production deployment.
  `compose.yaml` is an example only: create the `pvlt` bucket first and set `PVLT_COMPAT_TOKEN_FILE` if you use
  `/api/v1`.
* Auto-unseal supports AWS KMS only (no GCP, Azure or Vault), no certificate reload, no per-statement database timeouts, no separate
  database role for migrations.
* `pvlt seal` is an HTTP call (`POST /v2/sys/seal`), not a command; `pvlt unseal` is a command (below).
* Blob upload from Python (client-side encryption) is not in the Python client.
* Rate limits are per server and in memory. Group commit for the audit log is per server; two servers share one
  chain by retrying, which costs throughput under heavy contention.
* A caller holding any valid token can tell whether a fact id exists. Ids are unguessable UUIDs.
