# Moving from Open Privacy Vault to pvlt

This is the cutover guide. The tooling is exercised end to end by `scripts/smoke.sh` against a stand-in for OPV
(`scripts/fake_opv.py`); it has **not** been run against a real OPV deployment, so rehearse on a copy first.

## Order of work

1. Stand up pvlt beside OPV (see [`RUNNING.md`](RUNNING.md)): TLS, a **separate ledger bucket**, two named admins,
   unseal.
2. Register your application backend as an issuer and load a policy. Give the static compat token its own
   `compat` role in the policy, as narrow as your clients allow.
3. Export the list of facts to move from the application's own database (OPV cannot list them). Rehearse.
4. Switch clients: first to pvlt's `/api/v1` by changing the URL and token, then to `/v2` with delegated tokens.
5. Retire OPV, **including every dump and snapshot of its database and buckets**.

## 1. The export

OPV does not enumerate its facts, so the application that owns the ids provides a CSV, one row per fact:

```
id,subject,scope,type
6f1c...-uuid,user:1042,kyc,identity
```

`id` is the OPV fact id; `subject` and `scope` are opaque strings that become the subject and scope in pvlt (a fact
with no subject: leave it empty); `type` is the policy type name. Ids are kept, so stored references in your
application keep working. A malformed row, duplicate id, or bad UUID is a hard error naming the line number, never
the values.

## 2. Rehearse, then run

```bash
pvlt import-opv --csv facts.csv \
  --opv-url https://opv.internal --opv-token-file opv.token \
  --vault-admin-url https://pvlt.internal:8444 --admin-token-file admin.token \
  --vault-url https://pvlt.internal:8443 --vault-token-file reader.token \
  --cacert pvlt-ca.pem --dry-run
```

`--dry-run` reads and parses everything and reports counts but writes nothing. Without it, each fact is read from
OPV, written to pvlt through the admin `import/fact` route with the same id, then **read back through pvlt and
compared by SHA-256** with what OPV returned. A mismatch is reported and the fact is not marked done.

* It is **resumable**: progress is kept in `<csv>.pvlt-import-state` (or `--state FILE`), written atomically. Run it
  again after any failure and it skips what is verified.
* A row OPV does not have (`404`, or `410` for a deleted fact) is reported as **missing in source** and not imported.
* A fact already in pvlt with the same value is counted as already matching; one with a **different** value is
  reported as mismatched and left untouched. A failed request is reported with a fixed reason. There are no
  automatic retries: fix the cause and run again, and finished rows are skipped. Rows go one at a time.
* It logs counts and ids only, never values. The state file holds ids and hashes, not data.
* Run it from a host that may see both services; the plaintext passes through that process's memory only.

Use a **reader token** for `--vault-token-file` whose policy permits the read-back (the import reads every fact
through the normal, audited path, so each one appears in the audit log as a `read.grant`).

## 3. Cut clients over

* **`/api/v1`**: change the base URL and the `X-OPV-GRANT-TOKEN` value. Check the differences that matter to
  you: a deleted fact is `410`; four types only; errors have fixed text. Anything the policy's `compat` role does not
  allow is refused and written to the audit log.
* **`/v2`**: the Python client (`clients/python`) and TypeScript client (`clients/typescript`) cover facts and, in
  TypeScript, browser-side encrypted blobs. The backend mints short-lived delegated tokens; the static token can
  then be removed by unsetting `PVLT_COMPAT_TOKEN_FILE`, which makes `/api/v1` refuse everything.
* Watch `GET /v2/admin/audit` for `deny` entries during the transition; they show what a client is attempting that the
  policy forbids.

## 4. Verify before retiring OPV

* The report: `missing_in_source`, `mismatched` and `failed` are all empty (the command exits non-zero otherwise), and
  `imported + already_matching + already_done` equals the CSV's row count.
* Spot-check reads from the real application against pvlt.
* `pvlt audit-verify` is clean; `GET /readyz` is all true; a backup (`pvlt backup`) restores into a scratch database.
* Shred a test fact and confirm the ledger entry appears in the ledger bucket.

## 5. Retire OPV

Erasure in pvlt does not reach OPV's copies. Until OPV and everything derived from it is gone, a "deleted" subject
is still recoverable from there.

* Stop OPV and revoke its credentials.
* Destroy its database, its buckets, **and every dump, snapshot and backup of either**, on the schedule your retention
  policy allows. This is the step most often missed; a forgotten dump defeats crypto-shredding.
* Keep the CSV and the state file only as long as needed: they hold ids and subjects.
* Record the date, the counts and the destruction in your own records; pvlt does not know about OPV's side.

## What this does not do

* No two-way sync or live dual-write: it is a one-time copy, so freeze writes (or re-run for the delta) at cutover.
* Facts with expiry or retention set in OPV are imported without them; set them in pvlt afterwards if you need them.
* Blobs and anything outside `/api/v1/facts` are not migrated by this command.
