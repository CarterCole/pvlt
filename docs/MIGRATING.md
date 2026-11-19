# Migrating from Open Privacy Vault

This is the runbook for moving an application's facts from Open Privacy Vault (OPV) to pvlt, checking that every
one arrived intact, and retiring OPV. It is written so that a person or an agent can follow it step by step: each
step has the command, what a good result looks like, and what to do when it is not.

The tooling is exercised end to end by `scripts/smoke.sh` against a stand-in for OPV (`scripts/fake_opv.py`). It
has **not** been run against a real OPV deployment, so do the whole thing on a staging copy first (section 9).

## What moves and what does not

* **Moves:** every fact your application still holds an id for, read through OPV's `GET /api/v1/facts/{id}`,
  written to pvlt **under the same id**, with a subject and scope you choose. Stored ids in your application need
  no rewriting.
* **Does not move:** facts your application no longer points to (OPV cannot list its facts, so nobody can find
  them), expiry or retention set in OPV, blobs, and anything outside `/api/v1/facts`. Orphaned facts stay in OPV
  until OPV is destroyed (section 8).
* **No live sync.** It is a one-time copy. Freeze writes to OPV before the final export, or rerun for the delta.

## The order of work

| # | Step | Writes to pvlt? | Done when |
|---|---|---|---|
| 0 | Preconditions | no | every check in section 0 passes |
| 1 | Export the CSV from the application's database | no | the CSV checks in section 1 pass |
| 2 | Freeze writes to OPV | no | nothing can store a new fact in OPV |
| 3 | Dry run | no | exit 0, nothing missing or failed |
| 4 | Canary: one row for real | one fact | `imported 1`, exit 0 |
| 5 | Full import | yes | exit 0 |
| 6 | Verify, independently of the importer | reads only, plus one test fact | every check V1 to V9 passes |
| 7 | Switch clients to pvlt, then lift the freeze | normal traffic | the application works against pvlt |
| 8 | Retire OPV and every copy of it | no | OPV, its database, buckets, dumps and snapshots are destroyed |

Do not skip step 6 because step 5 reported success. The importer checks its own work; step 6 checks the importer.

## 0. Preconditions

Set these once in the shell you run everything from. Secrets live in files, never on a command line.

```bash
OPV=https://opv.internal                   # OPV's data plane, as the importer host reaches it
DATA=https://pvlt.internal:8443            # pvlt's data listener
ADMIN=https://pvlt.internal:8444           # pvlt's admin listener
CA=pvlt-ca.pem                             # the CA that signed pvlt's certificate
# opv.token     an OPV grant token that may GET facts
# admin.token   one pvlt admin token (a line of PVLT_ADMIN_TOKENS_FILE, the part after "name:")
# compat.token  the contents of PVLT_COMPAT_TOKEN_FILE, the token /api/v1 clients send
```

Check each of these. Every one is a reason the import fails part way.

1. **pvlt is ready.** `curl -sS --cacert $CA $DATA/readyz` returns HTTP 200 and

   ```json
   {"ready": true, "sealed": false, "key_store": true, "object_store": true, "ledger_in_sync": true,
    "audit_ok": true, "compat_policy": true, "insecure": false, "memory": {...}}
   ```

   `insecure` must be `false` (a `dev-insecure` build must never hold real data). On Linux, every `memory` flag
   should be `true`. A `false` anywhere else names what to fix: `sealed` (unseal, RUNNING.md), `compat_policy`
   (set a policy with a `compat` role), `ledger_in_sync` or `audit_ok` (stop: read RUNNING.md before going on).
2. **A separate ledger bucket.** `PVLT_LEDGER_S3_BUCKET` is set, and that bucket is never restored from a backup.
   Without it the server warns at every start.
3. **The compat token is set**, even if your clients will move to `/v2`. The importer reads every fact back through
   `/api/v1` with it. Unset, every row fails with `the server answered 401`.
4. **The policy's `compat` role may `read` every type in the CSV**, has **no `read_per_hour` limit** during the
   import (each row is one read, so a limit turns into `the server answered 429` part way), and none of the
   imported types is in `restricted_types` (dual control would refuse the read-back with `403`). The minimal role:

   ```json
   "compat": { "allow": [{ "types": ["ascii", "base64", "json"], "actions": ["create", "read", "shred"] }] }
   ```

   List the types your CSV actually uses. Add a limit back after the import if you want one. Without a `compat`
   role the compat token is refused everything (`403 no_usable_role`). With two or more admins, setting this
   policy is a request a second admin approves (`POST /v2/admin/changes/{id}/approve`, RUNNING.md).
5. **The importer host can reach all three listeners**: OPV, pvlt's data listener and pvlt's admin listener. The
   admin listener defaults to `127.0.0.1:8444`, inside the pvlt container or host only. Either run the importer
   there, or bind `PVLT_ADMIN_LISTEN` to a private network that is not published. Check:

   ```bash
   curl -sS --cacert $CA -o /dev/null -w '%{http_code}\n' $DATA/healthz                  # 200
   curl -sS --cacert $CA -o /dev/null -w '%{http_code}\n' \
     -H "Authorization: Bearer $(cat admin.token)" $ADMIN/v2/admin/audit/verify          # 200
   curl -sS -o /dev/null -w '%{http_code}\n' \
     -H "X-OPV-GRANT-TOKEN: $(cat opv.token)" $OPV/api/v1/facts/00000000-0000-4000-8000-000000000000   # 404
   ```

   A TLS error means pvlt's certificate does not name the host in `$DATA` / `$ADMIN`: use the name it was issued
   for. The OPV call must be a 404 (no such fact), not a 401 or 403 (wrong token).
6. **`pvlt audit-verify` is clean before you start**, so that anything wrong afterwards is the migration's. Run it
   where the server's environment is set, for example `docker compose exec pvlt /usr/local/bin/pvlt audit-verify`.
   Each line is `<domain>: ok (N entries, M checkpoints)` and the exit code is 0.
7. **A backup exists from before the import** (`pvlt backup`, RUNNING.md), so a bad import can be undone by
   restoring it into an empty database instead of shredding facts by hand.

## 1. Export the CSV

OPV does not enumerate its facts, so the application that owns the ids provides the list: one row per fact id it
stores, built from the columns that hold fact ids.

```
id,subject,scope,type
6f1c2a9e-0b7d-4c55-9f0e-2a1d3c4b5e6f,user:1042,kyc,ascii
```

| Column | Rules |
|---|---|
| `id` | the OPV fact id, a UUID. Each id once. |
| `subject` | the person the fact is about, as an opaque string of at most 256 bytes (`user:1042`). This is what a subject shred erases, so file every fact under its person. Empty means no subject, and then **no subject shred will ever reach that fact**. |
| `scope` | an opaque, non-empty string (`kyc`, `order:77`). Shred by scope uses it. |
| `type` | `ascii`, `printableascii`, `base64` or `json`. OPV's other types are not supported. |

The header must be exactly `id,subject,scope,type`. Quoted fields work. The importer refuses the whole file on the
first malformed row, duplicate id or bad UUID, naming the line number and never the value.

Check the CSV before using it (these print counts, not values):

```bash
tail -n +2 facts.csv | wc -l                                   # rows: write this number down as N
tail -n +2 facts.csv | cut -d, -f1 | sort | uniq -d | wc -l   # duplicate ids: must be 0
tail -n +2 facts.csv | awk -F, '{print $NF}' | sort | uniq -c # types: only the four above
tail -n +2 facts.csv | awk -F, '$2 == ""' | wc -l             # rows with no subject: should be 0, or each one deliberate
```

(`cut` and `awk` assume no commas inside fields; if your scopes or subjects contain commas, count with a CSV parser.)

The CSV holds ids and subjects, not values. Keep it, the state file and the logs on the importer host with mode
0600, and delete them when the migration is recorded (section 8).

## 2. Freeze writes to OPV

Anything stored in OPV after the export is not in the CSV and will not move. Put the application's PII writes into
maintenance (reads can keep working against OPV), then export the CSV **after** the freeze starts. If you cannot
freeze, export, import, then export and import again just before switching: finished rows are skipped, so the
second run only copies the delta.

## 3. Dry run

```bash
pvlt import-opv --csv facts.csv \
  --opv-url $OPV --opv-token-file opv.token \
  --vault-admin-url $ADMIN --admin-token-file admin.token \
  --vault-url $DATA --vault-token-file compat.token \
  --cacert $CA --dry-run
```

`--vault-token-file` is the **compat token**: the importer reads each fact back through `/api/v1/facts/{id}`.
`--cacert` may be repeated and is added to the system's roots for all three connections.

A dry run parses the CSV and reads every fact from OPV. **It does not contact pvlt**, so it proves the CSV and the
OPV side only; step 4 proves the pvlt side. It writes nothing except an empty state file.

The report is on stderr:

```
importing 608 facts (dry run: nothing will be written)
total 608  already done 0  imported 0  already there and matching 0  missing in OPV 0  different in the vault 0  failed 0
```

**Pass:** exit code 0, `missing in OPV 0`, `failed 0`. (`imported` is 0 in a dry run: nothing is written.)

`missing in OPV: <id>` lines are ids your application points to that OPV does not have (a 404, or a 410 for a fact
OPV deleted). Do not delete them from the CSV to make the run pass: find out why the application has a pointer to
nothing. If they really are dead pointers, take them out of the CSV deliberately and record the ids.

## 4. Canary: one row, for real

```bash
head -2 facts.csv > canary.csv
pvlt import-opv --csv canary.csv --state facts.csv.pvlt-import-state \
  --opv-url $OPV --opv-token-file opv.token \
  --vault-admin-url $ADMIN --admin-token-file admin.token \
  --vault-url $DATA --vault-token-file compat.token --cacert $CA
```

`--state` points at the full run's state file, so the full run skips this row.

**Pass:** `imported 1`, exit 0. This is the first call that writes to pvlt and reads back through it, so it proves
the admin token, the compat token, the `compat` read rule and TLS to both listeners. If it fails, see the table in
section 5; every failure there shows up on the first row.

## 5. Full import

```bash
set -o pipefail
pvlt import-opv --csv facts.csv \
  --opv-url $OPV --opv-token-file opv.token \
  --vault-admin-url $ADMIN --admin-token-file admin.token \
  --vault-url $DATA --vault-token-file compat.token --cacert $CA \
  2>&1 | tee import.log
echo "exit $?"
```

For each row it reads the value from OPV, writes it through the admin route `POST /v2/admin/import/fact` with the
same id, reads it back through `/api/v1/facts/{id}` and compares SHA-256 digests. Only a matching row is recorded
as done. Rows go one at a time.

```
importing 608 facts
total 608  already done 1  imported 607  already there and matching 0  missing in OPV 0  different in the vault 0  failed 0
```

| Field | Meaning |
|---|---|
| `already done` | skipped: an earlier run verified it (it is in the state file) |
| `imported` | written now, read back, digest matched |
| `already there and matching` | the id was already in pvlt (409) with the same value, for example after a crash between the write and the mark |
| `missing in OPV` | OPV answered 404 or 410. Not imported |
| `different in the vault` | pvlt already holds this id with a **different** value. Nothing was changed. Investigate; never "fix" it by shredding blindly |
| `failed` | a request failed; the reason follows the id |

**Exit codes:** 0 when nothing is missing, different or failed; 1 otherwise (the last line is then `error: not every
fact was imported cleanly; ...`); 2 for a usage error.

**Rerunning is the fix for any failure.** The state file (`<csv>.pvlt-import-state`, or `--state FILE`) gets one id
per verified row, synced to disk before the next row, mode 0600. A rerun skips those ids. There are no automatic
retries: fix the cause, run the same command again, and repeat until it exits 0.

What a `failed:` line means:

| Reason | Usually | Fix |
|---|---|---|
| `the vault answered 401` | wrong admin token | check `admin.token` against `PVLT_ADMIN_TOKENS_FILE` |
| `the vault answered 400` | the value does not match its type (for example non-ASCII in `ascii`), or the subject is over 256 bytes | correct the row's `type` or `subject` in the CSV |
| `the vault answered 410` | the row's subject was already shredded in pvlt, and a shredded subject is never reopened | expected only after a rehearsal on the same vault; never rehearse on the production vault |
| `the vault answered 503` | pvlt is sealed, or a required service is down | `/readyz` says which |
| `the server answered 401` | wrong OPV token, **or** wrong compat token on the read-back | try each by hand (section 0, check 5) |
| `the server answered 403` | the `compat` role may not read this type | section 0, check 4 |
| `the server answered 429` | a `read_per_hour` limit on the `compat` role | remove it for the import |
| `the server answered 503` | the read-back was refused because pvlt is sealed or the audit log cannot be written | `/readyz` |
| `the fact could not be read back` | written, but the read-back was 404 or 410 | rerun; if it repeats, the id was shredded in pvlt: investigate |
| `request failed: could not connect` / `timed out` | network or DNS from the importer host | section 0, check 5 |
| `the response has no value` / `was not JSON` | OPV returned something that is not `{"value": "..."}` | look at that id in OPV |
| `cannot record progress: ...` | the state file cannot be written | disk space, permissions |

"The server" is OPV on the read and pvlt on the read-back; the two are told apart only by trying each by hand.

The importer logs counts and ids, never values, and holds one value at a time in memory, wiped after use. Run it
on a host that may see the plaintext of both services.

## 6. Verify

Each check below is independent of the importer's own bookkeeping. Run them all, in order, and record the output.
"N" is the row count from section 1.

### V1. The report adds up

The last report line of the final run has `missing in OPV 0  different in the vault 0  failed 0`, the exit code was
0, and **across all runs** every row was counted once: the final run's `already done + imported + already there and
matching` equals N.

### V2. The state file covers the CSV exactly

```bash
comm -3 <(tail -n +2 facts.csv | cut -d, -f1 | sort) <(sort facts.csv.pvlt-import-state)
```

**Pass:** no output. A line in the first column is a CSV id that was never verified; in the second, an id that is
not in the CSV (a different CSV was used with this state file).

### V3. The key store has every id, active, with the right type

Run against pvlt's database (the URL in `PVLT_DATABASE_URL_FILE`, here in `$PVLT_DATABASE_URL`). The CSV goes into a temporary table in this session only.

```bash
psql "$PVLT_DATABASE_URL" -v ON_ERROR_STOP=1 \
  -c "CREATE TEMP TABLE want (id uuid, subject text, scope text, type text)" \
  -c "\copy want FROM STDIN WITH (FORMAT csv, HEADER true)" \
  -c "SELECT count(*) AS csv_rows,
             count(f.fact_id) AS in_pvlt,
             count(*) FILTER (WHERE f.fact_id IS NULL) AS missing,
             count(*) FILTER (WHERE f.state <> 'active') AS not_active,
             count(*) FILTER (WHERE f.fact_type <> w.type) AS wrong_type,
             count(*) FILTER (WHERE f.kind <> 'fact') AS not_a_fact
      FROM want w LEFT JOIN facts f ON f.fact_id = w.id" \
  < facts.csv
```

**Pass:** `csv_rows` = `in_pvlt` = N, and `missing`, `not_active`, `wrong_type`, `not_a_fact` are all 0. (If the
database is in a container: `docker exec -i <postgres-container> psql -U <user> -d <db> ...` with the same
arguments and the CSV on stdin.)

### V4. Every value matches, compared by a second program

`scripts/verify_opv_import.py` reads each CSV row from OPV and from pvlt's `/api/v1`, and compares the type and the
SHA-256 of the value. It shares no code with the importer. It needs only Python 3.9+ and the same three files.

```bash
python3 scripts/verify_opv_import.py --csv facts.csv \
  --opv-url $OPV --opv-token-file opv.token \
  --vault-url $DATA --vault-token-file compat.token --cacert $CA
```

```
checked 608  ok 608  problems 0
```

**Pass:** `problems 0`, exit 0. Each problem is one line naming the id and what was wrong (`MISMATCH`, `TYPE`, or
the HTTP status from `opv` or `vault`), never a value. `--sample K` checks K random rows instead of all of them;
use all of them unless N is very large. Every read through pvlt is written to its audit log as a `read.grant` by
`compat`; that is expected.

### V5. Facts are filed under the right person

Pick three subjects from the CSV, including one with many rows. For each, the audit log's `create` entries for that
subject must name exactly the CSV's ids for it:

```bash
S='user:1042'
curl -sS --cacert $CA -H "Authorization: Bearer $(cat admin.token)" -G $ADMIN/v2/admin/audit \
  --data-urlencode "subject=$S" --data-urlencode kind=create --data-urlencode limit=1000 \
  | jq -r '.entries[].body.fact_id' | sort > got.txt
awk -F, -v s="$S" 'NR > 1 && $2 == s {print $1}' facts.csv | sort > want.txt
diff want.txt got.txt && echo "subject ok: $(wc -l < want.txt) facts"
```

**Pass:** no diff. The server blinds the subject before it searches, but the subject travels in the query string,
so it can end up in a proxy's access log. That is fine for an opaque id like `user:1042`. If your subjects are
names or email addresses, turn on `PVLT_GDPR_MODE=true` and use `POST /v2/admin/subject/facts {"subject": ...}` on
the admin listener instead: it lists the same ids and takes the subject in the body.

### V6. The audit log is intact and shows the import

```bash
curl -sS --cacert $CA -H "Authorization: Bearer $(cat admin.token)" $ADMIN/v2/admin/audit/verify
```

**Pass:** `"status": "ok"` and `"reads_blocked": false`. Then `pvlt audit-verify` (where the server's environment is
set) exits 0. In the database, the import shows as one `create` per row under the name of the admin whose token
ran it, and at least one `read.grant` per row under `compat` (the read-backs, plus V4's reads):

```bash
psql "$PVLT_DATABASE_URL" -c "SELECT kind, principal, count(*) FROM audit GROUP BY 1, 2 ORDER BY 1, 2"
```

```
    kind    | principal | count
------------+-----------+-------
 admin      | alice     |     3
 create     | alice     |   608
 read.grant | compat    |  1216
```

**Pass:** `create` for that admin equals N. The canary is one of the N, and a row counted as `already there and
matching` was created once by an earlier run, so neither adds to it. More than N means something else was written
through the admin import route: find out what before going on. Run this before V7, which adds one.

### V7. Erasure works end to end

Create a test fact with the admin import route, read it, shred its subject, and confirm it is gone and that the
shred reached the ledger bucket. This uses only what the import already needed.

```bash
T=$(uuidgen | tr A-Z a-z)
AUTH="Authorization: Bearer $(cat admin.token)"
curl -sS --cacert $CA -H "$AUTH" $ADMIN/v2/admin/import/fact \
  -d "{\"id\":\"$T\",\"subject\":\"migration-canary\",\"scope\":\"migration-canary\",\"type\":\"ascii\",\"value\":\"canary\"}"
curl -sS --cacert $CA -o /dev/null -w '%{http_code}\n' -H "X-OPV-GRANT-TOKEN: $(cat compat.token)" $DATA/api/v1/facts/$T   # 200
curl -sS --cacert $CA -H "$AUTH" $ADMIN/v2/admin/shred/subject -d '{"subject":"migration-canary","reason":"admin"}'      # {"outcome":"shredded","count":1}
curl -sS --cacert $CA -o /dev/null -w '%{http_code}\n' -H "X-OPV-GRANT-TOKEN: $(cat compat.token)" $DATA/api/v1/facts/$T   # 410
aws s3 ls s3://$PVLT_LEDGER_S3_BUCKET/ledger/$(echo $PVLT_DOMAIN | tr -d -)/ | tail -1        # a new, highest-numbered entry
```

**Pass:** 200, `shredded`, 410, and the ledger bucket's newest `ledger/<domain>/<seq>.json` is the entry just
written (add `--endpoint-url` for MinIO or another S3-compatible store). `count` is the number of subject keys
destroyed, always 1 for one subject, however many facts it held.

On staging, also restart pvlt, unseal it, and check the test fact is still 410: the ledger is replayed on start.

### V8. Nothing readable at rest (staging only, with test data)

With a known test value in the import (never do this with real data, which would put it on a command line):

```bash
pg_dump "$PVLT_DATABASE_URL" | grep -c 'Known Test Value'        # 0
aws s3 cp --recursive s3://$PVLT_S3_BUCKET ./bucket-copy && grep -rl 'Known Test Value' ./bucket-copy | wc -l   # 0
```

### V9. The application reads from pvlt

Point a staging (then production) application at pvlt and use it: every screen that shows a migrated fact,
every flow that stores one, every purge. Then:

* `GET $ADMIN/v2/admin/audit?kind=deny` has no entries from the application: a `deny` is something the
  application does that the `compat` role forbids.
* If the application reads from pvlt with a fallback to OPV during the overlap (section 7), the fallback count is
  **zero**. Any fallback is a fact the import missed: add it to the CSV and rerun.
* A backup taken after the import (`pvlt backup`) restores into a scratch database (`pvlt restore`, RUNNING.md).

**Done:** V1 to V9 pass. Record the date, N, the final report line, V4's line and V3's counts.

## 7. Switch clients

* **`/api/v1` first.** Change the base URL and the `X-OPV-GRANT-TOKEN` value. Differences an OPV client may notice:
  a shredded fact is `410`, not `404`; four types only; `DELETE` works (it is a crypto-shred, written to the ledger)
  and needs the vault unsealed; errors are `{"error", "message"}` with fixed text; `subject_custom_id` on store files
  a new fact under a person. Use `/readyz`, not a test write, as the health check.
* **If you read with a fallback to OPV during an overlap**, fall back **only on 404**. Never on 410 (that would bring
  a shredded fact back from OPV), and never on 403, 503 or a connection error (pvlt cannot tell you whether the
  fact was shredded while it is sealed or unreachable). Write only to pvlt. OPV cannot erase anything you shred in
  pvlt during the overlap, so keep the overlap short.
* **`/v2` later.** The Python client (`clients/python`) and TypeScript client (`clients/typescript`) cover facts
  and, in TypeScript, browser-side encrypted blobs. The backend mints short-lived delegated tokens; once nothing
  uses `/api/v1`, unset `PVLT_COMPAT_TOKEN_FILE`, which makes `/api/v1` refuse everything.
* Watch `GET /v2/admin/audit?kind=deny` during the transition.

## 8. Retire OPV

Erasure in pvlt does not reach OPV's copies. Until OPV and everything derived from it is gone, a subject you erased
in pvlt is still recoverable from OPV.

* Stop OPV and revoke its credentials.
* Destroy its database, its buckets, **and every dump, snapshot and backup of either**, including copies pulled to
  other machines, on the schedule your retention policy allows. This is the step most often missed: a forgotten dump
  defeats crypto-shredding.
* Delete the CSV, the state file, `import.log` and V5's `got.txt` / `want.txt`: they hold ids and subjects.
* Record the date, the counts and the destruction in your own records. pvlt knows nothing about OPV's side.

## 9. Rehearse first

1. **Locally:** `scripts/smoke.sh` runs the importer against `scripts/fake_opv.py`, including a dry run, a flaky
   upstream, a missing row, a resume, the verify script and a subject shred of an imported fact.
2. **On staging, with test data written through your application.** This tests your export as well as the import:
   seed OPV through the application, export, run sections 3 to 6 in full against a staging pvlt, including V7's
   restart and V8.
3. **Never rehearse on the production pvlt.** A rehearsal's facts and shreds would be in it for good: a shredded
   subject is never reopened, so the real import of that subject would fail.
4. **In production:** the dry run (it only reads OPV), then sections 4 to 6.

## What this does not do

* No two-way sync or live dual-write: it is a one-time copy.
* Facts with expiry or retention in OPV arrive without them; set them in pvlt afterwards if you need them.
* Blobs and anything outside `/api/v1/facts` are not migrated.
* Facts with no subject in the CSV can be shredded one at a time or by scope, never by subject.
