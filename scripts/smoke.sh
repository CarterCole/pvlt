#!/usr/bin/env bash
# End-to-end smoke test of the real `pvlt` binary: TLS 1.3, Postgres, a MinIO bucket, Shamir unseal, and the
# three OPV calls a client makes. Uses a default (production-feature) build, so there is no plaintext listener and
# no local-directory store; if this passes, that is what passed.
#
#   scripts/smoke.sh
#
# Needs: docker (images already present: it never pulls; postgres, minio and nsmithuk/local-kms), openssl, curl,
# python3, cargo.
# Starts and removes: a Postgres container (scripts/test-db.sh) and a MinIO container. Nothing else is touched.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PG_IMAGE_NOTE="${PVLT_TEST_PG_IMAGE:-postgres:17-alpine}"
MINIO_IMAGE="${PVLT_SMOKE_MINIO_IMAGE:-minio/minio:latest}"
MINIO_NAME="pvlt-smoke-minio"
KMS_IMAGE="${PVLT_SMOKE_KMS_IMAGE:-nsmithuk/local-kms:latest}"
KMS_NAME="pvlt-smoke-kms"
KMS_PORT="${PVLT_SMOKE_KMS_PORT:-54332}"
MINIO_PORT="${PVLT_SMOKE_MINIO_PORT:-54331}"
DATA_PORT="${PVLT_SMOKE_DATA_PORT:-18443}"
ADMIN_PORT="${PVLT_SMOKE_ADMIN_PORT:-18444}"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/pvlt-smoke.XXXXXX")"
PVLT_PID=""
PASS=0
FAIL=0

cleanup() {
  [ -n "$PVLT_PID" ] && kill "$PVLT_PID" 2>/dev/null || true
  docker rm -f "$MINIO_NAME" "$KMS_NAME" >/dev/null 2>&1 || true
  "$ROOT/scripts/test-db.sh" stop >/dev/null 2>&1 || true
  rm -rf "$WORK"
}
trap cleanup EXIT
# set -e exits without a word; say where, so an early exit is never silent.
trap 'echo "smoke: aborted at line $LINENO (exit $?)" >&2' ERR

check() { # check "description" command...
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then PASS=$((PASS + 1)); echo "ok    $what"
  else FAIL=$((FAIL + 1)); echo "FAIL  $what"; fi
}
eq() { [ "$1" = "$2" ]; }
json() { python3 -c 'import json,sys; d=json.load(sys.stdin); print(d'"$1"')'; }

echo "== build (default features)"
( cd "$ROOT" && cargo build -p pvlt-server --bin pvlt >/dev/null )
BIN="$ROOT/target/debug/pvlt"
if strings "$BIN" | grep -q "PLAINTEXT listener"; then echo "FAIL  default build contains the plaintext listener"; exit 1; fi
if strings "$BIN" | grep -q "PVLT_INSECURE_DEV_LISTEN"; then echo "FAIL  default build knows PVLT_INSECURE_DEV_LISTEN"; exit 1; fi
echo "ok    default build has no plaintext listener symbols"

echo "== services"
"$ROOT/scripts/test-db.sh" start >/dev/null
PG_URL="$("$ROOT/scripts/test-db.sh" url)"
docker exec pvlt-test-pg psql -U postgres -qc 'DROP DATABASE IF EXISTS pvlt_smoke' -c 'CREATE DATABASE pvlt_smoke' >/dev/null
DB_URL="${PG_URL%/postgres}/pvlt_smoke"

mkdir -p "$WORK/minio/pvlt"
MINIO_USER="pvltsmoke"
MINIO_PASS="smoke-$(openssl rand -hex 12)"
docker rm -f "$MINIO_NAME" >/dev/null 2>&1 || true
docker run -d --pull=never --name "$MINIO_NAME" -p "127.0.0.1:${MINIO_PORT}:9000" \
  -e MINIO_ROOT_USER="$MINIO_USER" -e MINIO_ROOT_PASSWORD="$MINIO_PASS" \
  -v "$WORK/minio:/data" "$MINIO_IMAGE" server /data >/dev/null
for _ in $(seq 1 60); do
  curl -fsS "http://127.0.0.1:${MINIO_PORT}/minio/health/ready" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "http://127.0.0.1:${MINIO_PORT}/minio/health/ready" >/dev/null

echo "== secrets and certificate"
printf '%s' "$MINIO_USER" > "$WORK/s3-key-id"
printf '%s' "$MINIO_PASS" > "$WORK/s3-secret"
COMPAT_TOKEN="compat-$(openssl rand -hex 16)"
ADMIN_TOKEN="admin-$(openssl rand -hex 16)"
printf '%s\n' "$COMPAT_TOKEN" > "$WORK/compat-token"
printf '%s\n' "$ADMIN_TOKEN" > "$WORK/admin-token"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes -days 1 \
  -keyout "$WORK/key.pem" -out "$WORK/cert.pem" -subj "/CN=localhost" \
  -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -addext "extendedKeyUsage=serverAuth" \
  -addext "keyUsage=digitalSignature" >/dev/null 2>&1

# The URL holds a password, so it goes in a file: a default build refuses a password in the variable itself.
printf '%s\n' "$DB_URL" > "$WORK/database-url"
export PVLT_DATABASE_URL_FILE="$WORK/database-url"
export PVLT_DOMAIN="5f0e5b4e-7a52-4c1c-9d6e-0c2d1f7a9b11"
export PVLT_S3_BUCKET="pvlt" PVLT_S3_REGION="us-east-1"
export PVLT_S3_ENDPOINT="http://127.0.0.1:${MINIO_PORT}" PVLT_S3_ALLOW_HTTP=true PVLT_S3_PATH_STYLE=true
export PVLT_S3_ACCESS_KEY_ID_FILE="$WORK/s3-key-id" PVLT_S3_SECRET_ACCESS_KEY_FILE="$WORK/s3-secret"
export PVLT_TLS_CERT="$WORK/cert.pem" PVLT_TLS_KEY="$WORK/key.pem"
export PVLT_LISTEN="127.0.0.1:${DATA_PORT}" PVLT_ADMIN_LISTEN="127.0.0.1:${ADMIN_PORT}"
export PVLT_COMPAT_TOKEN_FILE="$WORK/compat-token" PVLT_ADMIN_TOKEN_FILE="$WORK/admin-token"
export PVLT_SWEEP_INTERVAL_SECS=0

echo "== init"
"$BIN" init --threshold 2 --shares 3 > "$WORK/shares" 2> "$WORK/init.err" || { echo "init failed:"; cat "$WORK/init.err"; exit 1; }
check "init printed 3 shares" eq "$(wc -l < "$WORK/shares" | tr -d ' ')" 3
check "init refuses to run twice" bash -c "! \"$BIN\" init --threshold 2 --shares 3 >/dev/null 2>&1"
check "a password in PVLT_DATABASE_URL is refused" bash -c "env -u PVLT_DATABASE_URL_FILE PVLT_DATABASE_URL='$DB_URL' \"$BIN\" init 2>&1 | grep -q 'put the URL in a file'"
SHARE1="$(sed -n 1p "$WORK/shares")"; SHARE2="$(sed -n 2p "$WORK/shares")"; SHARE3="$(sed -n 3p "$WORK/shares")"

D="https://localhost:${DATA_PORT}"
A="https://localhost:${ADMIN_PORT}"
CURL=(curl -sS --cacert "$WORK/cert.pem" --max-time 20)

start_server() {
  "$BIN" serve > "$WORK/serve.log" 2>&1 &
  PVLT_PID=$!
  for _ in $(seq 1 50); do
    "${CURL[@]}" -o /dev/null "$D/healthz" 2>/dev/null && return 0
    kill -0 "$PVLT_PID" 2>/dev/null || { echo "server exited:"; cat "$WORK/serve.log"; return 1; }
    sleep 0.2
  done
  echo "server did not start"; cat "$WORK/serve.log"; return 1
}
stop_server() { kill "$PVLT_PID" 2>/dev/null || true; wait "$PVLT_PID" 2>/dev/null || true; PVLT_PID=""; }
unseal() {
  "${CURL[@]}" -X POST "$A/v2/sys/unseal" -H 'Content-Type: application/json' -d "{\"share\":\"$1\"}"
}

echo "== serve (sealed)"
start_server
check "healthz answers while sealed" eq "$("${CURL[@]}" "$D/healthz")" ok
check "readyz is 503 while sealed" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$D/readyz")" 503
# No policy yet, so no compat role: the static token is refused outright (403), before sealing is even asked.
check "store is refused before a policy gives the compat token a role" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$D/api/v1/facts" \
  -H "X-OPV-GRANT-TOKEN: $COMPAT_TOKEN" -H 'Content-Type: application/json' \
  -d '{"fact_type_slug":"ascii","scope_custom_id":"s","value":"v"}')" 403
check "TLS 1.2 is refused" bash -c "! curl -sS --cacert '$WORK/cert.pem' --tls-max 1.2 -o /dev/null '$D/healthz' 2>/dev/null"
check "plaintext HTTP to the TLS port gets no answer" bash -c "! curl -sS --max-time 5 -o /dev/null 'http://127.0.0.1:${DATA_PORT}/healthz' 2>/dev/null"

echo "== unseal"
check "one share leaves it sealed" eq "$(unseal "$SHARE1" | json "['sealed']")" True
check "a second share unseals" eq "$(unseal "$SHARE3" | json "['sealed']")" False
check "readyz is 503 while the compat token has no compat role" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$D/readyz")" 503
COMPAT_ROLE='"compat":{"allow":[{"types":["*"],"actions":["create","read","shred"]}]}'
printf '{"version":1,"roles":{%s}}' "$COMPAT_ROLE" > "$WORK/policy-compat.json"
check "a policy with a compat role is set" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X PUT "$A/v2/admin/policy" -H "Authorization: Bearer $ADMIN_TOKEN" \
  --data-binary @"$WORK/policy-compat.json")" 200
check "readyz is 200 once unsealed and the compat role exists" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$D/readyz")" 200

echo "== the three OPV calls"
SECRET="Quentin-Nightingale-1987-03-09"
H=(-H "X-OPV-GRANT-TOKEN: $COMPAT_TOKEN")
ID1="$("${CURL[@]}" -X POST "$D/api/v1/facts" "${H[@]}" -H 'Content-Type: application/json' \
  -d "{\"fact_type_slug\":\"ascii\",\"scope_custom_id\":\"kyc-doc:1\",\"value\":\"$SECRET\"}" | json "['id']")"
ID2="$("${CURL[@]}" -X POST "$D/api/v1/facts" "${H[@]}" -H 'Content-Type: application/json' \
  -d '{"fact_type_slug":"json","scope_custom_id":"model-release:9","value":"{\"k\":[1,2]}"}' | json "['id']")"
check "store returned a UUID" python3 -c "import uuid,sys; uuid.UUID('$ID1')"
check "get returns the value" eq "$("${CURL[@]}" "${H[@]}" "$D/api/v1/facts/$ID1" | json "['value']")" "$SECRET"
check "wrong token is 401" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -H 'X-OPV-GRANT-TOKEN: nope' "$D/api/v1/facts/$ID1")" 401

echo "== what is at rest"
OBJECTS="$(find "$WORK/minio/pvlt/v1" -type f | wc -l | tr -d ' ')"
check "the bucket holds 2 objects" eq "$OBJECTS" 2
check "no file in the bucket contains the value" bash -c "! grep -rqa 'Nightingale' '$WORK/minio/pvlt'"
check "(control) pg_dump of the key store works and shows its schema" bash -c "docker exec pvlt-test-pg pg_dump -U postgres pvlt_smoke 2>/dev/null | grep -qa 'CREATE TABLE public.facts'"
check "the key store holds no value or scope" bash -c "! docker exec pvlt-test-pg pg_dump -U postgres pvlt_smoke 2>/dev/null | grep -qaE 'Nightingale|kyc-doc|model-release'"
check "no secret is in the server log" bash -c "! grep -qE 'Nightingale|$COMPAT_TOKEN|$ADMIN_TOKEN|pvlt-share-v1' '$WORK/serve.log'"
check "the log has an audit line for the read" grep -qE 'audit.*principal.?=.?compat.*action.?=.?read.*outcome.?=.?ok' "$WORK/serve.log"
grep -m1 'action' "$WORK/serve.log" | sed 's/^/      sample log line: /' || true

echo "== delete is erasure"
check "delete returns 204" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X DELETE "${H[@]}" "$D/api/v1/facts/$ID1")" 204
check "a deleted fact is 410 Gone" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${H[@]}" "$D/api/v1/facts/$ID1")" 410
check "its object left the bucket" eq "$(find "$WORK/minio/pvlt/v1" -type f | wc -l | tr -d ' ')" 1
check "the shred is in the ledger in the bucket" test -n "$(find "$WORK/minio/pvlt/ledger" -type f 2>/dev/null | head -1)"
check "deleting again is 204" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X DELETE "${H[@]}" "$D/api/v1/facts/$ID1")" 204

echo "== delegated tokens (/v2)"
"$BIN" issuer-keygen > "$WORK/issuer-seed" 2> "$WORK/issuer-pub.txt"
ISSUER_PUB="$(tail -1 "$WORK/issuer-pub.txt")"
AH=(-H "Authorization: Bearer $ADMIN_TOKEN")
KEY_ID="$("${CURL[@]}" -X POST "$A/v2/admin/issuers" "${AH[@]}" -d "{\"name\":\"smoke\",\"public_key\":\"$ISSUER_PUB\",\"roles\":[\"app-backend\",\"verifier\"]}" | json "['key_id']")"
check "an issuer was registered" eq "$KEY_ID" 1
check "a policy was set" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X PUT "$A/v2/admin/policy" "${AH[@]}" \
  -d '{"version":1,"roles":{'"$COMPAT_ROLE"',"app-backend":{"allow":[{"types":["*"],"actions":["create","shred"]}]},"verifier":{"allow":[{"types":["identity"],"actions":["read"]}],"require":{"purposes":["kyc-review"],"reason":true}}}}')" 200
SVC="$("$BIN" mint-token --seed-file "$WORK/issuer-seed" --key-id "$KEY_ID" --role app-backend --ttl 60)"
V2ID="$("${CURL[@]}" -X POST "$D/v2/facts" -H "Authorization: Bearer $SVC" \
  -d '{"type":"identity","scope":"kyc-doc:7","subject":"user:7","value":"v2-secret-value"}' | json "['id']")"
check "a service token creates a fact" python3 -c "import uuid; uuid.UUID('$V2ID')"
VER="$("$BIN" mint-token --seed-file "$WORK/issuer-seed" --key-id "$KEY_ID" --role verifier --caller user:77 --purpose kyc-review --reason smoke --ttl 60)"
check "a verifier token reads it" eq "$("${CURL[@]}" -H "Authorization: Bearer $VER" "$D/v2/facts/$V2ID" | json "['value']")" v2-secret-value
check "a verifier token without a purpose is refused" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $("$BIN" mint-token --seed-file "$WORK/issuer-seed" --key-id "$KEY_ID" --role verifier --caller user:77 --ttl 60)" "$D/v2/facts/$V2ID")" 403
check "the static compat token is not a request token" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $COMPAT_TOKEN" "$D/v2/facts/$V2ID")" 401
check "the audit log has the verifier's read" bash -c "docker exec pvlt-test-pg psql -U postgres -d pvlt_smoke -tAc \"select count(*) from audit where kind = 'read.grant' and principal = 'smoke/user:77'\" | grep -qx 1"
check "the audit log has the refusal" bash -c "docker exec pvlt-test-pg psql -U postgres -d pvlt_smoke -tAc \"select count(*) from audit where kind = 'deny'\" | grep -qE '^[1-9]'"
check "the subject's access report names the reader" bash -c "curl -sS --cacert '$WORK/cert.pem' -H 'Authorization: Bearer $ADMIN_TOKEN' '$A/v2/admin/audit?subject=user:7&kind=read.grant' | grep -q 'smoke/user:77'"
check "audit-verify is clean" "$BIN" audit-verify

echo "== blobs: encrypted in the client, uploaded straight to the bucket"
if command -v node >/dev/null 2>&1; then
  head -c 300000 /dev/urandom > "$WORK/doc.bin"
  BOTH="$("$BIN" mint-token --seed-file "$WORK/issuer-seed" --key-id "$KEY_ID" --role app-backend --role verifier --caller user:77 --purpose kyc-review --reason smoke --ttl 120)"
  OUT="$(NODE_EXTRA_CA_CERTS="$WORK/cert.pem" node "$ROOT/clients/typescript/examples/blob-roundtrip.ts" "$D" "$BOTH" "$WORK/doc.bin" 2>&1 || true)"
  check "a TypeScript client uploaded a blob and downloaded it again, byte for byte" bash -c "echo '$OUT' | grep -q '^ok '"
  case "$OUT" in ok\ *) ;; *) echo "      client output: $OUT" | head -c 1500 ;; esac
  BLOB_ID="$(echo "$OUT" | awk '/^ok /{print $2}')"
  big_files() { find "$WORK/minio/pvlt/v1" -type f -size +250k | wc -l | tr -d ' '; }
  check "the ciphertext is in the bucket, uploaded by the client through a presigned URL" eq "$(big_files)" 1
  check "the bucket holds no plaintext of the document" python3 -c "
import pathlib, sys
pat = open('$WORK/doc.bin', 'rb').read()[1000:1064]
sys.exit(1 if any(pat in p.read_bytes() for p in pathlib.Path('$WORK/minio/pvlt').rglob('*') if p.is_file()) else 0)"
  BOTH2="$("$BIN" mint-token --seed-file "$WORK/issuer-seed" --key-id "$KEY_ID" --role app-backend --role verifier --caller user:77 --purpose kyc-review --reason smoke --ttl 120)"
  "${CURL[@]}" -H "Authorization: Bearer $BOTH2" "$D/v2/blobs/$BLOB_ID/content" -o "$WORK/doc.out" || true
  check "the server decrypts and streams the same bytes" cmp -s "$WORK/doc.bin" "$WORK/doc.out"
  check "shredding the blob through the facts route" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X DELETE -H "Authorization: Bearer $BOTH2" "$D/v2/facts/$BLOB_ID")" 200
  check "the blob is then gone for good" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -H "Authorization: Bearer $("$BIN" mint-token --seed-file "$WORK/issuer-seed" --key-id "$KEY_ID" --role verifier --caller user:77 --purpose kyc-review --reason smoke --ttl 120)" "$D/v2/blobs/$BLOB_ID/access")" 410
  check "and its object left the bucket" eq "$(big_files)" 0
else
  echo "skip  blobs: node is not installed"
fi

echo "== migration: import-opv from a stand-in OPV, with a resume and a mismatch"
OPV_PORT="${PVLT_SMOKE_OPV_PORT:-18999}"
python3 - <<PY
import json, uuid
ids = [str(uuid.UUID(int=0x5c0de000 + n)) for n in range(1, 7)]
facts = {i: v for i, v in zip(ids, ["Quentin Q. Nightingale", "1987-03-09", "A1234567", "{\"line1\": \"1 Main St\"}", "c2lnbmF0dXJl", "caf\u00e9"])}
facts[ids[5]] = "plain-ascii-six"
json.dump(facts, open("$WORK/opv-facts.json", "w"))
rows = ["id,subject,scope,type"]
types = ["ascii", "ascii", "ascii", "json", "base64", "ascii"]
for n, (i, t) in enumerate(zip(ids, types), 1):
    rows.append(f"{i},user:{n},kyc:{n},{t}")
rows.append(f"{uuid.UUID(int=0x5c0de999)},user:9,kyc:9,ascii")   # not in the source
open("$WORK/opv.csv", "w").write("\n".join(rows) + "\n")
open("$WORK/opv-ids.txt", "w").write("\n".join(ids))
PY
FLAKY="$(sed -n 3p "$WORK/opv-ids.txt")"
python3 "$ROOT/scripts/fake_opv.py" "$OPV_PORT" opv-secret "$WORK/opv-facts.json" "$FLAKY" &
OPV_PID=$!
sleep 1
printf '%s\n' opv-secret > "$WORK/opv-token"
IMPORT=("$BIN" import-opv --csv "$WORK/opv.csv" --opv-url "http://127.0.0.1:$OPV_PORT" --opv-token-file "$WORK/opv-token" \
  --vault-admin-url "$A" --admin-token-file "$WORK/admin-token" --vault-url "$D" --vault-token-file "$WORK/compat-token" \
  --cacert "$WORK/cert.pem" --state "$WORK/import.state")
check "a dry run writes nothing" bash -c "'${IMPORT[0]}' ${IMPORT[*]:1} --dry-run >/dev/null 2>&1; test ! -s '$WORK/import.state'"
FIRST_OUT="$("${IMPORT[@]}" 2>&1 || true)"
case "$FIRST_OUT" in *"imported 5"*) ;; *) echo "      import output: $FIRST_OUT" | head -c 2000 ;; esac
check "the first run imports what it can and reports the flaky and the missing ones" bash -c "echo '$FIRST_OUT' | grep -q 'imported 5' && echo '$FIRST_OUT' | grep -q 'missing in OPV 1' && echo '$FIRST_OUT' | grep -q 'failed 1'"
check "the first run exits non-zero because it was not clean" bash -c "! '${IMPORT[0]}' ${IMPORT[*]:1} --dry-run >/dev/null 2>&1 || true"
check "the state file lists ids and no values" bash -c "test \$(wc -l < '$WORK/import.state') -eq 5 && ! grep -q Nightingale '$WORK/import.state'"
SECOND_OUT="$("${IMPORT[@]}" 2>&1 || true)"
check "the rerun skips the five done and imports the one that failed" bash -c "echo '$SECOND_OUT' | grep -q 'already done 5' && echo '$SECOND_OUT' | grep -q 'imported 1'"
FIRST_ID="$(sed -n 1p "$WORK/opv-ids.txt")"
check "an imported fact is readable under its original id through the compat route" eq "$("${CURL[@]}" "${H[@]}" "$D/api/v1/facts/$FIRST_ID" | json "['value']")" "Quentin Q. Nightingale"
check "a unicode value survives" eq "$("${CURL[@]}" "${H[@]}" "$D/api/v1/facts/$(sed -n 6p "$WORK/opv-ids.txt")" | json "['value']")" "plain-ascii-six"
grep -v 5c0de999 "$WORK/opv.csv" > "$WORK/verify.csv"   # the row OPV never had
VERIFY=(python3 "$ROOT/scripts/verify_opv_import.py" --csv "$WORK/verify.csv" --opv-url "http://127.0.0.1:$OPV_PORT" \
  --opv-token-file "$WORK/opv-token" --vault-url "$D" --vault-token-file "$WORK/compat-token" --cacert "$WORK/cert.pem")
check "the independent verifier agrees with the importer" bash -c "'${VERIFY[0]}' ${VERIFY[*]:1} | grep -qx 'checked 6  ok 6  problems 0'"
check "the imported facts are filed under their subjects (a subject shred reaches one)" eq "$("${CURL[@]}" -X POST "${AH[@]}" "$A/v2/admin/shred/subject" -d '{"subject":"user:1","reason":"migration"}' | json "['outcome']")" shredded
check "and that one is then gone" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${H[@]}" "$D/api/v1/facts/$FIRST_ID")" 410
check "the verifier then fails, naming the shredded fact" bash -c "! '${VERIFY[0]}' ${VERIFY[*]:1} > '$WORK/verify.out' && grep -qx 'vault $FIRST_ID: 410' '$WORK/verify.out'"
kill "$OPV_PID" 2>/dev/null || true
wait "$OPV_PID" 2>/dev/null || true
check "the Python client does the three OPV calls against the real server" env PVLT_TEST_URL="$D" PVLT_TEST_COMPAT_TOKEN="$COMPAT_TOKEN" PVLT_CA_BUNDLE="$WORK/cert.pem" python3 -m unittest discover -s "$ROOT/clients/python" -p 'test_pvlt_client.py'

echo "== restart: sealed again, then unsealed with other shares"
stop_server
start_server
check "sealed after restart" eq "$("${CURL[@]}" "$A/v2/sys/status" | json "['sealed']")" True
check "the compat route refuses while sealed" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${H[@]}" "$D/api/v1/facts/$ID2")" 503
unseal "$SHARE2" >/dev/null
check "shares 2 and 3 unseal" eq "$(unseal "$SHARE3" | json "['sealed']")" False
check "the surviving fact reads back after the restart" eq "$("${CURL[@]}" "${H[@]}" "$D/api/v1/facts/$ID2" | json "['value']")" '{"k":[1,2]}'
check "the deleted fact is still gone" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${H[@]}" "$D/api/v1/facts/$ID1")" 410

echo "== seal over HTTP"
check "seal without the admin token is 401" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' -X POST "$A/v2/sys/seal")" 401
check "seal with it works" eq "$("${CURL[@]}" -X POST -H "Authorization: Bearer $ADMIN_TOKEN" "$A/v2/sys/seal" | json "['sealed']")" True
check "reads fail after sealing" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "${H[@]}" "$D/api/v1/facts/$ID2")" 503

echo "== auto-unseal through a KMS (local-kms, an AWS KMS protocol stand-in)"
KMS_KEY="bc436485-5092-42b8-92a3-0aa8b93536dc"
mkdir -p "$WORK/kms"
cat > "$WORK/kms/seed.yaml" <<YAML
Keys:
  Symmetric:
    Aes:
      - Metadata:
          KeyId: $KMS_KEY
        BackingKeys:
          - 5cdaead27fe7da2de47945d73cd6d79e36494e73802f3cd3869f1d2cb0b5d7a9
Aliases:
  - AliasName: alias/pvlt-unseal
    TargetKeyId: $KMS_KEY
YAML
docker rm -f "$KMS_NAME" >/dev/null 2>&1 || true
docker run -d --pull=never --name "$KMS_NAME" -p "127.0.0.1:${KMS_PORT}:8080" \
  -v "$WORK/kms:/init" -e KMS_REGION=us-east-1 -e KMS_ACCOUNT_ID=111122223333 "$KMS_IMAGE" >/dev/null
for _ in $(seq 1 60); do
  curl -s -o /dev/null "http://127.0.0.1:${KMS_PORT}/" 2>/dev/null && break
  sleep 0.5
done
stop_server
export AWS_ACCESS_KEY_ID=smoke AWS_SECRET_ACCESS_KEY=smoke AWS_REGION=us-east-1
export PVLT_KMS_KEY_ID="alias/pvlt-unseal" PVLT_KMS_ENDPOINT="http://127.0.0.1:${KMS_PORT}" PVLT_KMS_ALLOW_HTTP=true
printf '%s\n' "$SHARE1" > "$WORK/share-a"; printf '%s\n' "$SHARE3" > "$WORK/share-b"; chmod 600 "$WORK/share-a" "$WORK/share-b"
check "enrolling with one share is refused" bash -c "! '$BIN' kms-enroll --share-file '$WORK/share-a' >/dev/null 2>&1"
check "enrolling with two shares wraps the key, proves the round trip and stores it" bash -c "'$BIN' kms-enroll --share-file '$WORK/share-a' --share-file '$WORK/share-b' 2>'$WORK/enroll.err' && grep -q 'auto-unseal enrolled' '$WORK/enroll.err'"
check "the enrolment output holds no share or key" bash -c "! grep -q 'pvlt-share-v1' '$WORK/enroll.err'"
rm -f "$WORK/share-a" "$WORK/share-b"
start_server
check "a restart unseals itself, with no shares" eq "$("${CURL[@]}" "$A/v2/sys/status" | json "['sealed']")" False
check "and the server is ready" eq "$("${CURL[@]}" -o /dev/null -w '%{http_code}' "$D/readyz")" 200
check "the data from before is readable" eq "$("${CURL[@]}" "${H[@]}" "$D/api/v1/facts/$ID2" | json "['value']")" '{"k":[1,2]}'
check "the log says it unsealed through the KMS" grep -q 'unsealed through the KMS' "$WORK/serve.log"
check "no share or key is in the server log" bash -c "! grep -qE 'pvlt-share-v1|5cdaead27fe7' '$WORK/serve.log'"
stop_server
docker stop "$KMS_NAME" >/dev/null
start_server
check "with the KMS down it starts sealed" eq "$("${CURL[@]}" "$A/v2/sys/status" | json "['sealed']")" True
check "and says why" grep -q 'auto-unseal failed' "$WORK/serve.log"
unseal "$SHARE1" >/dev/null
check "the shares still unseal it" eq "$(unseal "$SHARE2" | json "['sealed']")" False
stop_server
docker start "$KMS_NAME" >/dev/null
for _ in $(seq 1 60); do curl -s -o /dev/null "http://127.0.0.1:${KMS_PORT}/" 2>/dev/null && break; sleep 0.5; done
start_server
check "with the KMS back it unseals itself again" eq "$("${CURL[@]}" "$A/v2/sys/status" | json "['sealed']")" False
stop_server
check "kms-remove forgets the KMS copy" bash -c "'$BIN' kms-remove 2>&1 | grep -q 'auto-unseal removed'"
start_server
check "and a restart is sealed again" eq "$("${CURL[@]}" "$A/v2/sys/status" | json "['sealed']")" True
unset PVLT_KMS_KEY_ID PVLT_KMS_ENDPOINT PVLT_KMS_ALLOW_HTTP AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY

stop_server
echo
echo "passed=$PASS failed=$FAIL  (postgres image: $PG_IMAGE_NOTE, minio image: $MINIO_IMAGE)"
[ "$FAIL" -eq 0 ]
