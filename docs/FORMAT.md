# pvlt on-disk and on-wire format, version 1

Status: **draft for review (M0)**, 2026-11-14. Nothing here is frozen until the review in milestone M0 signs it
off. After that, any change needs a new format version or a new suite id, never an edit to v1.

This document is normative. "MUST", "MUST NOT", "SHOULD" and "MAY" are used as in RFC 2119. The Python reference
in `spec/reference/pvlt_ref.py` implements every construction here, and the vectors in `spec/vectors/` were
produced by it. Where the prose and the reference disagree, that is a bug in one of them and blocks the freeze.

`pvlt` is a working name (from the magic bytes). Renaming the project does not change the magic bytes or labels.

---

## 1. Notation

| Notation | Meaning |
|---|---|
| `a ‖ b` | byte concatenation |
| `u8(x)`, `u16(x)`, `u32(x)`, `u64(x)` | unsigned integer, big-endian, of that width |
| `lp(x)` | `u16(len(x)) ‖ x`; `len(x)` MUST be ≤ 65535 |
| `tuple(a, b, …)` | `lp(a) ‖ lp(b) ‖ …` (strings are UTF-8, integers are encoded first with the width named) |
| `"text"` | the UTF-8 bytes of the text, no terminator |
| `0x00` | a single zero byte |
| `id` | 16 bytes. UUIDs are in RFC 9562 network byte order. |
| `hex(x)` | lowercase hex, no prefix |
| `PREFIX` | `"PVLT-v1" ‖ 0x00` (8 bytes), the domain-separation prefix for every label below |

All random values MUST come from the operating system CSPRNG (`getrandom`). Every key is 32 bytes.

## 2. Algorithm suites

A suite fixes the AEAD. The KDF is HKDF-SHA-256 (RFC 5869) in every v1 suite.

| Suite id | Name | AEAD | AEAD nonce | Tag | Status |
|---|---|---|---|---|---|
| `0x0001` | `PVLT-XC20P-HS256` | XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha-03) | 24 B | 16 B | MUST implement. Default for everything the server encrypts. |
| `0x0002` | `PVLT-A256GCMSIV-HS256` | AES-256-GCM-SIV (RFC 8452) | 12 B | 16 B | MAY implement. Nonce-misuse resistant alternative. |
| `0x0003` | `PVLT-A256GCM-HS256` | AES-256-GCM (NIST SP 800-38D) | 12 B | 16 B | MUST implement. The browser suite: WebCrypto has AES-GCM and HKDF-SHA-256 but no XChaCha20 or GCM-SIV. |

Suite `0x0003` is safe here only because of section 3: every encryption key is derived fresh from a 192-bit random
salt, so a given AES-GCM key encrypts one fact, or one blob's chunks under distinct counter nonces. Random
96-bit nonces under a long-lived key never occur. Implementations MUST NOT use any AEAD key outside section 3's
derivation.

Readers MUST reject an unknown suite id, and MUST reject a suite their deployment disabled (for example a
FIPS-mode deployment that only allows `0x0003`).

## 3. Sealing: key derivation, commitment and nonces

Every encrypted unit in v1 (a fact object, a blob, a wrapped key) is sealed the same way.

Inputs: a 32-byte key `K`, the `suite` id, a fresh 24-byte random `salt`, a usage `label` and a context `ctx`.

```
info = PREFIX ‖ label ‖ 0x00 ‖ u16(suite) ‖ ctx
okm  = HKDF-SHA-256(IKM = K, salt = salt, info = info, L = 64)
ek   = okm[0..32]       the AEAD key for this unit only
ck   = okm[32..64]      the key commitment, stored next to the ciphertext
```

`ck` is stored in clear. Before any AEAD decryption, a reader MUST recompute `ck` and compare it to the stored value
in constant time, and MUST fail if they differ. This makes every seal key-committing (a ciphertext opens under at
most one `K` and one `ctx`), which plain Poly1305 and GCM tags are not.

Errors from a commitment mismatch and from an AEAD tag failure MUST be reported identically to the caller.

AEAD nonce for a single-shot seal:

| Suite | Nonce |
|---|---|
| `0x0001` | `salt` (24 bytes) |
| `0x0002`, `0x0003` | `salt[0..12]` |

AEAD nonce for chunk `i` of a stream (section 4.2), with `last` = 1 for the final chunk and 0 otherwise:

| Suite | Nonce |
|---|---|
| `0x0001` | `salt[0..19] ‖ u32(i) ‖ u8(last)` |
| `0x0002`, `0x0003` | `salt[0..7] ‖ u32(i) ‖ u8(last)` |

Labels used in v1: `"object"` (fact and blob objects) and `"wrap"` (wrapped keys). A new use MUST get a new label.

## 4. Object header (facts and blobs in the bucket)

Every object in the bucket starts with a 104-byte header.

| Offset | Size | Field | Value |
|---|---|---|---|
| 0 | 4 | `magic` | `"PVLT"` (`50 56 4c 54`) |
| 4 | 1 | `version` | `0x01` |
| 5 | 1 | `kind` | `0x01` fact, `0x02` blob |
| 6 | 2 | `suite` | section 2 |
| 8 | 16 | `domain_id` | the domain (tenant) |
| 24 | 16 | `object_id` | 128-bit random; also the bucket key (section 7) |
| 40 | 4 | `dek_generation` | starts at 0; increments when a fact is re-encrypted under a new DEK |
| 44 | 4 | `chunk_size` | 0 for a fact; plaintext bytes per chunk for a blob |
| 48 | 24 | `salt` | random, fresh for every object |
| 72 | 32 | `commitment` | `ck` from section 3 |

`object_id` is not the fact id the API returns. Fact ids can be caller-supplied (OPV import keeps the UUIDs the application
already stores), while object ids are always random, so a bucket listing reveals nothing about fact ids.

Sealing an object uses `K` = the object's DEK, `label = "object"` and `ctx = header[0..48]` (magic through
`chunk_size`). The commitment therefore binds the key to the domain, object, generation and kind; changing any of
those fields fails the commitment check before the AEAD runs. The AEAD associated data is the full 104-byte header.

### 4.1 Fact objects (`kind = 0x01`)

```
object = header ‖ AEAD-Seal(ek, nonce, plaintext = pad(value), aad = header)
```

`pad(v) = v ‖ 0x80 ‖ 0x00 * (c - len(v) - 1)` where the size class `c` is the smallest `256 · 4^k` (k ≥ 0) with
`c ≥ len(v) + 1`. The classes are 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB, 4 MiB. Values longer than
4 MiB − 1 are not facts; store them as blobs. Deployments set a lower limit (default 65,536 bytes).

`unpad` strips trailing zeros, requires the next byte to be `0x80` and removes it, and MUST then check that
`len(padded)` equals the class computed from the result. Non-canonical padding is an error, not a value.

`chunk_size` MUST be 0. Readers MUST reject a fact object whose ciphertext length is not `class + 16` for a valid
class.

### 4.2 Blob objects (`kind = 0x02`)

Blobs use a STREAM construction (Hoang, Reyhanitabar, Rogaway, Vizár 2015), the same family as `age` and Tink's
streaming AEAD. It gives constant-memory encryption and decryption and detects truncation, reordering and
extension.

The plaintext stream is the length, the data, then zero padding to a Padmé size:

```
P = u64(len(data)) ‖ data ‖ 0x00 * (padme(8 + len(data)) - 8 - len(data))
```

`padme(L)` for `L ≥ 2`: `E = floor(log2 L)`, `S = floor(log2 E) + 1`, `z = E - S`, `mask = 2^z - 1`,
result `(L + mask) & ~mask`. Padmé leaks at most O(log log L) bits of length and costs at most about 12 %.

`P` is split into `n = ceil(len(P) / chunk_size)` chunks. Every chunk except the last is exactly `chunk_size`
bytes; the last is 1 to `chunk_size` bytes.

```
object  = header ‖ C_0 ‖ C_1 ‖ … ‖ C_{n-1}
C_i     = AEAD-Seal(ek, nonce(i, last = (i == n-1)), plaintext = chunk_i, aad = header)
```

`chunk_size` MUST be a multiple of 1024 between 1024 and 16 MiB. The default is 65536. Readers MUST:

- treat a chunk as final exactly when it is the last in the object, and fail if a non-final chunk is short;
- fail if the object ends before a chunk sealed with `last = 1` has been read;
- check after the final chunk that the declared `u64` length fits, that every padding byte is zero, and that
  `len(P)` equals `padme(8 + len(data))` (non-canonical padding is an error, as for facts);
- never release plaintext from chunk `i` before chunk `i`'s tag has verified (releasing earlier verified chunks of
  an object that later fails is allowed; the caller MUST discard the whole result on failure).

The DEK for a blob is handed to the browser for direct upload (B2 in the requirements). The browser derives `ek`
and `ck` with WebCrypto HKDF and encrypts with WebCrypto AES-GCM, so browser uploads use suite `0x0003`.

## 5. Wrapped keys (key store)

Every key below the root is stored wrapped by its parent. A wrapped key is 107 bytes:

| Offset | Size | Field |
|---|---|---|
| 0 | 1 | `version` = `0x01` |
| 1 | 2 | `suite` |
| 3 | 24 | `salt` |
| 27 | 32 | `commitment` |
| 59 | 48 | `AEAD-Seal(ek, nonce, plaintext = child key, aad = wrapped[0..59] ‖ wctx)` (32 + 16) |

Sealing uses `K` = the parent key, `label = "wrap"`, `ctx = wctx`. The wrap context `wctx` is not stored; the reader
rebuilds it from the row it is reading, so a wrapped key copied onto another row fails to open.

| Child key | Parent | `wctx` |
|---|---|---|
| Domain KEK | Root key | `tuple("kek", domain_id, u32(kek_version), root_key_id, u32(root_key_version))` |
| Domain blind-index key (BIK) | Root key | `tuple("bik", domain_id, u32(bik_version), root_key_id, u32(root_key_version))` |
| Domain blind-index key for caller indexes (BIX) | Root key | `tuple("bix", domain_id, u32(bix_version), root_key_id, u32(root_key_version))` |
| Subject key | Domain KEK | `tuple("subject", domain_id, subject_hmac, u32(subject_key_version), u32(kek_version))` |
| Data key (DEK) | Subject key | `tuple("dek", domain_id, subject_hmac, u32(subject_key_version), object_id, u32(dek_generation))` |
| Root key | Unseal key or KMS | `tuple("root", root_key_id, u32(root_key_version))` |
| Signing key (Ed25519 seed) | Root key | `tuple("sign", domain_id, purpose, signing_key_id, root_key_id, u32(root_key_version))` |

`subject_hmac` is 32 bytes (section 6). `root_key_id` and `signing_key_id` are 16-byte ids. `purpose` is
`"ledger"` or `"checkpoint"` (section 8). Version numbers start at 1.

Shredding a DEK means overwriting its 107 bytes with zeros (or deleting the row). A zeroed wrapped key MUST be
recognised and reported as `shredded`, never passed to the AEAD.

## 6. Blind identifiers

The key store never holds a subject or scope in clear. It holds HMACs under the domain's blind-index key `BIK`:

```
subject_hmac          = HMAC-SHA-256(BIK, PREFIX ‖ "subject" ‖ 0x00 ‖ subject)
scope_hmac            = HMAC-SHA-256(BIK, PREFIX ‖ "scope"   ‖ 0x00 ‖ scope)
pseudo_subject_hmac   = HMAC-SHA-256(BIK, PREFIX ‖ "scope-subject" ‖ 0x00 ‖ scope)
```

A fact created without a subject (compat mode, C4) is filed under `pseudo_subject_hmac` of its scope, so a scope
shred can destroy one key. The distinct label keeps a pseudo-subject from colliding with a real subject string.

`subject` and `scope` are UTF-8 strings, NFC-normalised by the vault before hashing, at most 1024 bytes.

Caller-visible blind indexes (dedup, requirement 3.9) use a separate key `BIX`, so rotating or shredding them does
not touch subject lookup:

```
index_value = HMAC-SHA-256(BIX, PREFIX ‖ "index" ‖ 0x00 ‖ lp(index_name) ‖ value)
```

## 7. Bucket layout

```
v1/<hex(domain_id)>/<hex(object_id)[0..2]>/<hex(object_id)>
```

No extension, timestamp, subject or fact id appears in the key or in object metadata. Writers MUST NOT set
`Content-Type` beyond `application/octet-stream` and MUST NOT set user metadata.

Other prefixes in the same bucket, or in a separate bucket that is never rolled back (preferred):

| Prefix | Contents |
|---|---|
| `ledger/<hex(domain_id)>/<u64 seq, 20 digits zero-padded>.json` | shred ledger entries (section 8) |
| `checkpoints/<log>/<hex(domain_id)>/<20-digit seq>.json` | signed checkpoints of the audit log and ledger |

## 8. Signed logs: shred ledger, audit log, checkpoints

Entries are JSON objects serialised with the JSON Canonicalization Scheme (RFC 8785). To keep JCS simple, v1
entries MUST use only ASCII object keys, strings, booleans, `null`, arrays, objects and integers in
`0 … 2^53 − 1`. Binary values are lowercase hex strings.

Every entry has these fields, plus a type-specific `body`:

| Field | Type | Meaning |
|---|---|---|
| `log` | string | `"ledger"` or `"audit"` |
| `domain_id` | hex string | |
| `seq` | integer | starts at 0, no gaps |
| `prev` | hex string | the previous entry's `entry_hash`; 64 zeros for `seq` 0 |
| `time` | string | RFC 3339 UTC with milliseconds, `2026-11-14T12:00:00.000Z` |
| `type` | string | entry type |
| `body` | object | |

```
entry_hash = SHA-256(PREFIX ‖ "log-entry" ‖ 0x00 ‖ JCS(entry))
```

**Shred ledger.** Every ledger entry is signed:

```
sig = Ed25519(ledger_signing_key, PREFIX ‖ "ledger-sig" ‖ 0x00 ‖ entry_hash)
stored line = JCS({"entry": entry, "sig": hex(sig), "key_id": hex(signing_key_id)})
```

Ledger entry types and bodies (no key material, no plaintext subject or scope):

| `type` | `body` |
|---|---|
| `shred.fact` | `{"fact_ids": [string], "object_ids": [hex], "request_id": string, "reason": string}` |
| `shred.scope` | `{"scope_hmac": hex, "bik_version": int, "fact_ids": [string], "object_ids": [hex], "request_id": string, "reason": string}` |
| `shred.subject` | `{"subject_hmac": hex, "bik_version": int, "subject_key_versions": [int], "request_id": string, "reason": string}` |
| `shred.domain` | `{"request_id": string, "reason": string}` |
| `expire` | same body as `shred.fact`, written by the retention sweeper |

`reason` is a short code from a fixed list (`subject_request`, `retention`, `legal`, `admin`, `migration`), never
free text, because free text is where PII leaks.

A `shred.scope` entry lists every object it destroyed. Replay after a restore MUST shred by `object_ids`, not by
looking up `scope_hmac`: a fact re-bound to the scope after the backup was taken is filed under its old scope in
that backup. `bik_version` names the blind-index key the HMAC was made with, so entries stay matchable after a
BIK rotation.

Fact ids MUST be UUIDs, written in lowercase hyphenated form. This holds for caller-supplied ids on import too:
a free-form id could carry PII into a log that is never deleted.

**Audit log.** Audit entries are hash-chained but not signed one by one. A **checkpoint** is signed instead:

```
checkpoint = {"log": "audit"|"ledger", "domain_id": hex, "seq": int, "head": hex(entry_hash), "time": string,
              "policy_hash": hex, "key_id": hex}
sig        = Ed25519(checkpoint_key, PREFIX ‖ "checkpoint" ‖ 0x00 ‖ SHA-256(JCS(checkpoint)))
```

Checkpoints are written at least every 60 s and every 1000 entries, whichever comes first.

Audit entry types. Every audit body has the same fields; a field that does not apply is `null`.

| `type` | Written |
|---|---|
| `read.grant` | before a value or blob key is released; the read does not proceed until this entry is durable |
| `read.fail` | after a granted read could not be completed (best effort) |
| `create`, `shred`, `rebind` | with the operation |
| `deny` | when policy refuses a request |
| `admin` | for every admin-listener action |
| `inventory` | before a subject's fact list (ids, types, dates, no values) is released by the GDPR routes; the list is not sent until this entry is durable |

```
body = {"principal": string, "caller": string|null, "roles": [string], "purpose": string|null,
        "reason": string|null, "action": string, "fact_id": string|null, "subject_hmac": hex|null,
        "denial": string|null, "request_id": string, "policy_hash": hex}
```

An entry is written before its operation's outcome is known, which is why a failed read is a second entry and
not a field. Audit bodies never contain a value, a key, or a plaintext subject or scope.

## 9. Backups

A backup is a JSON Lines stream, a header line, then one row per line, grouped by table in this order: `seal_config`, `domains`,
`subject_keys`, `facts`, `sign_keys`, `ledger`, `audit`, `issuers`, `policies`, `approvals`, ending with a closing
line holding the SHA-256 of everything before it. The whole stream is then encrypted with `age` to one or
more recipients and written with mode 0600; there is never a plaintext form on disk. Restore verifies the trailer
before inserting, requires an empty key store, resets identity sequences, and then replays the ledger.

Recipients: at least one X25519 recipient is required, because the `age` crate used here can decrypt only with an
X25519 identity. A hybrid post-quantum recipient (`age1tagpq...`) may be added for encryption; decrypting that copy
needs the external `age` tool. That path has not been tested with a real key.

Sign-key purposes: `ledger` and `checkpoint`, per domain, each wrapped under the root key. A checkpoint is
`checkpoints/audit|ledger/<domain hex>/<seq, 20 digits>.json` in the ledger bucket. An `audit-ack` marker is a signed
object that lists the exact (seq, head hash) pairs of the lost range it covers. Blob rows add `kind`, `chunk_size`,
`blob_len`, `ready` and `blob_expires_at` to the fact row.

## 10. Test vectors

`spec/vectors/` holds known-answer vectors. Every implementation MUST reproduce each `expected` byte string from
its inputs and MUST fail on each `must_fail` case.

| File | Covers |
|---|---|
| `derive.json` | HKDF info construction, `ek`, `ck` for every suite |
| `fact.json` | fact objects in every suite, both sides of the first two size class boundaries (0, 254, 255, 256, 1023, 1024 bytes) |
| `blob.json` | blob streams: empty data, exactly one chunk, a chunk boundary, multi-chunk |
| `wrap.json` | every wrap context in section 5 |
| `blind.json` | subject, scope, pseudo-subject and index HMACs, including a non-ASCII subject |
| `log.json` | ledger entries, the hash chain and signatures, a checkpoint |
| `tamper.json` | `must_fail`: flipped header byte, swapped object id, wrong key, wrong wrap context, truncated stream, reordered chunks, missing final chunk, non-canonical fact and blob padding, non-zero blob padding, zeroed wrapped key |

Regenerate with `uv run spec/reference/gen_vectors.py`. The output is deterministic: all "random" inputs in the
vectors are fixed in the generator.

## 11. Rejected alternatives

- **BLAKE3 for the KDF and commitment** (suggested in REQUIREMENTS.md 3.4). Rejected for v1 because the browser
  must derive the same keys, and WebCrypto has HKDF-SHA-256 but no BLAKE3. One KDF everywhere is simpler to review.
- **The fact id in the object header.** Rejected because fact ids can be caller-chosen (import); the random
  `object_id` is used instead.
- **Plaintext length in the blob header.** It would undo the padding; the length is the first 8 encrypted bytes.
- **Per-object random nonces under a long-lived key.** Every unit gets its own derived key instead, which removes
  nonce-collision limits for all three suites.
