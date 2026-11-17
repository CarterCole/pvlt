# /// script
# requires-python = ">=3.11"
# dependencies = ["cryptography>=44", "pynacl>=1.5"]
# ///
"""Generates the known-answer vectors in spec/vectors/ from the reference (FORMAT.md section 10).

    uv run spec/reference/gen_vectors.py           write the vectors
    uv run spec/reference/gen_vectors.py --check   regenerate in memory, compare with the files, exit 1 on a diff

Output is deterministic: every "random" input is derived from a name with SHA-256. All byte strings are
lowercase hex. Before writing, the script opens everything it sealed and confirms every must_fail case fails.
"""

from __future__ import annotations

import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import pvlt_ref as R  # noqa: E402

OUT = Path(__file__).resolve().parent.parent / "vectors"


def fx(name: str, n: int) -> bytes:
    """Fixed pseudo-random bytes for a named input."""
    out, i = b"", 0
    while len(out) < n:
        out += hashlib.sha256(f"pvlt-vector:{name}:{i}".encode()).digest()
        i += 1
    return out[:n]


def hx(d: dict) -> dict:
    return {k: (v.hex() if isinstance(v, (bytes, bytearray)) else v) for k, v in d.items()}


DOMAIN = fx("domain_id", 16)
ROOT_ID = fx("root_key_id", 16)
TIME0 = "2026-11-14T12:00:00.000Z"


def self_test() -> None:
    # RFC 5869 test case 1.
    okm = R.hkdf_sha256(bytes.fromhex("0b" * 22), bytes.fromhex("000102030405060708090a0b0c"),
                        bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42)
    assert okm.hex() == ("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
                         "34007208d5b887185865"), "HKDF self-test failed"
    # Padmé values worked by hand from the definition in section 4.2.
    assert [R.padme(x) for x in (8, 9, 1024, 2048, 2508)] == [8, 10, 1024, 2048, 2560]
    assert [R.fact_class(n) for n in (0, 255, 256, 1023, 1024)] == [256, 256, 1024, 1024, 4096]


def gen_derive() -> list[dict]:
    out = []
    for suite in R.SUITES:
        for label, ctx in (("object", fx("derive-ctx-object", 48)), ("wrap", R.wctx_root(ROOT_ID, 1))):
            key, salt = fx(f"derive-key-{label}", 32), fx(f"derive-salt-{suite}-{label}", 24)
            ek, ck = R.derive(key, suite, salt, label, ctx)
            info = R.PREFIX + label.encode() + b"\x00" + R.u16(suite) + ctx
            out.append({"name": f"{R.SUITE_NAMES[suite]} {label}", "suite": suite, "label": label,
                        **hx({"key": key, "salt": salt, "ctx": ctx}),
                        "expected": hx({"info": info, "ek": ek, "ck": ck,
                                        "nonce_single": R.nonce_single(suite, salt),
                                        "nonce_chunk_0": R.nonce_chunk(suite, salt, 0, False),
                                        "nonce_chunk_7_last": R.nonce_chunk(suite, salt, 7, True)})})
    return out


def gen_fact() -> list[dict]:
    out = []
    for suite in R.SUITES:
        for n in (0, 254, 255, 256, 1023, 1024):
            name = f"{R.SUITE_NAMES[suite]} {n} bytes"
            dek, oid, salt = fx(f"fact-dek-{name}", 32), fx(f"fact-oid-{name}", 16), fx(f"fact-salt-{name}", 24)
            value = fx(f"fact-value-{name}", n)
            obj = R.fact_seal(dek, suite, DOMAIN, oid, 0, salt, value)
            assert R.fact_open(dek, obj) == value
            out.append({"name": name, "suite": suite, "dek_generation": 0,
                        **hx({"dek": dek, "domain_id": DOMAIN, "object_id": oid, "salt": salt, "value": value}),
                        "expected": {"size_class": R.fact_class(n), "object": obj.hex()}})
    # A text value and a later DEK generation, in the default suite.
    value = '{"name":"Zoë Example","city":"Montréal"}'.encode()
    dek, oid, salt = fx("fact-dek-json", 32), fx("fact-oid-json", 16), fx("fact-salt-json", 24)
    obj = R.fact_seal(dek, R.SUITE_XC20P, DOMAIN, oid, 3, salt, value)
    assert R.fact_open(dek, obj) == value
    out.append({"name": "json value, dek_generation 3", "suite": R.SUITE_XC20P, "dek_generation": 3,
                **hx({"dek": dek, "domain_id": DOMAIN, "object_id": oid, "salt": salt, "value": value}),
                "expected": {"size_class": 256, "object": obj.hex()}})
    return out


BLOB_CASES = (("empty", 0), ("exactly one chunk", 1016), ("ends on a chunk boundary", 2040), ("multi-chunk", 2500))


def gen_blob() -> list[dict]:
    out = []
    for suite in R.SUITES:
        for label, n in BLOB_CASES:
            name = f"{R.SUITE_NAMES[suite]} {label}"
            dek, oid, salt = fx(f"blob-dek-{name}", 32), fx(f"blob-oid-{name}", 16), fx(f"blob-salt-{name}", 24)
            data = fx(f"blob-data-{name}", n)
            obj = R.blob_seal(dek, suite, DOMAIN, oid, 0, 1024, salt, data)
            assert R.blob_open(dek, obj) == data
            padded = R.padme(8 + n)
            out.append({"name": name, "suite": suite, "dek_generation": 0, "chunk_size": 1024,
                        **hx({"dek": dek, "domain_id": DOMAIN, "object_id": oid, "salt": salt, "data": data}),
                        "expected": {"padded_len": padded, "chunks": -(-padded // 1024), "object": obj.hex()}})
    return out


def wrap_cases() -> list[tuple[str, bytes]]:
    sh = R.subject_hmac(fx("bik", 32), "user:1234")
    return [
        ("kek", R.wctx_kek(DOMAIN, 1, ROOT_ID, 1)),
        ("bik", R.wctx_bik(DOMAIN, 1, ROOT_ID, 1)),
        ("bix", R.wctx_bix(DOMAIN, 2, ROOT_ID, 1)),
        ("subject", R.wctx_subject(DOMAIN, sh, 1, 1)),
        ("dek", R.wctx_dek(DOMAIN, sh, 1, fx("wrap-oid", 16), 0)),
        ("root", R.wctx_root(ROOT_ID, 1)),
        ("sign ledger", R.wctx_sign(DOMAIN, "ledger", fx("sign-key-id", 16), ROOT_ID, 1)),
        ("sign checkpoint", R.wctx_sign(DOMAIN, "checkpoint", fx("sign-key-id", 16), ROOT_ID, 1)),
    ]


def gen_wrap() -> list[dict]:
    out = []
    for suite in R.SUITES:
        for kind, wctx in wrap_cases():
            name = f"{R.SUITE_NAMES[suite]} {kind}"
            parent, child, salt = fx(f"wrap-parent-{name}", 32), fx(f"wrap-child-{name}", 32), fx(f"wrap-salt-{name}", 24)
            w = R.wrap(parent, suite, salt, wctx, child)
            assert R.unwrap(parent, w, wctx) == child
            out.append({"name": name, "suite": suite,
                        **hx({"parent": parent, "child": child, "salt": salt, "wctx": wctx}),
                        "expected": {"wrapped": w.hex()}})
    return out


def gen_blind() -> list[dict]:
    bik, bix = fx("bik", 32), fx("bix", 32)
    out = []
    for subject in ("user:1234", "Zoë Example"):  # the second is not NFC on input
        out.append({"name": f"subject {subject!r}", "fn": "subject_hmac", "key": bik.hex(), "input": subject,
                    "expected": R.subject_hmac(bik, subject).hex()})
    assert R.subject_hmac(bik, "Zoë Example") == R.subject_hmac(bik, "Zoë Example")
    scope = "kyc-doc:42"
    out.append({"name": "scope", "fn": "scope_hmac", "key": bik.hex(), "input": scope,
                "expected": R.scope_hmac(bik, scope).hex()})
    out.append({"name": "pseudo-subject", "fn": "pseudo_subject_hmac", "key": bik.hex(), "input": scope,
                "expected": R.pseudo_subject_hmac(bik, scope).hex()})
    assert R.subject_hmac(bik, scope) != R.pseudo_subject_hmac(bik, scope) != R.scope_hmac(bik, scope)
    value = b"passport:X1234567"
    out.append({"name": "index", "fn": "index_value", "key": bix.hex(), "index_name": "id-doc",
                "input_hex": value.hex(), "expected": R.index_value(bix, "id-doc", value).hex()})
    return out


def gen_log() -> dict:
    bik = fx("bik", 32)
    seed, key_id = fx("ledger-seed", 32), fx("sign-key-id", 16)
    fact_a, fact_b = "0b8f3c1e-5d2a-4f6b-9c7d-1e2f3a4b5c6d", "7a1d9e44-0c3b-4e8f-a2b1-6f5e4d3c2b1a"
    bodies = [
        ("shred.fact", {"fact_ids": [fact_a], "object_ids": [fx("log-oid-a", 16).hex()],
                        "request_id": "req-0001", "reason": "subject_request"}),
        ("shred.scope", {"scope_hmac": R.scope_hmac(bik, "kyc-doc:42").hex(), "bik_version": 1,
                         "fact_ids": [fact_b], "object_ids": [fx("log-oid-b", 16).hex()],
                         "request_id": "req-0002", "reason": "retention"}),
        ("shred.subject", {"subject_hmac": R.subject_hmac(bik, "user:1234").hex(), "bik_version": 1,
                           "subject_key_versions": [1, 2], "request_id": "req-0003", "reason": "subject_request"}),
        ("shred.domain", {"request_id": "req-0004", "reason": "admin"}),
    ]
    entries, lines, prev = [], [], R.ZERO_HASH
    for seq, (type_, body) in enumerate(bodies):
        e = R.make_entry("ledger", DOMAIN, seq, prev, f"2026-11-14T12:00:0{seq}.000Z", type_, body)
        line = R.ledger_line(seed, key_id, e)
        assert R.ledger_verify(R.ed25519_public(seed), line) == e
        prev = R.entry_hash(e).hex()
        entries.append({"entry": e, "expected": {"jcs": R.jcs(e).decode(), "entry_hash": prev,
                                                 "sig": R.ledger_sign(seed, e).hex(), "line": line.decode()}})
        lines.append(e)
    head = R.verify_chain(lines)

    audit_body = {"principal": "svc:app-backend", "caller": "user:77", "roles": ["verifier"],
                  "purpose": "kyc-review", "reason": "ticket-812", "action": "read", "fact_id": fact_a,
                  "subject_hmac": R.subject_hmac(bik, "user:1234").hex(), "denial": None,
                  "request_id": "req-0005", "policy_hash": fx("policy", 32).hex()}
    audit = R.make_entry("audit", DOMAIN, 0, R.ZERO_HASH, TIME0, "read.grant", audit_body)

    cp_seed = fx("checkpoint-seed", 32)
    cp = R.make_checkpoint("ledger", DOMAIN, len(lines) - 1, head, "2026-11-14T12:01:00.000Z", fx("policy", 32),
                           fx("checkpoint-key-id", 16))
    return {
        "ledger": {"signing_seed": seed.hex(), "signing_public": R.ed25519_public(seed).hex(),
                   "key_id": key_id.hex(), "entries": entries, "expected_head": head.hex()},
        "audit": {"entry": audit, "expected": {"jcs": R.jcs(audit).decode(), "entry_hash": R.entry_hash(audit).hex()}},
        "checkpoint": {"signing_seed": cp_seed.hex(), "signing_public": R.ed25519_public(cp_seed).hex(),
                       "checkpoint": cp, "expected": {"jcs": R.jcs(cp).decode(),
                                                      "sig": R.checkpoint_sign(cp_seed, cp).hex()}},
    }


def gen_tamper() -> list[dict]:
    """Every case must fail to open. `op` names the reference function to call with the given inputs."""
    out = []

    def must_fail(fn, *args, shredded=False):
        try:
            fn(*args)
        except R.Shredded:
            assert shredded, "unexpected Shredded"
            return
        except R.FormatError:
            assert not shredded, "expected Shredded"
            return
        raise AssertionError("tamper case opened successfully")

    def flip(b: bytes, i: int) -> bytes:
        return b[:i] + bytes([b[i] ^ 0x01]) + b[i + 1:]

    S = R.SUITE_XC20P
    dek, oid, salt = fx("t-dek", 32), fx("t-oid", 16), fx("t-salt", 24)
    fact = R.fact_seal(dek, S, DOMAIN, oid, 0, salt, b"Ada Example")

    def fact_case(name: str, obj: bytes, key: bytes = dek) -> None:
        must_fail(R.fact_open, key, obj)
        out.append({"name": name, "op": "fact_open", "dek": key.hex(), "object": obj.hex(), "must_fail": True})

    fact_case("fact: flipped header byte (dek_generation)", flip(fact, 43))
    fact_case("fact: flipped salt byte", flip(fact, 50))
    fact_case("fact: flipped commitment byte", flip(fact, 80))
    fact_case("fact: flipped ciphertext byte", flip(fact, R.HEADER_LEN + 5))
    fact_case("fact: flipped tag byte", flip(fact, len(fact) - 1))
    fact_case("fact: swapped object id", fact[:24] + fx("t-other-oid", 16) + fact[40:])
    fact_case("fact: wrong key", fact, fx("t-other-dek", 32))
    fact_case("fact: truncated ciphertext", fact[:-1])
    fact_case("fact: kind changed to blob", fact[:5] + b"\x02" + fact[6:])

    # Valid AEAD over a value padded to the wrong class: authenticates, then must be rejected by unpad.
    prefix = R.header_prefix(R.KIND_FACT, S, DOMAIN, oid, 0, 0)
    ek, ck = R.derive(dek, S, salt, "object", prefix)
    header = prefix + salt + ck
    for name, padded in (
        ("fact: non-canonical padding (10 bytes padded to 1024)", b"0123456789\x80" + b"\x00" * 1013),
        ("fact: padding with no 0x80 marker", b"\x00" * 256),
        ("fact: padding marker is not 0x80", b"0123456789\x81" + b"\x00" * 245),
    ):
        fact_case(name, header + R.aead_seal(S, ek, R.nonce_single(S, salt), padded, header))

    G = R.SUITE_GCM
    bdek, boid, bsalt = fx("t-bdek", 32), fx("t-boid", 16), fx("t-bsalt", 24)
    data = fx("t-bdata", 2500)
    blob = R.blob_seal(bdek, G, DOMAIN, boid, 0, 1024, bsalt, data)
    sealed = 1024 + R.TAG_LEN
    H = R.HEADER_LEN
    chunks = [blob[H + i * sealed:H + (i + 1) * sealed] for i in range(3)]

    def blob_case(name: str, obj: bytes) -> None:
        must_fail(R.blob_open, bdek, obj)
        out.append({"name": name, "op": "blob_open", "dek": bdek.hex(), "object": obj.hex(), "must_fail": True})

    blob_case("blob: missing final chunk", blob[:H] + chunks[0] + chunks[1])
    blob_case("blob: truncated inside the final chunk", blob[:-10])
    blob_case("blob: truncated inside a middle chunk", blob[:H + sealed + 100])
    blob_case("blob: reordered chunks", blob[:H] + chunks[1] + chunks[0] + chunks[2])
    blob_case("blob: duplicated chunk", blob[:H] + chunks[0] + chunks[0] + chunks[1] + chunks[2])
    blob_case("blob: extended with a copy of the final chunk", blob + chunks[2])
    blob_case("blob: header only", blob[:H])
    blob_case("blob: flipped chunk_size byte", flip(blob, 46))
    blob_case("blob: flipped byte in chunk 1", flip(blob, H + sealed + 7))

    good = R.blob_plaintext(data)
    blob_case("blob: non-zero padding byte",
              R.blob_seal(bdek, G, DOMAIN, boid, 0, 1024, bsalt, data, _plaintext=good[:-1] + b"\x01"))
    blob_case("blob: non-canonical padding (extra zero block)",
              R.blob_seal(bdek, G, DOMAIN, boid, 0, 1024, bsalt, data, _plaintext=good + b"\x00" * 64))
    blob_case("blob: declared length longer than the stream",
              R.blob_seal(bdek, G, DOMAIN, boid, 0, 1024, bsalt, data, _plaintext=R.u64(5000) + good[8:]))

    parent, child, wsalt = fx("t-parent", 32), fx("t-child", 32), fx("t-wsalt", 24)
    wctx = R.wctx_dek(DOMAIN, fx("t-subject-hmac", 32), 1, oid, 0)
    w = R.wrap(parent, S, wsalt, wctx, child)

    def wrap_case(name: str, wrapped: bytes, ctx: bytes = wctx, key: bytes = parent, shredded: bool = False) -> None:
        must_fail(R.unwrap, key, wrapped, ctx, shredded=shredded)
        out.append({"name": name, "op": "unwrap", "parent": key.hex(), "wrapped": wrapped.hex(), "wctx": ctx.hex(),
                    "must_fail": True, "error": "shredded" if shredded else "open_failed"})

    wrap_case("wrap: wrong wrap context (another object id)",
              w, R.wctx_dek(DOMAIN, fx("t-subject-hmac", 32), 1, fx("t-other-oid", 16), 0))
    wrap_case("wrap: wrong wrap context (dek_generation 1)", w, R.wctx_dek(DOMAIN, fx("t-subject-hmac", 32), 1, oid, 1))
    wrap_case("wrap: wrong parent key", w, key=fx("t-other-parent", 32))
    wrap_case("wrap: flipped commitment byte", flip(w, 30))
    wrap_case("wrap: flipped ciphertext byte", flip(w, 70))
    wrap_case("wrap: suite changed", w[:1] + R.u16(R.SUITE_GCM) + w[3:])
    wrap_case("wrap: zeroed wrapped key reports shredded", bytes(R.WRAPPED_LEN), shredded=True)
    return out


def build() -> dict[str, str]:
    self_test()
    files = {
        "derive.json": ("HKDF info, ek, ck and nonces for every suite (FORMAT.md section 3)", gen_derive()),
        "fact.json": ("Fact objects (section 4.1)", gen_fact()),
        "blob.json": ("Blob streams, chunk_size 1024 (section 4.2)", gen_blob()),
        "wrap.json": ("Wrapped keys for every wrap context (section 5)", gen_wrap()),
        "blind.json": ("Blind identifiers (section 6)", gen_blind()),
        "log.json": ("Ledger entries, hash chain, signatures, an audit entry, a checkpoint (section 8)", gen_log()),
        "tamper.json": ("Inputs that MUST fail to open", gen_tamper()),
    }
    return {name: json.dumps({"format": "pvlt-v1", "description": desc, "vectors": vectors},
                             indent=1, ensure_ascii=False, sort_keys=False) + "\n"
            for name, (desc, vectors) in files.items()}


def main() -> int:
    built = build()
    if "--check" in sys.argv:
        bad = [n for n, text in built.items() if not (OUT / n).exists() or (OUT / n).read_text("utf-8") != text]
        print("vectors match" if not bad else f"vectors differ: {', '.join(bad)}")
        return 1 if bad else 0
    OUT.mkdir(parents=True, exist_ok=True)
    for name, text in built.items():
        (OUT / name).write_text(text, "utf-8")
        print(f"{name:14} {len(json.loads(text)['vectors']):3} vectors  {len(text):7} bytes")
    return 0


if __name__ == "__main__":
    sys.exit(main())
