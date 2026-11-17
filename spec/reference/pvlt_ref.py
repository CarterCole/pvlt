"""Reference implementation of the pvlt v1 format (docs/FORMAT.md).

Written for clarity, not speed. Section numbers in comments refer to FORMAT.md. Where this file and the prose
disagree, one of them has a bug.

Dependencies: `cryptography` (AES-GCM, AES-GCM-SIV, Ed25519) and `pynacl` (XChaCha20-Poly1305). HKDF, HMAC and
SHA-256 come from the standard library so the derivation is visible here.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import struct
import unicodedata

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, AESGCMSIV
from nacl import bindings as sodium
from nacl.exceptions import CryptoError

# --- Section 1: notation -------------------------------------------------------------------------------------

PREFIX = b"PVLT-v1\x00"
KEY_LEN = 32
SALT_LEN = 24
TAG_LEN = 16
ID_LEN = 16


class FormatError(Exception):
    """The input is malformed, was tampered with, or was opened with the wrong key or context.

    Section 3: a commitment mismatch and an AEAD tag failure must look the same to the caller, so both raise
    this with the same message.
    """


class Shredded(Exception):
    """The wrapped key is all zeros (section 5): the key was destroyed on purpose."""


OPEN_FAILED = "open failed"


def u8(x: int) -> bytes:
    return struct.pack(">B", x)


def u16(x: int) -> bytes:
    return struct.pack(">H", x)


def u32(x: int) -> bytes:
    return struct.pack(">I", x)


def u64(x: int) -> bytes:
    return struct.pack(">Q", x)


def lp(x: bytes | str) -> bytes:
    if isinstance(x, str):
        x = x.encode("utf-8")
    if len(x) > 0xFFFF:
        raise ValueError("lp: value longer than 65535 bytes")
    return u16(len(x)) + x


def tuple_(*parts: bytes | str) -> bytes:
    return b"".join(lp(p) for p in parts)


# --- Section 2: suites ---------------------------------------------------------------------------------------

SUITE_XC20P = 0x0001
SUITE_GCMSIV = 0x0002
SUITE_GCM = 0x0003
SUITES = (SUITE_XC20P, SUITE_GCMSIV, SUITE_GCM)
SUITE_NAMES = {
    SUITE_XC20P: "PVLT-XC20P-HS256",
    SUITE_GCMSIV: "PVLT-A256GCMSIV-HS256",
    SUITE_GCM: "PVLT-A256GCM-HS256",
}


def _check_suite(suite: int) -> None:
    if suite not in SUITES:
        raise FormatError("unknown suite")


def aead_seal(suite: int, ek: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> bytes:
    _check_suite(suite)
    if suite == SUITE_XC20P:
        return sodium.crypto_aead_xchacha20poly1305_ietf_encrypt(plaintext, aad, nonce, ek)
    if suite == SUITE_GCMSIV:
        return AESGCMSIV(ek).encrypt(nonce, plaintext, aad)
    return AESGCM(ek).encrypt(nonce, plaintext, aad)


def aead_open(suite: int, ek: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    _check_suite(suite)
    try:
        if suite == SUITE_XC20P:
            return sodium.crypto_aead_xchacha20poly1305_ietf_decrypt(ciphertext, aad, nonce, ek)
        if suite == SUITE_GCMSIV:
            return AESGCMSIV(ek).decrypt(nonce, ciphertext, aad)
        return AESGCM(ek).decrypt(nonce, ciphertext, aad)
    except (CryptoError, InvalidTag, ValueError):
        raise FormatError(OPEN_FAILED) from None


# --- Section 3: derivation, commitment, nonces ---------------------------------------------------------------


def hkdf_sha256(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    """RFC 5869."""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm, block, counter = b"", b"", 1
    while len(okm) < length:
        block = hmac.new(prk, block + info + u8(counter), hashlib.sha256).digest()
        okm += block
        counter += 1
    return okm[:length]


def derive(key: bytes, suite: int, salt: bytes, label: str, ctx: bytes) -> tuple[bytes, bytes]:
    """Returns (ek, ck): the one-unit AEAD key and the key commitment."""
    _check_suite(suite)
    if len(key) != KEY_LEN or len(salt) != SALT_LEN:
        raise ValueError("derive: bad key or salt length")
    info = PREFIX + label.encode() + b"\x00" + u16(suite) + ctx
    okm = hkdf_sha256(key, salt, info, 64)
    return okm[:32], okm[32:]


def nonce_single(suite: int, salt: bytes) -> bytes:
    return salt if suite == SUITE_XC20P else salt[:12]


def nonce_chunk(suite: int, salt: bytes, i: int, last: bool) -> bytes:
    head = salt[:19] if suite == SUITE_XC20P else salt[:7]
    return head + u32(i) + u8(1 if last else 0)


# --- Section 4: object header --------------------------------------------------------------------------------

MAGIC = b"PVLT"
VERSION = 0x01
KIND_FACT = 0x01
KIND_BLOB = 0x02
HEADER_LEN = 104
HEADER_CTX_LEN = 48  # magic through chunk_size


def header_prefix(kind: int, suite: int, domain_id: bytes, object_id: bytes, dek_generation: int,
                  chunk_size: int) -> bytes:
    if len(domain_id) != ID_LEN or len(object_id) != ID_LEN:
        raise ValueError("ids are 16 bytes")
    out = MAGIC + u8(VERSION) + u8(kind) + u16(suite) + domain_id + object_id + u32(dek_generation) + u32(chunk_size)
    assert len(out) == HEADER_CTX_LEN
    return out


def parse_header(obj: bytes) -> dict:
    if len(obj) < HEADER_LEN:
        raise FormatError("short object")
    h = obj[:HEADER_LEN]
    if h[0:4] != MAGIC or h[4] != VERSION:
        raise FormatError("bad magic or version")
    kind = h[5]
    if kind not in (KIND_FACT, KIND_BLOB):
        raise FormatError("bad kind")
    suite = struct.unpack(">H", h[6:8])[0]
    _check_suite(suite)
    return {
        "raw": h,
        "kind": kind,
        "suite": suite,
        "domain_id": h[8:24],
        "object_id": h[24:40],
        "dek_generation": struct.unpack(">I", h[40:44])[0],
        "chunk_size": struct.unpack(">I", h[44:48])[0],
        "salt": h[48:72],
        "commitment": h[72:104],
    }


def _open_header(dek: bytes, obj: bytes, kind: int) -> tuple[dict, bytes]:
    """Parses the header and checks the commitment before any AEAD call. Returns (header, ek)."""
    h = parse_header(obj)
    if h["kind"] != kind:
        raise FormatError("wrong kind")
    ek, ck = derive(dek, h["suite"], h["salt"], "object", h["raw"][:HEADER_CTX_LEN])
    if not hmac.compare_digest(ck, h["commitment"]):
        raise FormatError(OPEN_FAILED)
    return h, ek


# --- Section 4.1: facts --------------------------------------------------------------------------------------

FACT_CLASSES = tuple(256 * 4**k for k in range(8))  # 256 B ... 4 MiB
FACT_MAX = FACT_CLASSES[-1] - 1


def fact_class(value_len: int) -> int:
    for c in FACT_CLASSES:
        if c >= value_len + 1:
            return c
    raise ValueError("value too long for a fact")


def pad(value: bytes) -> bytes:
    c = fact_class(len(value))
    return value + b"\x80" + b"\x00" * (c - len(value) - 1)


def unpad(padded: bytes) -> bytes:
    stripped = padded.rstrip(b"\x00")
    if not stripped or stripped[-1] != 0x80:
        raise FormatError(OPEN_FAILED)
    value = stripped[:-1]
    if len(value) > FACT_MAX or fact_class(len(value)) != len(padded):
        raise FormatError(OPEN_FAILED)  # non-canonical padding
    return value


def fact_seal(dek: bytes, suite: int, domain_id: bytes, object_id: bytes, dek_generation: int, salt: bytes,
              value: bytes) -> bytes:
    prefix = header_prefix(KIND_FACT, suite, domain_id, object_id, dek_generation, 0)
    ek, ck = derive(dek, suite, salt, "object", prefix)
    header = prefix + salt + ck
    return header + aead_seal(suite, ek, nonce_single(suite, salt), pad(value), header)


def fact_open(dek: bytes, obj: bytes) -> bytes:
    h, ek = _open_header(dek, obj, KIND_FACT)
    if h["chunk_size"] != 0:
        raise FormatError("fact with a chunk size")
    body = obj[HEADER_LEN:]
    if len(body) - TAG_LEN not in FACT_CLASSES:
        raise FormatError("bad fact length")
    padded = aead_open(h["suite"], ek, nonce_single(h["suite"], h["salt"]), body, h["raw"])
    return unpad(padded)


# --- Section 4.2: blobs --------------------------------------------------------------------------------------

CHUNK_MIN = 1024
CHUNK_MAX = 16 * 1024 * 1024
CHUNK_DEFAULT = 65536


def padme(length: int) -> int:
    if length < 2:
        raise ValueError("padme needs L >= 2")
    e = length.bit_length() - 1
    s = e.bit_length()  # floor(log2 e) + 1
    mask = (1 << (e - s)) - 1
    return (length + mask) & ~mask


def _check_chunk_size(chunk_size: int) -> None:
    if chunk_size % 1024 or not CHUNK_MIN <= chunk_size <= CHUNK_MAX:
        raise FormatError("bad chunk size")


def blob_plaintext(data: bytes) -> bytes:
    total = padme(8 + len(data))
    return u64(len(data)) + data + b"\x00" * (total - 8 - len(data))


def blob_seal(dek: bytes, suite: int, domain_id: bytes, object_id: bytes, dek_generation: int, chunk_size: int,
              salt: bytes, data: bytes, *, _plaintext: bytes | None = None) -> bytes:
    """`_plaintext` replaces the padded stream; only the tamper vectors use it."""
    _check_chunk_size(chunk_size)
    prefix = header_prefix(KIND_BLOB, suite, domain_id, object_id, dek_generation, chunk_size)
    ek, ck = derive(dek, suite, salt, "object", prefix)
    header = prefix + salt + ck
    p = blob_plaintext(data) if _plaintext is None else _plaintext
    chunks = [p[i:i + chunk_size] for i in range(0, len(p), chunk_size)]
    out = [header]
    for i, chunk in enumerate(chunks):
        last = i == len(chunks) - 1
        out.append(aead_seal(suite, ek, nonce_chunk(suite, salt, i, last), chunk, header))
    return b"".join(out)


def blob_open(dek: bytes, obj: bytes) -> bytes:
    h, ek = _open_header(dek, obj, KIND_BLOB)
    cs = h["chunk_size"]
    _check_chunk_size(cs)
    body = obj[HEADER_LEN:]
    sealed = cs + TAG_LEN
    if not body:
        raise FormatError(OPEN_FAILED)  # no final chunk
    n = -(-len(body) // sealed)
    if len(body) - (n - 1) * sealed <= TAG_LEN:
        raise FormatError(OPEN_FAILED)  # final chunk would hold no plaintext
    parts = []
    for i in range(n):
        chunk = body[i * sealed:(i + 1) * sealed]
        parts.append(aead_open(h["suite"], ek, nonce_chunk(h["suite"], h["salt"], i, i == n - 1), chunk, h["raw"]))
    p = b"".join(parts)
    if len(p) < 8:
        raise FormatError(OPEN_FAILED)
    (length,) = struct.unpack(">Q", p[:8])
    if 8 + length > len(p) or padme(8 + length) != len(p) or any(p[8 + length:]):
        raise FormatError(OPEN_FAILED)
    return p[8:8 + length]


# --- Section 5: wrapped keys ---------------------------------------------------------------------------------

WRAP_VERSION = 0x01
WRAP_HEAD_LEN = 59
WRAPPED_LEN = 107


def wrap(parent: bytes, suite: int, salt: bytes, wctx: bytes, child: bytes) -> bytes:
    if len(child) != KEY_LEN:
        raise ValueError("child key must be 32 bytes")
    ek, ck = derive(parent, suite, salt, "wrap", wctx)
    head = u8(WRAP_VERSION) + u16(suite) + salt + ck
    assert len(head) == WRAP_HEAD_LEN
    out = head + aead_seal(suite, ek, nonce_single(suite, salt), child, head + wctx)
    assert len(out) == WRAPPED_LEN
    return out


def unwrap(parent: bytes, wrapped: bytes, wctx: bytes) -> bytes:
    if len(wrapped) != WRAPPED_LEN:
        raise FormatError("bad wrapped key length")
    if not any(wrapped):
        raise Shredded()
    if wrapped[0] != WRAP_VERSION:
        raise FormatError("bad wrap version")
    suite = struct.unpack(">H", wrapped[1:3])[0]
    _check_suite(suite)
    salt, commitment = wrapped[3:27], wrapped[27:59]
    ek, ck = derive(parent, suite, salt, "wrap", wctx)
    if not hmac.compare_digest(ck, commitment):
        raise FormatError(OPEN_FAILED)
    return aead_open(suite, ek, nonce_single(suite, salt), wrapped[59:], wrapped[:59] + wctx)


def wctx_kek(domain_id: bytes, kek_version: int, root_key_id: bytes, root_key_version: int) -> bytes:
    return tuple_("kek", domain_id, u32(kek_version), root_key_id, u32(root_key_version))


def wctx_bik(domain_id: bytes, bik_version: int, root_key_id: bytes, root_key_version: int) -> bytes:
    return tuple_("bik", domain_id, u32(bik_version), root_key_id, u32(root_key_version))


def wctx_bix(domain_id: bytes, bix_version: int, root_key_id: bytes, root_key_version: int) -> bytes:
    return tuple_("bix", domain_id, u32(bix_version), root_key_id, u32(root_key_version))


def wctx_subject(domain_id: bytes, subject_hmac: bytes, subject_key_version: int, kek_version: int) -> bytes:
    return tuple_("subject", domain_id, subject_hmac, u32(subject_key_version), u32(kek_version))


def wctx_dek(domain_id: bytes, subject_hmac: bytes, subject_key_version: int, object_id: bytes,
             dek_generation: int) -> bytes:
    return tuple_("dek", domain_id, subject_hmac, u32(subject_key_version), object_id, u32(dek_generation))


def wctx_root(root_key_id: bytes, root_key_version: int) -> bytes:
    return tuple_("root", root_key_id, u32(root_key_version))


def wctx_sign(domain_id: bytes, purpose: str, signing_key_id: bytes, root_key_id: bytes,
              root_key_version: int) -> bytes:
    if purpose not in ("ledger", "checkpoint"):
        raise ValueError("unknown signing purpose")
    return tuple_("sign", domain_id, purpose, signing_key_id, root_key_id, u32(root_key_version))


# --- Section 6: blind identifiers ----------------------------------------------------------------------------

BLIND_MAX = 1024


def _norm(s: str) -> bytes:
    b = unicodedata.normalize("NFC", s).encode("utf-8")
    if len(b) > BLIND_MAX:
        raise ValueError("subject or scope longer than 1024 bytes")
    return b


def _blind(key: bytes, label: str, data: bytes) -> bytes:
    return hmac.new(key, PREFIX + label.encode() + b"\x00" + data, hashlib.sha256).digest()


def subject_hmac(bik: bytes, subject: str) -> bytes:
    return _blind(bik, "subject", _norm(subject))


def scope_hmac(bik: bytes, scope: str) -> bytes:
    return _blind(bik, "scope", _norm(scope))


def pseudo_subject_hmac(bik: bytes, scope: str) -> bytes:
    return _blind(bik, "scope-subject", _norm(scope))


def index_value(bix: bytes, index_name: str, value: bytes) -> bytes:
    return _blind(bix, "index", lp(index_name) + value)


# --- Section 8: signed logs ----------------------------------------------------------------------------------

JCS_INT_MAX = 2**53 - 1


def _jcs_check(v: object) -> None:
    if v is None or isinstance(v, bool):
        return
    if isinstance(v, int):
        if not 0 <= v <= JCS_INT_MAX:
            raise ValueError("integer out of range for v1 entries")
        return
    if isinstance(v, str):
        v.encode("utf-8")  # rejects lone surrogates
        return
    if isinstance(v, list):
        for x in v:
            _jcs_check(x)
        return
    if isinstance(v, dict):
        for k, x in v.items():
            if not isinstance(k, str) or not k.isascii():
                raise ValueError("object keys must be ASCII strings")
            _jcs_check(x)
        return
    raise ValueError(f"type not allowed in v1 entries: {type(v).__name__}")


def jcs(v: object) -> bytes:
    """RFC 8785 for the subset v1 allows (no floats, ASCII keys), where it reduces to sorted keys, no
    whitespace, and JSON.stringify string escaping, which `json.dumps(ensure_ascii=False)` matches."""
    _jcs_check(v)
    return json.dumps(v, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


ZERO_HASH = "00" * 32


def make_entry(log: str, domain_id: bytes, seq: int, prev: str, time: str, type_: str, body: dict) -> dict:
    if log not in ("ledger", "audit"):
        raise ValueError("unknown log")
    if seq == 0 and prev != ZERO_HASH:
        raise ValueError("seq 0 must chain from zeros")
    return {"log": log, "domain_id": domain_id.hex(), "seq": seq, "prev": prev, "time": time, "type": type_,
            "body": body}


def entry_hash(entry: dict) -> bytes:
    return hashlib.sha256(PREFIX + b"log-entry\x00" + jcs(entry)).digest()


def ed25519_public(seed: bytes) -> bytes:
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    return Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def ledger_sign(seed: bytes, entry: dict) -> bytes:
    return Ed25519PrivateKey.from_private_bytes(seed).sign(PREFIX + b"ledger-sig\x00" + entry_hash(entry))


def ledger_line(seed: bytes, signing_key_id: bytes, entry: dict) -> bytes:
    return jcs({"entry": entry, "sig": ledger_sign(seed, entry).hex(), "key_id": signing_key_id.hex()})


def ledger_verify(public: bytes, line: bytes) -> dict:
    obj = json.loads(line)
    if jcs(obj) != line:
        raise FormatError("ledger line is not canonical")
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(
            bytes.fromhex(obj["sig"]), PREFIX + b"ledger-sig\x00" + entry_hash(obj["entry"]))
    except Exception:
        raise FormatError(OPEN_FAILED) from None
    return obj["entry"]


def make_checkpoint(log: str, domain_id: bytes, seq: int, head: bytes, time: str, policy_hash: bytes,
                    key_id: bytes) -> dict:
    return {"log": log, "domain_id": domain_id.hex(), "seq": seq, "head": head.hex(), "time": time,
            "policy_hash": policy_hash.hex(), "key_id": key_id.hex()}


def checkpoint_sign(seed: bytes, checkpoint: dict) -> bytes:
    digest = hashlib.sha256(jcs(checkpoint)).digest()
    return Ed25519PrivateKey.from_private_bytes(seed).sign(PREFIX + b"checkpoint\x00" + digest)


def verify_chain(entries: list[dict]) -> bytes:
    """Checks seq and prev links from seq 0 and returns the head hash."""
    prev = ZERO_HASH
    for i, e in enumerate(entries):
        if e["seq"] != i or e["prev"] != prev:
            raise FormatError("broken chain")
        prev = entry_hash(e).hex()
    return bytes.fromhex(prev)
