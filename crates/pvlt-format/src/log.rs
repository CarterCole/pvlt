//! Section 8: the shred ledger, the audit log and checkpoints.
//!
//! Entries are JSON values here. Typed entry bodies arrive with the ledger in milestone M2; this module is the
//! canonical encoding, the hash chain and the signatures they will sit on.

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::{Error, Id, Key, PREFIX};

/// Largest integer a v1 entry may hold: `2^53 − 1`.
pub const INT_MAX: u64 = (1 << 53) - 1;

/// `prev` for the entry with `seq` 0.
pub const ZERO_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// Which log an entry belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Log {
    /// The shred ledger: every entry is signed.
    Ledger,
    /// The audit log: hash-chained, signed at checkpoints.
    Audit,
}

impl Log {
    fn as_str(self) -> &'static str {
        match self {
            Log::Ledger => "ledger",
            Log::Audit => "audit",
        }
    }
}

fn write_string(out: &mut Vec<u8>, s: &str) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\u{09}' => out.extend_from_slice(b"\\t"),
            '\u{0a}' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\u{0d}' => out.extend_from_slice(b"\\r"),
            c if c < '\u{20}' => {
                out.extend_from_slice(format!("\\u{:04x}", u32::from(c)).as_bytes())
            }
            c => out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes()),
        }
    }
    out.push(b'"');
}

fn write_value(out: &mut Vec<u8>, v: &Value) -> Result<(), Error> {
    match v {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => match n.as_u64() {
            Some(i) if i <= INT_MAX => out.extend_from_slice(i.to_string().as_bytes()),
            _ => return Err(Error::Invalid("number is not an integer in 0..2^53")),
        },
        Value::String(s) => write_string(out, s),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(out, item)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            if !map.keys().all(|k| k.is_ascii()) {
                return Err(Error::Invalid("object key is not ASCII"));
            }
            // RFC 8785 sorts keys by UTF-16 code unit, which for ASCII keys is byte order.
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            out.push(b'{');
            for (i, key) in keys.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(out, key);
                out.push(b':');
                if let Some(item) = map.get(key) {
                    write_value(out, item)?;
                }
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Serialises a value with the JSON Canonicalization Scheme (RFC 8785), for the subset v1 allows: ASCII
/// object keys and integers in `0 … 2^53 − 1`. Anything else is an error.
pub fn jcs(v: &Value) -> Result<Vec<u8>, Error> {
    let mut out = Vec::new();
    write_value(&mut out, v)?;
    Ok(out)
}

/// Builds a log entry with the common fields of section 8.
pub fn entry(
    log: Log,
    domain_id: &Id,
    seq: u64,
    prev: &str,
    time: &str,
    type_: &str,
    body: Value,
) -> Value {
    let mut m = Map::new();
    m.insert("log".into(), log.as_str().into());
    m.insert("domain_id".into(), hex::encode(domain_id).into());
    m.insert("seq".into(), seq.into());
    m.insert("prev".into(), prev.into());
    m.insert("time".into(), time.into());
    m.insert("type".into(), type_.into());
    m.insert("body".into(), body);
    Value::Object(m)
}

fn tagged_hash(label: &[u8], data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PREFIX);
    h.update(label);
    h.update([0]);
    h.update(data);
    h.finalize().into()
}

/// `SHA-256(PREFIX ‖ "log-entry" ‖ 0x00 ‖ JCS(entry))`.
pub fn entry_hash(entry: &Value) -> Result<[u8; 32], Error> {
    Ok(tagged_hash(b"log-entry", &jcs(entry)?))
}

fn signed_message(label: &[u8], digest: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(PREFIX.len() + label.len() + 1 + 32);
    msg.extend_from_slice(PREFIX);
    msg.extend_from_slice(label);
    msg.push(0);
    msg.extend_from_slice(digest);
    msg
}

fn verify(public: &[u8; 32], msg: &[u8], sig_hex: &str) -> Result<(), Error> {
    let key = VerifyingKey::from_bytes(public).map_err(|_| Error::Invalid("ed25519 public key"))?;
    let mut sig = [0u8; 64];
    hex::decode_to_slice(sig_hex, &mut sig)
        .map_err(|_| Error::Malformed("signature is not 64 hex-encoded bytes"))?;
    key.verify_strict(msg, &Signature::from_bytes(&sig))
        .map_err(|_| Error::OpenFailed)
}

/// The Ed25519 public key for a signing seed.
pub fn public_key(seed: &Key) -> [u8; 32] {
    SigningKey::from_bytes(seed).verifying_key().to_bytes()
}

/// Signs a ledger entry: `Ed25519(key, PREFIX ‖ "ledger-sig" ‖ 0x00 ‖ entry_hash)`.
pub fn ledger_sign(seed: &Key, entry: &Value) -> Result<[u8; 64], Error> {
    let msg = signed_message(b"ledger-sig", &entry_hash(entry)?);
    Ok(SigningKey::from_bytes(seed).sign(&msg).to_bytes())
}

/// The stored form of a ledger entry: `JCS({"entry", "sig", "key_id"})`.
pub fn ledger_line(seed: &Key, signing_key_id: &Id, entry: &Value) -> Result<Vec<u8>, Error> {
    let mut m = Map::new();
    m.insert("sig".into(), hex::encode(ledger_sign(seed, entry)?).into());
    m.insert("key_id".into(), hex::encode(signing_key_id).into());
    m.insert("entry".into(), entry.clone());
    jcs(&Value::Object(m))
}

/// Checks that a stored ledger line is canonical and correctly signed, and returns its entry.
pub fn ledger_verify(public: &[u8; 32], line: &[u8]) -> Result<Value, Error> {
    let mut parsed: Value =
        serde_json::from_slice(line).map_err(|_| Error::Malformed("ledger line is not JSON"))?;
    // Re-encoding must give the same bytes. This also rejects duplicate keys, which the parser would merge.
    if jcs(&parsed)? != line {
        return Err(Error::Malformed("ledger line is not canonical"));
    }
    let sig = parsed
        .get("sig")
        .and_then(Value::as_str)
        .ok_or(Error::Malformed("ledger line has no sig"))?
        .to_owned();
    let entry = parsed
        .get_mut("entry")
        .map(Value::take)
        .ok_or(Error::Malformed("ledger line has no entry"))?;
    verify(
        public,
        &signed_message(b"ledger-sig", &entry_hash(&entry)?),
        &sig,
    )?;
    Ok(entry)
}

/// Signs a checkpoint: `Ed25519(key, PREFIX ‖ "checkpoint" ‖ 0x00 ‖ SHA-256(JCS(checkpoint)))`.
pub fn checkpoint_sign(seed: &Key, checkpoint: &Value) -> Result<[u8; 64], Error> {
    let digest: [u8; 32] = Sha256::digest(jcs(checkpoint)?).into();
    Ok(SigningKey::from_bytes(seed)
        .sign(&signed_message(b"checkpoint", &digest))
        .to_bytes())
}

/// Verifies a checkpoint signature given as hex.
pub fn checkpoint_verify(
    public: &[u8; 32],
    checkpoint: &Value,
    sig_hex: &str,
) -> Result<(), Error> {
    let digest: [u8; 32] = Sha256::digest(jcs(checkpoint)?).into();
    verify(public, &signed_message(b"checkpoint", &digest), sig_hex)
}

/// Checks `seq` and `prev` for a run of entries starting at `seq` 0, and returns the head hash.
pub fn verify_chain(entries: &[Value]) -> Result<[u8; 32], Error> {
    let mut prev = ZERO_HASH.to_owned();
    let mut head = [0u8; 32];
    for (i, e) in entries.iter().enumerate() {
        let seq_ok = e.get("seq").and_then(Value::as_u64) == u64::try_from(i).ok();
        let prev_ok = e.get("prev").and_then(Value::as_str) == Some(prev.as_str());
        if !seq_ok || !prev_ok {
            return Err(Error::Malformed("broken hash chain"));
        }
        head = entry_hash(e)?;
        prev = hex::encode(head);
    }
    Ok(head)
}
