//! Key-store backups: framing, integrity, and `age` encryption.
//!
//! A backup is the key store exported as JSON lines (see `crate::pg::PgStore::export_all`), closed with a line
//! that holds the SHA-256 of everything before it, and encrypted with `age`. The file on disk is never
//! plaintext: it holds wrapped keys and the access history, which are not secret enough to be keys but are not
//! something to leave in a bucket in the clear (REQUIREMENTS 3.6.4, threat T3).
//!
//! **Recipients.** An X25519 recipient (`age1...`) is what `pvlt restore` can decrypt in-process. A hybrid
//! post-quantum recipient (`age1tagpq...`) is accepted too, and is decrypted with the external `age` tool: the
//! `age` crate (0.12.1, beta) can encrypt to it but has no identity type to decrypt with. Encrypt to both, keep
//! the post-quantum identity offline, and use it only if the classical one is lost.

use std::fmt;
use std::io::{Read, Write};
use std::str::FromStr;

use crate::pg::{BACKUP_TABLES, TableDump};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

/// The format name written to the first line.
pub const FORMAT: &str = "pvlt-backup-v1";

/// Why a backup could not be written or read. Never holds key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BackupError(pub String);

impl fmt::Display for BackupError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for BackupError {}

fn err(m: impl Into<String>) -> BackupError {
    BackupError(m.into())
}

/// Frames a dump as JSON lines: a header, one line per row, and a closing hash.
pub fn encode(created: &str, dump: &[TableDump]) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    let counts: serde_json::Map<String, Value> = dump
        .iter()
        .map(|t| (t.table.clone(), Value::from(t.rows.len())))
        .collect();
    let mut out = Zeroizing::new(Vec::new());
    let mut line = |v: &Value| -> Result<(), BackupError> {
        serde_json::to_writer(&mut *out, v).map_err(|e| err(e.to_string()))?;
        out.push(b'\n');
        Ok(())
    };
    line(&json!({"format": FORMAT, "created": created, "tables": counts}))?;
    for t in dump {
        for row in &t.rows {
            line(&json!({"t": t.table, "r": row}))?;
        }
    }
    let digest = Sha256::digest(out.as_slice());
    out.extend_from_slice(json!({"end": hex::encode(digest)}).to_string().as_bytes());
    out.push(b'\n');
    Ok(out)
}

/// Reads a framed backup. The closing hash, the header's counts and the table names are all checked, so a
/// truncated or edited file is refused and never half-loaded.
pub fn decode(bytes: &[u8]) -> Result<Vec<TableDump>, BackupError> {
    let end_at = bytes
        .strip_suffix(b"\n")
        .and_then(|b| b.iter().rposition(|c| *c == b'\n'))
        .map(|i| i + 1)
        .ok_or_else(|| err("the backup is not complete"))?;
    let (body, trailer) = bytes.split_at(end_at);
    let trailer: Value =
        serde_json::from_slice(trailer).map_err(|_| err("the backup has no closing hash"))?;
    let want = trailer
        .get("end")
        .and_then(Value::as_str)
        .ok_or_else(|| err("the backup has no closing hash"))?;
    if hex::encode(Sha256::digest(body)) != want {
        return Err(err(
            "the backup's hash does not match: it is damaged or was edited",
        ));
    }
    let mut lines = body.split(|c| *c == b'\n').filter(|l| !l.is_empty());
    let header: Value = serde_json::from_slice(lines.next().ok_or_else(|| err("empty backup"))?)
        .map_err(|_| err("the backup header is not JSON"))?;
    if header.get("format").and_then(Value::as_str) != Some(FORMAT) {
        return Err(err("this is not a pvlt-backup-v1 file"));
    }
    let mut dump: Vec<TableDump> = BACKUP_TABLES
        .iter()
        .map(|t| TableDump {
            table: (*t).to_owned(),
            rows: Vec::new(),
        })
        .collect();
    for l in lines {
        let v: Value = serde_json::from_slice(l).map_err(|_| err("a backup row is not JSON"))?;
        let name = v
            .get("t")
            .and_then(Value::as_str)
            .ok_or_else(|| err("a backup row has no table"))?;
        let row = v
            .get("r")
            .cloned()
            .ok_or_else(|| err("a backup row has no data"))?;
        dump.iter_mut()
            .find(|t| t.table == name)
            .ok_or_else(|| err("a backup row is for an unknown table"))?
            .rows
            .push(row);
    }
    for t in &dump {
        let declared = header
            .get("tables")
            .and_then(|m| m.get(&t.table))
            .and_then(Value::as_u64);
        if declared != u64::try_from(t.rows.len()).ok() {
            return Err(err("the backup's row counts do not match its header"));
        }
    }
    Ok(dump)
}

/// A parsed recipient.
enum Recipient {
    X25519(age::x25519::Recipient),
    HybridPq(Box<age::tagpq::Recipient>),
}

fn parse_recipient(text: &str) -> Result<Recipient, BackupError> {
    let text = text.trim();
    if text.starts_with("age1tagpq") {
        age::tagpq::Recipient::from_str(text)
            .map(|r| Recipient::HybridPq(Box::new(r)))
            .map_err(|_| err("not a valid age1tagpq recipient"))
    } else {
        age::x25519::Recipient::from_str(text)
            .map(Recipient::X25519)
            .map_err(|_| err("not a valid age recipient (expected age1... or age1tagpq...)"))
    }
}

/// Encrypts to every recipient. At least one must be an X25519 recipient, so the backup can be restored
/// without an external tool; the rest may be hybrid post-quantum.
pub fn encrypt(plain: &[u8], recipients: &[String]) -> Result<Vec<u8>, BackupError> {
    let parsed = recipients
        .iter()
        .map(|r| parse_recipient(r))
        .collect::<Result<Vec<_>, _>>()?;
    if !parsed.iter().any(|r| matches!(r, Recipient::X25519(_))) {
        return Err(err(
            "give at least one X25519 recipient (age1...) so `pvlt restore` can read the backup",
        ));
    }
    let dyns: Vec<&dyn age::Recipient> = parsed
        .iter()
        .map(|r| match r {
            Recipient::X25519(r) => r as &dyn age::Recipient,
            Recipient::HybridPq(r) => r.as_ref() as &dyn age::Recipient,
        })
        .collect();
    let encryptor =
        age::Encryptor::with_recipients(dyns.into_iter()).map_err(|_| err("no recipients"))?;
    let mut out = Vec::with_capacity(plain.len() + 512);
    let mut w = encryptor
        .wrap_output(&mut out)
        .map_err(|e| err(e.to_string()))?;
    w.write_all(plain).map_err(|e| err(e.to_string()))?;
    w.finish().map_err(|e| err(e.to_string()))?;
    Ok(out)
}

/// Decrypts with an X25519 identity (`AGE-SECRET-KEY-1...`). The identity text is wiped when dropped.
pub fn decrypt(cipher: &[u8], identity: &str) -> Result<Zeroizing<Vec<u8>>, BackupError> {
    let identity = age::x25519::Identity::from_str(identity.trim())
        .map_err(|_| err("the identity file does not hold an age secret key"))?;
    let decryptor = age::Decryptor::new_buffered(cipher).map_err(|_| err("not an age file"))?;
    let mut reader = decryptor
        .decrypt(std::iter::once(&identity as &dyn age::Identity))
        .map_err(|_| err("this identity cannot decrypt the backup"))?;
    let mut out = Zeroizing::new(Vec::new());
    reader
        .read_to_end(&mut out)
        .map_err(|_| err("the backup is damaged"))?;
    Ok(out)
}

/// A new X25519 identity and its recipient: `(secret, recipient)`.
pub fn generate_identity() -> (Zeroizing<String>, String) {
    use age::secrecy::ExposeSecret;
    let id = age::x25519::Identity::generate();
    (
        Zeroizing::new(id.to_string().expose_secret().to_owned()),
        id.to_public().to_string(),
    )
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;

    fn sample() -> Vec<TableDump> {
        BACKUP_TABLES
            .iter()
            .enumerate()
            .map(|(i, t)| TableDump {
                table: (*t).to_owned(),
                rows: (0..i).map(|n| json!({"n": n, "b": "\\x00ff"})).collect(),
            })
            .collect()
    }

    #[test]
    fn a_dump_round_trips_through_the_framing() {
        let framed = encode("2026-11-16T00:00:00.000Z", &sample()).unwrap();
        assert_eq!(decode(&framed).unwrap(), sample());
    }

    #[test]
    fn a_damaged_truncated_or_edited_backup_is_refused() {
        let framed = encode("2026-11-16T00:00:00.000Z", &sample())
            .unwrap()
            .to_vec();
        for at in [0, 5, framed.len() / 2, framed.len() - 20] {
            let mut bad = framed.clone();
            bad[at] ^= 1;
            assert!(decode(&bad).is_err(), "a flip at {at} was accepted");
        }
        for cut in [1, 10, framed.len() / 2, framed.len() - 1] {
            assert!(decode(&framed[..framed.len() - cut]).is_err(), "cut {cut}");
        }
        // A row dropped with the hash recomputed still fails the header's counts.
        let text = String::from_utf8(framed.clone()).unwrap();
        let mut lines: Vec<&str> = text.lines().collect();
        lines.remove(2);
        lines.pop();
        let body = format!("{}\n", lines.join("\n"));
        let digest = hex::encode(Sha256::digest(body.as_bytes()));
        let forged = format!("{body}{}\n", json!({"end": digest}));
        assert!(decode(forged.as_bytes()).is_err());
        assert!(decode(b"").is_err());
        assert!(decode(b"{}\n").is_err());
    }

    #[test]
    fn a_backup_is_encrypted_and_only_the_right_identity_reads_it() {
        let (secret, recipient) = generate_identity();
        let (other_secret, _) = generate_identity();
        let plain = encode("t", &sample()).unwrap();
        let cipher = encrypt(&plain, std::slice::from_ref(&recipient)).unwrap();
        assert!(
            !cipher.windows(8).any(|w| w == b"pvlt-bac"),
            "the format name is visible in the ciphertext"
        );
        assert_eq!(
            decrypt(&cipher, &secret).unwrap().as_slice(),
            plain.as_slice()
        );
        assert!(decrypt(&cipher, &other_secret).is_err());
        let mut damaged = cipher.clone();
        let n = damaged.len();
        damaged[n - 5] ^= 1;
        assert!(decrypt(&damaged, &secret).is_err());
    }

    #[test]
    fn at_least_one_recipient_must_be_one_the_server_can_read() {
        let plain = encode("t", &sample()).unwrap();
        assert!(encrypt(&plain, &[]).is_err());
        assert!(encrypt(&plain, &["not a key".to_owned()]).is_err());
        let (_, recipient) = generate_identity();
        assert!(encrypt(&plain, &[recipient]).is_ok());
    }
}
