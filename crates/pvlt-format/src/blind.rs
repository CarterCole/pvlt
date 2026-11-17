//! Section 6: blind identifiers. The key store holds HMACs of subjects and scopes, never the strings.

use hmac::{Hmac, KeyInit, Mac};
use sha2::Sha256;
use unicode_normalization::UnicodeNormalization;

use crate::bytes::lp;
use crate::{Error, Key, PREFIX};

/// Longest subject or scope, in UTF-8 bytes after NFC normalisation.
pub const MAX_LEN: usize = 1024;

fn blind(key: &Key, label: &str, data: &[u8]) -> Result<[u8; 32], Error> {
    let mut mac = <Hmac<Sha256> as KeyInit>::new_from_slice(key)
        .map_err(|_| Error::Invalid("hmac key length"))?;
    mac.update(PREFIX);
    mac.update(label.as_bytes());
    mac.update(&[0]);
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

fn normalise(s: &str) -> Result<String, Error> {
    let nfc: String = s.nfc().collect();
    if nfc.len() > MAX_LEN {
        return Err(Error::Invalid("subject or scope longer than 1024 bytes"));
    }
    Ok(nfc)
}

/// `HMAC(BIK, PREFIX ‖ "subject" ‖ 0x00 ‖ subject)`.
pub fn subject_hmac(bik: &Key, subject: &str) -> Result<[u8; 32], Error> {
    blind(bik, "subject", normalise(subject)?.as_bytes())
}

/// `HMAC(BIK, PREFIX ‖ "scope" ‖ 0x00 ‖ scope)`.
pub fn scope_hmac(bik: &Key, scope: &str) -> Result<[u8; 32], Error> {
    blind(bik, "scope", normalise(scope)?.as_bytes())
}

/// The subject a fact is filed under when it was created without one, so that a scope shred can destroy one
/// key. The label differs from [`subject_hmac`]'s, so it cannot collide with a real subject string.
pub fn pseudo_subject_hmac(bik: &Key, scope: &str) -> Result<[u8; 32], Error> {
    blind(bik, "scope-subject", normalise(scope)?.as_bytes())
}

/// A caller-visible blind index value under the separate key `BIX`.
pub fn index_value(bix: &Key, index_name: &str, value: &[u8]) -> Result<[u8; 32], Error> {
    let mut data = Vec::with_capacity(2 + index_name.len() + value.len());
    lp(&mut data, index_name.as_bytes())?;
    data.extend_from_slice(value);
    blind(bix, "index", &data)
}
