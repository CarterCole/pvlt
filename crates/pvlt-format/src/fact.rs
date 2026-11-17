//! Section 4.1: fact objects. One padded value sealed with one AEAD call.

use zeroize::Zeroizing;

use crate::header::{Header, Kind};
use crate::suite::{self, Suite};
use crate::{Error, Id, Key, Salt, TAG_LEN};

/// The size classes: `256 · 4^k` for `k` in `0..8`, from 256 B to 4 MiB.
pub const CLASSES: [usize; 8] = [
    256, 1024, 4096, 16_384, 65_536, 262_144, 1_048_576, 4_194_304,
];

/// The longest value a fact can hold. Deployments set a lower limit.
pub const MAX_VALUE_LEN: usize = 4_194_304 - 1;

/// The size class for a value: the smallest class that fits the value and its one marker byte.
pub fn size_class(value_len: usize) -> Option<usize> {
    CLASSES.iter().copied().find(|c| *c > value_len)
}

fn pad(value: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let class = size_class(value.len()).ok_or(Error::Invalid("value too long for a fact"))?;
    let mut out = Zeroizing::new(Vec::with_capacity(class));
    out.extend_from_slice(value);
    out.push(0x80);
    out.resize(class, 0);
    Ok(out)
}

/// Strips the padding in place. Non-canonical padding is an error, not a value.
fn unpad(mut padded: Zeroizing<Vec<u8>>) -> Result<Zeroizing<Vec<u8>>, Error> {
    let marker = padded
        .iter()
        .rposition(|b| *b != 0)
        .ok_or(Error::OpenFailed)?;
    if padded.get(marker) != Some(&0x80) || size_class(marker) != Some(padded.len()) {
        return Err(Error::OpenFailed);
    }
    padded.truncate(marker);
    Ok(padded)
}

/// Seals a value into a fact object: `header ‖ AEAD-Seal(pad(value))`.
///
/// `salt` MUST be 24 fresh random bytes; it must never repeat for the same `dek`.
pub fn seal(
    dek: &Key,
    suite: Suite,
    domain_id: &Id,
    object_id: &Id,
    dek_generation: u32,
    salt: &Salt,
    value: &[u8],
) -> Result<Vec<u8>, Error> {
    let padded = pad(value)?;
    let (header, ek) = Header::seal(
        dek,
        Kind::Fact,
        suite,
        domain_id,
        object_id,
        dek_generation,
        0,
        salt,
    )?;
    let mut object = header.to_bytes();
    let sealed = suite::seal(
        suite,
        &ek,
        &suite::nonce_single(suite, salt),
        &padded,
        &object,
    )?;
    object.extend_from_slice(&sealed);
    Ok(object)
}

/// Opens a fact object and returns the value.
pub fn open(dek: &Key, object: &[u8]) -> Result<Zeroizing<Vec<u8>>, Error> {
    let (header, body) = Header::split(object)?;
    if header.kind == Kind::Fact && header.chunk_size != 0 {
        return Err(Error::Malformed("fact with a chunk size"));
    }
    let padded_len = body
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(Error::Malformed("fact too short"))?;
    if !CLASSES.contains(&padded_len) {
        return Err(Error::Malformed("fact length is not a size class"));
    }
    let ek = header.open(dek, Kind::Fact)?;
    let aad = header.to_bytes();
    let padded = suite::open(
        header.suite,
        &ek,
        &suite::nonce_single(header.suite, &header.salt),
        body,
        &aad,
    )?;
    unpad(padded)
}
