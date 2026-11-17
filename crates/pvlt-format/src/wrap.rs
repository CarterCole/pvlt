//! Section 5: wrapped keys. Every key below the root is stored sealed under its parent.

use zeroize::Zeroizing;

use crate::bytes::{Reader, tuple};
use crate::suite::{self, Suite};
use crate::{Error, Id, KEY_LEN, Key, Salt};

/// Length of a wrapped key.
pub const WRAPPED_LEN: usize = 107;

const VERSION: u8 = 0x01;
const HEAD_LEN: usize = 59;
const LABEL: &str = "wrap";

/// Wraps `child` under `parent`. The wrap context `wctx` is not stored: the reader rebuilds it from the row it
/// is reading, so a wrapped key copied onto another row does not open.
///
/// `salt` MUST be 24 fresh random bytes.
pub fn wrap(
    parent: &Key,
    suite: Suite,
    salt: &Salt,
    wctx: &[u8],
    child: &Key,
) -> Result<Vec<u8>, Error> {
    let d = suite::derive(parent, suite, salt, LABEL, wctx)?;
    let mut out = Vec::with_capacity(WRAPPED_LEN);
    out.push(VERSION);
    out.extend_from_slice(&suite.id().to_be_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(&d.ck);
    let mut aad = out.clone();
    aad.extend_from_slice(wctx);
    out.extend_from_slice(&suite::seal(
        suite,
        &d.ek,
        &suite::nonce_single(suite, salt),
        child,
        &aad,
    )?);
    Ok(out)
}

/// Unwraps a key. A zeroed wrapped key is [`Error::Shredded`] and never reaches the AEAD.
pub fn unwrap(parent: &Key, wrapped: &[u8], wctx: &[u8]) -> Result<Zeroizing<Key>, Error> {
    if wrapped.len() != WRAPPED_LEN {
        return Err(Error::Malformed("wrapped key length"));
    }
    if wrapped.iter().all(|b| *b == 0) {
        return Err(Error::Shredded);
    }
    let (head, sealed) = wrapped
        .split_at_checked(HEAD_LEN)
        .ok_or(Error::Malformed("wrapped key length"))?;
    let mut r = Reader::new(head);
    if r.u8()? != VERSION {
        return Err(Error::Malformed("unknown wrap version"));
    }
    let suite = Suite::from_id(r.u16()?)?;
    let salt: Salt = r.take()?;
    let commitment: [u8; 32] = r.take()?;

    let ek = suite::derive_checked(parent, suite, &salt, LABEL, wctx, &commitment)?;
    let mut aad = head.to_vec();
    aad.extend_from_slice(wctx);
    let plain = suite::open(suite, &ek, &suite::nonce_single(suite, &salt), sealed, &aad)?;
    let mut child = Zeroizing::new([0u8; KEY_LEN]);
    if plain.len() != KEY_LEN {
        return Err(Error::OpenFailed);
    }
    child.copy_from_slice(&plain);
    Ok(child)
}

/// What a signing key is used for (section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignPurpose {
    /// Signs shred ledger entries.
    Ledger,
    /// Signs checkpoints.
    Checkpoint,
}

/// Wrap contexts, one per row of the table in section 5.
pub mod ctx {
    use super::*;

    fn v(version: u32) -> [u8; 4] {
        version.to_be_bytes()
    }

    /// Domain KEK, wrapped by the root key.
    pub fn kek(
        domain_id: &Id,
        kek_version: u32,
        root_key_id: &Id,
        root_key_version: u32,
    ) -> Result<Vec<u8>, Error> {
        tuple(&[
            b"kek",
            domain_id,
            &v(kek_version),
            root_key_id,
            &v(root_key_version),
        ])
    }

    /// Domain blind-index key, wrapped by the root key.
    pub fn bik(
        domain_id: &Id,
        bik_version: u32,
        root_key_id: &Id,
        root_key_version: u32,
    ) -> Result<Vec<u8>, Error> {
        tuple(&[
            b"bik",
            domain_id,
            &v(bik_version),
            root_key_id,
            &v(root_key_version),
        ])
    }

    /// Domain blind-index key for caller indexes, wrapped by the root key.
    pub fn bix(
        domain_id: &Id,
        bix_version: u32,
        root_key_id: &Id,
        root_key_version: u32,
    ) -> Result<Vec<u8>, Error> {
        tuple(&[
            b"bix",
            domain_id,
            &v(bix_version),
            root_key_id,
            &v(root_key_version),
        ])
    }

    /// Subject key, wrapped by the domain KEK.
    pub fn subject(
        domain_id: &Id,
        subject_hmac: &[u8; 32],
        subject_key_version: u32,
        kek_version: u32,
    ) -> Result<Vec<u8>, Error> {
        tuple(&[
            b"subject",
            domain_id,
            subject_hmac,
            &v(subject_key_version),
            &v(kek_version),
        ])
    }

    /// Data key, wrapped by the subject key.
    pub fn dek(
        domain_id: &Id,
        subject_hmac: &[u8; 32],
        subject_key_version: u32,
        object_id: &Id,
        dek_generation: u32,
    ) -> Result<Vec<u8>, Error> {
        tuple(&[
            b"dek",
            domain_id,
            subject_hmac,
            &v(subject_key_version),
            object_id,
            &v(dek_generation),
        ])
    }

    /// Root key, wrapped by the unseal key or a KMS.
    pub fn root(root_key_id: &Id, root_key_version: u32) -> Result<Vec<u8>, Error> {
        tuple(&[b"root", root_key_id, &v(root_key_version)])
    }

    /// Ed25519 signing-key seed, wrapped by the root key.
    pub fn sign(
        domain_id: &Id,
        purpose: SignPurpose,
        signing_key_id: &Id,
        root_key_id: &Id,
        root_key_version: u32,
    ) -> Result<Vec<u8>, Error> {
        let purpose: &[u8] = match purpose {
            SignPurpose::Ledger => b"ledger",
            SignPurpose::Checkpoint => b"checkpoint",
        };
        tuple(&[
            b"sign",
            domain_id,
            purpose,
            signing_key_id,
            root_key_id,
            &v(root_key_version),
        ])
    }
}
