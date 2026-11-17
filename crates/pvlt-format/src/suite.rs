//! Sections 2 and 3: algorithm suites, key derivation, key commitment and nonces.

use aes_gcm::Aes256Gcm;
use chacha20poly1305::XChaCha20Poly1305;
use chacha20poly1305::aead::{Aead, KeyInit, Nonce, Payload};
use hkdf::Hkdf;
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::{Error, KEY_LEN, Key, PREFIX, Salt};

/// An algorithm suite (section 2). The KDF is HKDF-SHA-256 in all of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Suite {
    /// `0x0001`, XChaCha20-Poly1305. The default for everything the server encrypts.
    XChaCha20Poly1305,
    /// `0x0002`, AES-256-GCM-SIV. Needs the `gcm-siv` feature.
    Aes256GcmSiv,
    /// `0x0003`, AES-256-GCM. The browser suite.
    Aes256Gcm,
}

impl Suite {
    /// The suite for an id read from the wire. Fails for unknown ids and for suites this build leaves out.
    pub fn from_id(id: u16) -> Result<Self, Error> {
        match id {
            0x0001 => Ok(Suite::XChaCha20Poly1305),
            #[cfg(feature = "gcm-siv")]
            0x0002 => Ok(Suite::Aes256GcmSiv),
            0x0003 => Ok(Suite::Aes256Gcm),
            _ => Err(Error::UnsupportedSuite),
        }
    }

    /// The id written to the wire.
    pub fn id(self) -> u16 {
        match self {
            Suite::XChaCha20Poly1305 => 0x0001,
            Suite::Aes256GcmSiv => 0x0002,
            Suite::Aes256Gcm => 0x0003,
        }
    }

    fn nonce_len(self) -> usize {
        match self {
            Suite::XChaCha20Poly1305 => 24,
            Suite::Aes256GcmSiv | Suite::Aes256Gcm => 12,
        }
    }
}

/// The two halves of the HKDF output for one sealed unit.
pub(crate) struct Derived {
    /// The AEAD key for this unit only.
    pub(crate) ek: Zeroizing<Key>,
    /// The key commitment, stored in clear next to the ciphertext.
    pub(crate) ck: [u8; 32],
}

/// `info = PREFIX ‖ label ‖ 0x00 ‖ u16(suite) ‖ ctx`.
pub(crate) fn info(suite: Suite, label: &str, ctx: &[u8]) -> Vec<u8> {
    let mut info = Vec::with_capacity(PREFIX.len() + label.len() + 3 + ctx.len());
    info.extend_from_slice(PREFIX);
    info.extend_from_slice(label.as_bytes());
    info.push(0);
    info.extend_from_slice(&suite.id().to_be_bytes());
    info.extend_from_slice(ctx);
    info
}

/// Derives `(ek, ck)` from a key, a fresh salt, a usage label and a context (section 3).
pub(crate) fn derive(
    key: &Key,
    suite: Suite,
    salt: &Salt,
    label: &str,
    ctx: &[u8],
) -> Result<Derived, Error> {
    let mut okm = Zeroizing::new([0u8; 64]);
    Hkdf::<Sha256>::new(Some(salt), key)
        .expand(&info(suite, label, ctx), okm.as_mut_slice())
        .map_err(|_| Error::Invalid("hkdf output length"))?;
    let (ek_half, ck_half) = okm.split_at(KEY_LEN);
    let mut ek = Zeroizing::new([0u8; KEY_LEN]);
    ek.copy_from_slice(ek_half);
    let mut ck = [0u8; 32];
    ck.copy_from_slice(ck_half);
    Ok(Derived { ek, ck })
}

/// Recomputes the commitment and compares it in constant time. Must run before any AEAD decryption.
pub(crate) fn derive_checked(
    key: &Key,
    suite: Suite,
    salt: &Salt,
    label: &str,
    ctx: &[u8],
    stored_ck: &[u8; 32],
) -> Result<Zeroizing<Key>, Error> {
    let d = derive(key, suite, salt, label, ctx)?;
    if bool::from(d.ck.ct_eq(stored_ck)) {
        Ok(d.ek)
    } else {
        Err(Error::OpenFailed)
    }
}

/// The nonce for a single-shot seal: the salt, cut to the suite's nonce length.
pub(crate) fn nonce_single(suite: Suite, salt: &Salt) -> Vec<u8> {
    salt.iter().copied().take(suite.nonce_len()).collect()
}

/// The nonce for chunk `i` of a stream: `salt[0..n-5] ‖ u32(i) ‖ u8(last)`.
pub(crate) fn nonce_chunk(suite: Suite, salt: &Salt, i: u32, last: bool) -> Vec<u8> {
    let mut n: Vec<u8> = salt.iter().copied().take(suite.nonce_len() - 5).collect();
    n.extend_from_slice(&i.to_be_bytes());
    n.push(u8::from(last));
    n
}

fn seal_with<C: Aead + KeyInit>(
    ek: &Key,
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    let cipher = C::new_from_slice(ek).map_err(|_| Error::Invalid("aead key length"))?;
    let nonce = Nonce::<C>::try_from(nonce).map_err(|_| Error::Invalid("aead nonce length"))?;
    cipher
        .encrypt(
            &nonce,
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| Error::Invalid("aead input too long"))
}

fn open_with<C: Aead + KeyInit>(
    ek: &Key,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    let cipher = C::new_from_slice(ek).map_err(|_| Error::Invalid("aead key length"))?;
    let nonce = Nonce::<C>::try_from(nonce).map_err(|_| Error::Invalid("aead nonce length"))?;
    cipher
        .decrypt(
            &nonce,
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::OpenFailed)
}

/// AEAD-Seal. Returns `ciphertext ‖ tag`.
pub(crate) fn seal(
    suite: Suite,
    ek: &Key,
    nonce: &[u8],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, Error> {
    match suite {
        Suite::XChaCha20Poly1305 => seal_with::<XChaCha20Poly1305>(ek, nonce, plaintext, aad),
        Suite::Aes256Gcm => seal_with::<Aes256Gcm>(ek, nonce, plaintext, aad),
        #[cfg(feature = "gcm-siv")]
        Suite::Aes256GcmSiv => seal_with::<aes_gcm_siv::Aes256GcmSiv>(ek, nonce, plaintext, aad),
        #[cfg(not(feature = "gcm-siv"))]
        Suite::Aes256GcmSiv => Err(Error::UnsupportedSuite),
    }
}

/// AEAD-Open. Any failure is [`Error::OpenFailed`].
pub(crate) fn open(
    suite: Suite,
    ek: &Key,
    nonce: &[u8],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Zeroizing<Vec<u8>>, Error> {
    match suite {
        Suite::XChaCha20Poly1305 => open_with::<XChaCha20Poly1305>(ek, nonce, ciphertext, aad),
        Suite::Aes256Gcm => open_with::<Aes256Gcm>(ek, nonce, ciphertext, aad),
        #[cfg(feature = "gcm-siv")]
        Suite::Aes256GcmSiv => open_with::<aes_gcm_siv::Aes256GcmSiv>(ek, nonce, ciphertext, aad),
        #[cfg(not(feature = "gcm-siv"))]
        Suite::Aes256GcmSiv => Err(Error::UnsupportedSuite),
    }
}

/// The intermediate values of section 3, exposed so the known-answer tests can check each one.
#[doc(hidden)]
pub mod testing {
    use super::*;

    /// `(info, ek, ck, nonce_single, nonce_chunk(0, false), nonce_chunk(7, true))`.
    #[allow(clippy::type_complexity)]
    pub fn derive_parts(
        key: &Key,
        suite: Suite,
        salt: &Salt,
        label: &str,
        ctx: &[u8],
    ) -> Result<(Vec<u8>, Key, [u8; 32], Vec<u8>, Vec<u8>, Vec<u8>), Error> {
        let d = derive(key, suite, salt, label, ctx)?;
        Ok((
            info(suite, label, ctx),
            *d.ek,
            d.ck,
            nonce_single(suite, salt),
            nonce_chunk(suite, salt, 0, false),
            nonce_chunk(suite, salt, 7, true),
        ))
    }
}
