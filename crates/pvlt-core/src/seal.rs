//! Creating the root key and sealing it, and unsealing it again (PLAN.md section 3, M1 step 4).
//!
//! The root key is never stored in the clear. It is wrapped by an **unseal key**, and the unseal key exists only
//! as Shamir shares held by different people. `init_shamir` makes both, returns the shares once, and drops the
//! unseal key. Unsealing collects at least `threshold` shares, recovers the unseal key, opens the wrapped root
//! key into locked memory, and drops the unseal key again.
//!
//! ```text
//!   shares ──(any k of n)──▶ unseal key ──opens──▶ wrapped root key ──▶ root key (locked memory)
//! ```
//!
//! What this does not protect against: the unseal key and the polynomials inside the `blahaj` crate pass through
//! ordinary heap memory during `init` and unseal. That window is one function call at a ceremony, not a
//! running-service exposure, but it is not wiped by this crate.

use blahaj::Sharks;
use pvlt_format::{Id, Key, PREFIX};
use pvlt_mem::Arena;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::VaultError;
use crate::keys::{EphemeralKey, KeyMaterial, RootKey, WrappedRoot};
#[cfg(feature = "dev-insecure")]
use crate::rng;

const SHARE_VERSION: u8 = 1;
const SHARE_PREFIX: &str = "pvlt-share-v1:";
/// `version ‖ threshold ‖ root_key_id ‖ x ‖ y ‖ check`.
const SHARE_LEN: usize = 1 + 1 + 16 + 1 + 32 + 4;
const SHARE_Y_LEN: usize = 32;

// --- Shares ----------------------------------------------------------------------------------------------

/// One Shamir share of the unseal key, with a version, the threshold, the root key's id and a checksum around
/// it so a mistyped share, or one from another vault, is rejected with a clear reason and not as a failed
/// decryption.
///
/// Layout (55 bytes): `version(1) ‖ threshold(1) ‖ root_key_id(16) ‖ x(1) ‖ y(32) ‖ check(4)`. The text form is
/// `pvlt-share-v1:` followed by the lowercase hex of those bytes. The share holds a secret, so it has no
/// `Clone` and its `Debug` prints nothing about it.
pub struct UnsealShare(Zeroizing<Vec<u8>>);

/// The parts of a share that are not secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ShareInfo {
    /// How many shares are needed to unseal.
    pub threshold: u8,
    /// The root key this share belongs to.
    pub root_key_id: Id,
    /// This share's number (1 to 255).
    pub index: u8,
}

struct Parts {
    info: ShareInfo,
    y: Zeroizing<Key>,
}

/// A 4-byte checksum over the share body. It catches typos; it is not a security control.
fn checksum(body: &[u8]) -> [u8; 4] {
    let digest: [u8; 32] = Sha256::new()
        .chain_update(PREFIX)
        .chain_update(b"share-check\0")
        .chain_update(body)
        .finalize()
        .into();
    let [a, b, c, d, ..] = digest;
    [a, b, c, d]
}

impl UnsealShare {
    fn build(threshold: u8, root_key_id: &Id, share: &blahaj::Share) -> Result<Self, VaultError> {
        let raw = Zeroizing::new(Vec::from(share));
        let (x, y) = raw
            .split_first()
            .ok_or(VaultError::Unavailable("share is empty"))?;
        if y.len() != SHARE_Y_LEN {
            return Err(VaultError::Unavailable("share has the wrong length"));
        }
        let mut bytes = Zeroizing::new(Vec::with_capacity(SHARE_LEN));
        bytes.push(SHARE_VERSION);
        bytes.push(threshold);
        bytes.extend_from_slice(root_key_id);
        bytes.push(*x);
        bytes.extend_from_slice(y);
        let check = checksum(&bytes);
        bytes.extend_from_slice(&check);
        Ok(Self(bytes))
    }

    fn parts(&self) -> Result<Parts, VaultError> {
        let bad = |what| VaultError::Invalid(what);
        if self.0.len() != SHARE_LEN {
            return Err(bad("share has the wrong length"));
        }
        let (body, check) = self
            .0
            .split_last_chunk::<4>()
            .ok_or(bad("share has the wrong length"))?;
        if !bool::from(checksum(body).ct_eq(check)) {
            return Err(bad(
                "share checksum does not match: it was mistyped or damaged",
            ));
        }
        let (version, rest) = body
            .split_first()
            .ok_or(bad("share has the wrong length"))?;
        if *version != SHARE_VERSION {
            return Err(bad("unknown share version"));
        }
        let (threshold, rest) = rest
            .split_first()
            .ok_or(bad("share has the wrong length"))?;
        let (root_key_id, rest) = rest
            .split_first_chunk::<16>()
            .ok_or(bad("share has the wrong length"))?;
        let (index, y) = rest
            .split_first()
            .ok_or(bad("share has the wrong length"))?;
        if *index == 0 {
            return Err(bad("share number is zero"));
        }
        let y: Key = y
            .try_into()
            .map_err(|_| bad("share has the wrong length"))?;
        Ok(Parts {
            info: ShareInfo {
                threshold: *threshold,
                root_key_id: *root_key_id,
                index: *index,
            },
            y: Zeroizing::new(y),
        })
    }

    /// The non-secret facts about this share. Fails if the share is damaged.
    pub fn info(&self) -> Result<ShareInfo, VaultError> {
        Ok(self.parts()?.info)
    }

    /// The text form, for printing or typing: `pvlt-share-v1:<hex>`.
    pub fn to_text(&self) -> Zeroizing<String> {
        let hex = Zeroizing::new(hex::encode(self.0.as_slice()));
        let mut out = Zeroizing::new(String::with_capacity(SHARE_PREFIX.len() + hex.len()));
        out.push_str(SHARE_PREFIX);
        out.push_str(&hex);
        out
    }

    /// Parses the text form. Checks the prefix, the hex and the length; the checksum is checked when the share
    /// is used or when [`UnsealShare::info`] is called.
    pub fn from_text(text: &str) -> Result<Self, VaultError> {
        let hex = text
            .trim()
            .strip_prefix(SHARE_PREFIX)
            .ok_or(VaultError::Invalid("not a pvlt share"))?;
        let bytes = Zeroizing::new(
            hex::decode(hex).map_err(|_| VaultError::Invalid("share is not valid hex"))?,
        );
        if bytes.len() != SHARE_LEN {
            return Err(VaultError::Invalid("share has the wrong length"));
        }
        Ok(Self(bytes))
    }
}

impl core::fmt::Debug for UnsealShare {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("UnsealShare(..)")
    }
}

// --- Seal configuration ----------------------------------------------------------------------------------

/// Parameters for sealing the unseal key with a passphrase. Only exists with the `dev-insecure` feature: the
/// production gate in DECISIONS.md is Shamir shares or a KMS.
#[cfg(feature = "dev-insecure")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassphraseParams {
    /// Argon2id memory, in KiB.
    pub m_kib: u32,
    /// Argon2id passes.
    pub t_cost: u32,
    /// Argon2id lanes.
    pub p_cost: u32,
    /// The random salt, stored in the clear.
    pub salt: [u8; 16],
}

#[cfg(feature = "dev-insecure")]
impl PassphraseParams {
    /// RFC 9106's second recommended parameter set (64 MiB, 3 passes, 4 lanes) with a fresh salt.
    pub fn recommended() -> Result<Self, VaultError> {
        let mut salt = [0u8; 16];
        rng::fill(&mut salt)?;
        Ok(Self {
            m_kib: 64 * 1024,
            t_cost: 3,
            p_cost: 4,
            salt,
        })
    }
}

/// How the unseal key is held.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SealMode {
    /// Split into `shares` Shamir shares, any `threshold` of which recover it.
    Shamir {
        /// Shares needed to unseal.
        threshold: u8,
        /// Shares made.
        shares: u8,
    },
    /// Derived from a passphrase with Argon2id. Development only.
    #[cfg(feature = "dev-insecure")]
    Passphrase(PassphraseParams),
}

/// What a key store persists about sealing. It contains no secret: the wrapped root key is ciphertext.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SealConfig {
    /// The root key, wrapped by the unseal key.
    pub root: WrappedRoot,
    /// How the unseal key is held.
    pub mode: SealMode,
}

/// The result of creating a vault's root key.
#[derive(Debug)]
pub struct Initialized {
    /// Store this.
    pub config: SealConfig,
    /// Hand one to each key holder, then drop them. Empty for passphrase mode.
    pub shares: Vec<UnsealShare>,
    /// The root key, already unsealed, so first start does not have to unseal at once.
    pub root: RootKey,
}

// --- Shamir ----------------------------------------------------------------------------------------------

/// Combines shares into the unseal key. Checks everything about the shares it can before any arithmetic.
fn recover_unseal_key(
    threshold: u8,
    root_key_id: &Id,
    shares: &[UnsealShare],
) -> Result<EphemeralKey, VaultError> {
    let mut distinct: Vec<(u8, Zeroizing<Key>)> = Vec::new();
    for share in shares {
        let Parts { info, y } = share.parts()?;
        if info.root_key_id != *root_key_id {
            return Err(VaultError::Invalid("share is for a different root key"));
        }
        if info.threshold != threshold {
            return Err(VaultError::Invalid(
                "share was made for a different threshold",
            ));
        }
        match distinct.iter().find(|(x, _)| *x == info.index) {
            Some((_, seen)) if !bool::from(seen.as_slice().ct_eq(y.as_slice())) => {
                return Err(VaultError::Invalid(
                    "two shares have the same number but different contents",
                ));
            }
            Some(_) => {}
            None => distinct.push((info.index, y)),
        }
    }
    let needed = usize::from(threshold);
    if distinct.len() < needed {
        return Err(VaultError::Invalid("not enough shares"));
    }
    let mut points = Vec::with_capacity(needed);
    for (x, y) in distinct.iter().take(needed) {
        let mut bytes = Zeroizing::new(Vec::with_capacity(1 + SHARE_Y_LEN));
        bytes.push(*x);
        bytes.extend_from_slice(y.as_slice());
        points.push(
            blahaj::Share::try_from(bytes.as_slice())
                .map_err(|_| VaultError::Invalid("share could not be read"))?,
        );
    }
    let secret = Zeroizing::new(
        Sharks(threshold)
            .recover(&points)
            .map_err(|_| VaultError::Invalid("shares could not be combined"))?,
    );
    let key: Zeroizing<Key> = Zeroizing::new(
        secret
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::Invalid("shares combine to the wrong length"))?,
    );
    Ok(EphemeralKey::from_key(&key))
}

/// Creates a root key, wraps it under a new unseal key, and splits the unseal key into `shares` shares of which
/// any `threshold` unseal the vault. `2 <= threshold <= shares`.
///
/// The shares are checked before they are returned: two different subsets must each recover the unseal key.
pub fn init_shamir(arena: &Arena, threshold: u8, shares: u8) -> Result<Initialized, VaultError> {
    if threshold < 2 {
        return Err(VaultError::Invalid("threshold must be at least 2"));
    }
    if shares < threshold {
        return Err(VaultError::Invalid("fewer shares than the threshold"));
    }
    let unseal = EphemeralKey::random()?;
    let root = RootKey::generate(arena)?;
    let wrapped = root.wrap(&unseal)?;

    let dealt = Sharks(threshold)
        .dealer(unseal.expose())
        .take(usize::from(shares))
        .map(|s| UnsealShare::build(threshold, root.id(), &s))
        .collect::<Result<Vec<_>, _>>()?;

    let needed = usize::from(threshold);
    let (first, last) = (dealt.iter().take(needed), dealt.iter().rev().take(needed));
    for subset in [first.collect::<Vec<_>>(), last.collect::<Vec<_>>()] {
        let owned: Vec<UnsealShare> = subset
            .into_iter()
            .map(|s| UnsealShare(s.0.clone()))
            .collect();
        let back = recover_unseal_key(threshold, root.id(), &owned)?;
        if !bool::from(back.expose().ct_eq(unseal.expose())) {
            return Err(VaultError::Unavailable("share self-check failed"));
        }
    }

    Ok(Initialized {
        config: SealConfig {
            root: wrapped,
            mode: SealMode::Shamir { threshold, shares },
        },
        shares: dealt,
        root,
    })
}

/// Unseals with Shamir shares. Fewer than `threshold` distinct shares, shares from another vault, and damaged
/// shares are [`VaultError::Invalid`]; enough shares that do not open the root key are
/// [`VaultError::OpenFailed`].
pub fn unseal_with_shares(
    arena: &Arena,
    config: &SealConfig,
    shares: &[UnsealShare],
) -> Result<RootKey, VaultError> {
    let threshold = match &config.mode {
        SealMode::Shamir { threshold, .. } => *threshold,
        #[cfg(feature = "dev-insecure")]
        SealMode::Passphrase(_) => {
            return Err(VaultError::Invalid("this vault is not sealed with shares"));
        }
    };
    let unseal = recover_unseal_key(threshold, &config.root.id, shares)?;
    RootKey::unwrap(arena, &unseal, &config.root)
}

// --- Passphrase (development only) -----------------------------------------------------------------------

#[cfg(feature = "dev-insecure")]
fn passphrase_key(
    passphrase: &[u8],
    params: &PassphraseParams,
) -> Result<EphemeralKey, VaultError> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let p = Params::new(params.m_kib, params.t_cost, params.p_cost, Some(32))
        .map_err(|_| VaultError::Invalid("argon2 parameters"))?;
    let mut out = Zeroizing::new([0u8; 32]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, p)
        .hash_password_into(passphrase, &params.salt, out.as_mut_slice())
        .map_err(|_| VaultError::Invalid("argon2 failed"))?;
    Ok(EphemeralKey::from_key(&out))
}

/// Creates a root key sealed by a passphrase. Development only.
#[cfg(feature = "dev-insecure")]
pub fn init_passphrase(
    arena: &Arena,
    passphrase: &[u8],
    params: PassphraseParams,
) -> Result<Initialized, VaultError> {
    if passphrase.len() < 12 {
        return Err(VaultError::Invalid("passphrase must be at least 12 bytes"));
    }
    let unseal = passphrase_key(passphrase, &params)?;
    let root = RootKey::generate(arena)?;
    let wrapped = root.wrap(&unseal)?;
    Ok(Initialized {
        config: SealConfig {
            root: wrapped,
            mode: SealMode::Passphrase(params),
        },
        shares: Vec::new(),
        root,
    })
}

/// Unseals with a passphrase. A wrong passphrase is [`VaultError::OpenFailed`]. Development only.
#[cfg(feature = "dev-insecure")]
pub fn unseal_with_passphrase(
    arena: &Arena,
    config: &SealConfig,
    passphrase: &[u8],
) -> Result<RootKey, VaultError> {
    let SealMode::Passphrase(params) = &config.mode else {
        return Err(VaultError::Invalid(
            "this vault is not sealed with a passphrase",
        ));
    };
    let unseal = passphrase_key(passphrase, params)?;
    RootKey::unwrap(arena, &unseal, &config.root)
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use pvlt_mem::LockPolicy;

    use super::*;

    fn arena() -> Arena {
        Arena::new(64, LockPolicy::BestEffort).unwrap()
    }

    fn copy(share: &UnsealShare) -> UnsealShare {
        UnsealShare::from_text(&share.to_text()).unwrap()
    }

    /// A share with one secret byte changed and its checksum recomputed, so it looks perfectly valid. The
    /// checksum only catches typos; this is what a damaged or malicious share that passes it looks like.
    fn forged(share: &UnsealShare) -> UnsealShare {
        let mut bytes = share.0.to_vec();
        bytes.truncate(SHARE_LEN - 4);
        let y_start = 1 + 1 + 16 + 1;
        bytes[y_start] ^= 0x01;
        let check = checksum(&bytes);
        bytes.extend_from_slice(&check);
        UnsealShare(Zeroizing::new(bytes))
    }

    #[test]
    fn a_forged_share_passes_the_checksum() {
        let a = arena();
        let init = init_shamir(&a, 3, 5).unwrap();
        let bad = forged(&init.shares[0]);
        assert_eq!(
            bad.info().unwrap(),
            init.shares[0].info().unwrap(),
            "same number and root, different secret"
        );
    }

    #[test]
    fn two_shares_with_one_number_and_different_contents_are_refused() {
        let a = arena();
        let init = init_shamir(&a, 3, 5).unwrap();
        let shares = [
            copy(&init.shares[0]),
            forged(&init.shares[0]),
            copy(&init.shares[1]),
            copy(&init.shares[2]),
        ];
        assert_eq!(
            unseal_with_shares(&a, &init.config, &shares).unwrap_err(),
            VaultError::Invalid("two shares have the same number but different contents")
        );
    }

    #[test]
    fn a_wrong_share_can_never_produce_a_wrong_root_key() {
        let a = arena();
        let init = init_shamir(&a, 3, 5).unwrap();
        let shares = [
            forged(&init.shares[0]),
            copy(&init.shares[1]),
            copy(&init.shares[2]),
        ];
        // The shares combine to some other unseal key, which then fails to open the wrapped root key.
        assert_eq!(
            unseal_with_shares(&a, &init.config, &shares).unwrap_err(),
            VaultError::OpenFailed
        );
    }

    #[test]
    fn a_share_for_another_threshold_is_refused() {
        let a = arena();
        let init = init_shamir(&a, 3, 5).unwrap();
        let mut bytes = init.shares[0].0.to_vec();
        bytes.truncate(SHARE_LEN - 4);
        bytes[1] = 2;
        let check = checksum(&bytes);
        bytes.extend_from_slice(&check);
        let odd = UnsealShare(Zeroizing::new(bytes));
        let shares = [odd, copy(&init.shares[1]), copy(&init.shares[2])];
        assert_eq!(
            unseal_with_shares(&a, &init.config, &shares).unwrap_err(),
            VaultError::Invalid("share was made for a different threshold")
        );
    }

    #[test]
    fn share_number_zero_is_refused() {
        let a = arena();
        let init = init_shamir(&a, 3, 5).unwrap();
        let mut bytes = init.shares[0].0.to_vec();
        bytes.truncate(SHARE_LEN - 4);
        bytes[1 + 1 + 16] = 0;
        let check = checksum(&bytes);
        bytes.extend_from_slice(&check);
        assert_eq!(
            UnsealShare(Zeroizing::new(bytes)).info().unwrap_err(),
            VaultError::Invalid("share number is zero")
        );
    }
}
