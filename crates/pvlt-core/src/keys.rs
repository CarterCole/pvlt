//! The key hierarchy (FORMAT.md section 5, PLAN.md 3.2):
//!
//! ```text
//!   unseal key ──wraps──▶ root key ──wraps──▶ domain KEK, blind-index keys (BIK, BIX)
//!                                                 └─ KEK ──wraps──▶ subject key ──wraps──▶ data key (DEK)
//! ```
//!
//! Shredding is deleting a wrapped key at the right level. Nothing here deletes anything: this module makes
//! keys and wraps them, and opens them again from the wrapped bytes a key store holds. A zeroed wrapped key
//! opens as [`VaultError::Shredded`].

use core::fmt;

use pvlt_format::wrap::{self, SignPurpose, ctx};
use pvlt_format::{Id, Key, Suite, blind, log};
use pvlt_mem::{Arena, SecretKey};
use zeroize::Zeroize;

use crate::{VaultError, rng};

/// The suite every key is wrapped with.
pub const WRAP_SUITE: Suite = Suite::XChaCha20Poly1305;

/// Anything that holds 32 key bytes and can lend them out.
pub trait KeyMaterial {
    /// Borrows the key bytes. Keep the borrow short and do not hold it across an `.await`.
    fn expose(&self) -> &Key;
}

impl KeyMaterial for SecretKey {
    fn expose(&self) -> &Key {
        SecretKey::expose(self)
    }
}

/// A short-lived key on the heap, wiped when dropped.
///
/// It is boxed so that moving it moves a pointer and not the key bytes, which would leave copies behind in
/// stack frames.
pub struct EphemeralKey(Box<Key>);

impl EphemeralKey {
    /// A new random key.
    pub fn random() -> Result<Self, VaultError> {
        let mut key = Box::new([0u8; 32]);
        rng::fill(key.as_mut_slice())?;
        Ok(Self(key))
    }

    /// Copies a key. The caller is responsible for wiping the source.
    pub(crate) fn from_key(key: &Key) -> Self {
        Self(Box::new(*key))
    }
}

impl KeyMaterial for EphemeralKey {
    fn expose(&self) -> &Key {
        &self.0
    }
}

impl Drop for EphemeralKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for EphemeralKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EphemeralKey(..)")
    }
}

/// Wraps `child` under `parent` with a fresh salt.
fn wrap_child(
    parent: &impl KeyMaterial,
    wctx: &[u8],
    child: &impl KeyMaterial,
) -> Result<Vec<u8>, VaultError> {
    Ok(wrap::wrap(
        parent.expose(),
        WRAP_SUITE,
        &rng::salt()?,
        wctx,
        child.expose(),
    )?)
}

/// Opens a wrapped key into locked memory.
fn unwrap_into_arena(
    arena: &Arena,
    parent: &impl KeyMaterial,
    wctx: &[u8],
    wrapped: &[u8],
) -> Result<SecretKey, VaultError> {
    let child = wrap::unwrap(parent.expose(), wrapped, wctx)?;
    arena.alloc_with(|slot| {
        *slot = *child;
        Ok::<(), VaultError>(())
    })
}

/// A new random key in locked memory, written there directly.
fn random_secret(arena: &Arena) -> Result<SecretKey, VaultError> {
    arena.alloc_with(|slot| rng::fill(slot.as_mut_slice()))
}

// --- Root key --------------------------------------------------------------------------------------------

/// The root key as it is stored: wrapped by the unseal key (FORMAT.md section 5, `"root"` context).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedRoot {
    /// The root key's id. Not secret; it is in the wrap context and in every Shamir share.
    pub id: Id,
    /// The root key's version, starting at 1.
    pub version: u32,
    /// The 107-byte wrapped key.
    pub wrapped: Vec<u8>,
}

/// The root key. It lives in locked memory for as long as the vault is unsealed.
#[derive(Debug)]
pub struct RootKey {
    id: Id,
    version: u32,
    key: SecretKey,
}

impl RootKey {
    /// A new root key (version 1) with a random id.
    pub fn generate(arena: &Arena) -> Result<Self, VaultError> {
        Ok(Self {
            id: rng::id()?,
            version: 1,
            key: random_secret(arena)?,
        })
    }

    /// The root key's id.
    pub fn id(&self) -> &Id {
        &self.id
    }

    /// The root key's version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Wraps the root key under the unseal key.
    pub fn wrap(&self, unseal: &impl KeyMaterial) -> Result<WrappedRoot, VaultError> {
        let wctx = ctx::root(&self.id, self.version)?;
        Ok(WrappedRoot {
            id: self.id,
            version: self.version,
            wrapped: wrap_child(unseal, &wctx, &self.key)?,
        })
    }

    /// Opens a wrapped root key with the unseal key. A wrong unseal key is [`VaultError::OpenFailed`].
    pub fn unwrap(
        arena: &Arena,
        unseal: &impl KeyMaterial,
        wrapped: &WrappedRoot,
    ) -> Result<Self, VaultError> {
        let wctx = ctx::root(&wrapped.id, wrapped.version)?;
        let key = unwrap_into_arena(arena, unseal, &wctx, &wrapped.wrapped)?;
        Ok(Self {
            id: wrapped.id,
            version: wrapped.version,
            key,
        })
    }
}

impl KeyMaterial for RootKey {
    fn expose(&self) -> &Key {
        self.key.expose()
    }
}

// --- Signing keys ----------------------------------------------------------------------------------------

/// A domain's ledger signing key as a key store holds it: the Ed25519 seed wrapped by the root key, and the
/// public key, which is not secret and lets a ledger be verified without unsealing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedSigningKey {
    /// What it signs: ledger entries or checkpoints. The purpose is part of the wrap context, so a key made for
    /// one cannot be used for the other.
    pub purpose: SignPurpose,
    /// The key's id, written into every ledger line it signs.
    pub key_id: Id,
    /// The version of the root key that wrapped it.
    pub root_key_version: u32,
    /// The 107-byte wrapped seed.
    pub wrapped: Vec<u8>,
    /// The Ed25519 public key.
    pub public_key: [u8; 32],
}

impl RootKey {
    /// Makes a domain's signing key for a purpose and wraps its seed under this root key.
    pub fn new_signing_key(
        &self,
        arena: &Arena,
        domain_id: &Id,
        purpose: SignPurpose,
    ) -> Result<WrappedSigningKey, VaultError> {
        let seed = random_secret(arena)?;
        let key_id = rng::id()?;
        let wctx = ctx::sign(domain_id, purpose, &key_id, &self.id, self.version)?;
        Ok(WrappedSigningKey {
            purpose,
            key_id,
            root_key_version: self.version,
            wrapped: wrap_child(self, &wctx, &seed)?,
            public_key: log::public_key(seed.expose()),
        })
    }

    /// Signs a ledger entry and returns the stored line (FORMAT.md section 8). The seed is opened into locked
    /// memory for the call and wiped when it returns. A key whose public half does not match its seed is
    /// refused.
    pub fn sign_ledger(
        &self,
        arena: &Arena,
        domain_id: &Id,
        key: &WrappedSigningKey,
        entry: &serde_json::Value,
    ) -> Result<Vec<u8>, VaultError> {
        if key.purpose != SignPurpose::Ledger {
            return Err(VaultError::Invalid("not a ledger signing key"));
        }
        let seed = self.open_signing_seed(arena, domain_id, key)?;
        Ok(log::ledger_line(seed.expose(), &key.key_id, entry)?)
    }

    /// Signs a checkpoint and returns the signature as hex.
    pub fn sign_checkpoint(
        &self,
        arena: &Arena,
        domain_id: &Id,
        key: &WrappedSigningKey,
        checkpoint: &serde_json::Value,
    ) -> Result<String, VaultError> {
        if key.purpose != SignPurpose::Checkpoint {
            return Err(VaultError::Invalid("not a checkpoint signing key"));
        }
        let seed = self.open_signing_seed(arena, domain_id, key)?;
        Ok(hex::encode(log::checkpoint_sign(
            seed.expose(),
            checkpoint,
        )?))
    }

    fn open_signing_seed(
        &self,
        arena: &Arena,
        domain_id: &Id,
        key: &WrappedSigningKey,
    ) -> Result<SecretKey, VaultError> {
        let wctx = ctx::sign(
            domain_id,
            key.purpose,
            &key.key_id,
            &self.id,
            key.root_key_version,
        )?;
        let seed = unwrap_into_arena(arena, self, &wctx, &key.wrapped)?;
        if log::public_key(seed.expose()) != key.public_key {
            return Err(VaultError::OpenFailed);
        }
        Ok(seed)
    }
}

// --- Domain keys -----------------------------------------------------------------------------------------

/// A domain's three root-wrapped keys as a key store holds them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedDomainKeys {
    /// Version of the key-encryption key.
    pub kek_version: u32,
    /// The wrapped KEK.
    pub kek: Vec<u8>,
    /// Version of the subject and scope blind-index key.
    pub bik_version: u32,
    /// The wrapped BIK.
    pub bik: Vec<u8>,
    /// Version of the caller-index blind-index key.
    pub bix_version: u32,
    /// The wrapped BIX.
    pub bix: Vec<u8>,
}

/// One domain's keys, all in locked memory: the key-encryption key that wraps subject keys, and the two
/// blind-index keys.
#[derive(Debug)]
pub struct DomainKeys {
    domain_id: Id,
    kek_version: u32,
    kek: SecretKey,
    bik_version: u32,
    bik: SecretKey,
    bix_version: u32,
    bix: SecretKey,
}

impl DomainKeys {
    /// Makes a new domain's keys (all version 1) and wraps them under the root key.
    pub fn create(
        arena: &Arena,
        root: &RootKey,
        domain_id: &Id,
    ) -> Result<(Self, WrappedDomainKeys), VaultError> {
        let (kek, bik, bix) = (
            random_secret(arena)?,
            random_secret(arena)?,
            random_secret(arena)?,
        );
        let version = 1;
        let wrapped = WrappedDomainKeys {
            kek_version: version,
            kek: wrap_child(
                root,
                &ctx::kek(domain_id, version, &root.id, root.version)?,
                &kek,
            )?,
            bik_version: version,
            bik: wrap_child(
                root,
                &ctx::bik(domain_id, version, &root.id, root.version)?,
                &bik,
            )?,
            bix_version: version,
            bix: wrap_child(
                root,
                &ctx::bix(domain_id, version, &root.id, root.version)?,
                &bix,
            )?,
        };
        let keys = Self {
            domain_id: *domain_id,
            kek_version: version,
            kek,
            bik_version: version,
            bik,
            bix_version: version,
            bix,
        };
        Ok((keys, wrapped))
    }

    /// Opens a domain's wrapped keys with the root key. Each key is bound to this domain, its version and the
    /// root key, so wrapped keys from another domain, or swapped between the three slots, do not open.
    pub fn unwrap(
        arena: &Arena,
        root: &RootKey,
        domain_id: &Id,
        wrapped: &WrappedDomainKeys,
    ) -> Result<Self, VaultError> {
        let (id, rv) = (&root.id, root.version);
        Ok(Self {
            domain_id: *domain_id,
            kek_version: wrapped.kek_version,
            kek: unwrap_into_arena(
                arena,
                root,
                &ctx::kek(domain_id, wrapped.kek_version, id, rv)?,
                &wrapped.kek,
            )?,
            bik_version: wrapped.bik_version,
            bik: unwrap_into_arena(
                arena,
                root,
                &ctx::bik(domain_id, wrapped.bik_version, id, rv)?,
                &wrapped.bik,
            )?,
            bix_version: wrapped.bix_version,
            bix: unwrap_into_arena(
                arena,
                root,
                &ctx::bix(domain_id, wrapped.bix_version, id, rv)?,
                &wrapped.bix,
            )?,
        })
    }

    /// The domain these keys belong to.
    pub fn domain_id(&self) -> &Id {
        &self.domain_id
    }

    /// The KEK version that wraps new subject keys.
    pub fn kek_version(&self) -> u32 {
        self.kek_version
    }

    /// The blind-index key version used for subject and scope HMACs. Ledger entries record it (FORMAT.md 8).
    pub fn bik_version(&self) -> u32 {
        self.bik_version
    }

    /// The blind-index key version used for caller indexes.
    pub fn bix_version(&self) -> u32 {
        self.bix_version
    }

    /// The blind identifier for a subject (FORMAT.md section 6).
    pub fn subject_hmac(&self, subject: &str) -> Result<[u8; 32], VaultError> {
        Ok(blind::subject_hmac(self.bik.expose(), subject)?)
    }

    /// The blind identifier for a scope.
    pub fn scope_hmac(&self, scope: &str) -> Result<[u8; 32], VaultError> {
        Ok(blind::scope_hmac(self.bik.expose(), scope)?)
    }

    /// The blind identifier of the pseudo-subject that holds facts created without a subject.
    pub fn pseudo_subject_hmac(&self, scope: &str) -> Result<[u8; 32], VaultError> {
        Ok(blind::pseudo_subject_hmac(self.bik.expose(), scope)?)
    }

    /// A caller-visible blind index value, for duplicate detection (FORMAT.md section 6).
    pub fn index_value(&self, index_name: &str, value: &[u8]) -> Result<[u8; 32], VaultError> {
        Ok(blind::index_value(self.bix.expose(), index_name, value)?)
    }

    /// Makes a subject's key and wraps it under the KEK. `subject_hmac` comes from [`Self::subject_hmac`] or
    /// [`Self::pseudo_subject_hmac`].
    pub fn new_subject_key(
        &self,
        subject_hmac: &[u8; 32],
        version: u32,
    ) -> Result<(SubjectKey, WrappedSubjectKey), VaultError> {
        let key = EphemeralKey::random()?;
        let wctx = ctx::subject(&self.domain_id, subject_hmac, version, self.kek_version)?;
        let wrapped = WrappedSubjectKey {
            version,
            kek_version: self.kek_version,
            wrapped: wrap_child(&self.kek, &wctx, &key)?,
        };
        Ok((
            SubjectKey {
                key,
                domain_id: self.domain_id,
                subject_hmac: *subject_hmac,
                version,
            },
            wrapped,
        ))
    }

    /// Opens a subject's wrapped key. A zeroed one is [`VaultError::Shredded`].
    pub fn unwrap_subject_key(
        &self,
        subject_hmac: &[u8; 32],
        wrapped: &WrappedSubjectKey,
    ) -> Result<SubjectKey, VaultError> {
        if wrapped.kek_version != self.kek_version {
            return Err(VaultError::Invalid(
                "subject key was wrapped by a different KEK version",
            ));
        }
        let wctx = ctx::subject(
            &self.domain_id,
            subject_hmac,
            wrapped.version,
            wrapped.kek_version,
        )?;
        let key = wrap::unwrap(self.kek.expose(), &wrapped.wrapped, &wctx)?;
        Ok(SubjectKey {
            key: EphemeralKey::from_key(&key),
            domain_id: self.domain_id,
            subject_hmac: *subject_hmac,
            version: wrapped.version,
        })
    }
}

// --- Subject keys and data keys --------------------------------------------------------------------------

/// A subject key as a key store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedSubjectKey {
    /// The subject key's version, starting at 1.
    pub version: u32,
    /// The KEK version that wrapped it.
    pub kek_version: u32,
    /// The 107-byte wrapped key.
    pub wrapped: Vec<u8>,
}

/// A subject's key. Destroying its wrapped form makes every data key under it unreachable.
#[derive(Debug)]
pub struct SubjectKey {
    key: EphemeralKey,
    domain_id: Id,
    subject_hmac: [u8; 32],
    version: u32,
}

/// A data key as a key store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WrappedDek {
    /// The subject key version that wrapped it.
    pub subject_key_version: u32,
    /// The DEK generation, which increments when a fact is re-encrypted (FORMAT.md section 4).
    pub generation: u32,
    /// The 107-byte wrapped key.
    pub wrapped: Vec<u8>,
}

/// The key for one fact or blob object. Pass [`Dek::expose`] to `pvlt_format::fact` or `blob`.
#[derive(Debug)]
pub struct Dek {
    key: EphemeralKey,
    domain_id: Id,
    object_id: Id,
    generation: u32,
}

impl SubjectKey {
    /// The subject key's version.
    pub fn version(&self) -> u32 {
        self.version
    }

    /// Makes a data key for an object and wraps it under this subject key.
    pub fn new_dek(
        &self,
        object_id: &Id,
        generation: u32,
    ) -> Result<(Dek, WrappedDek), VaultError> {
        let key = EphemeralKey::random()?;
        let wctx = ctx::dek(
            &self.domain_id,
            &self.subject_hmac,
            self.version,
            object_id,
            generation,
        )?;
        let wrapped = WrappedDek {
            subject_key_version: self.version,
            generation,
            wrapped: wrap_child(&self.key, &wctx, &key)?,
        };
        Ok((
            Dek {
                key,
                domain_id: self.domain_id,
                object_id: *object_id,
                generation,
            },
            wrapped,
        ))
    }

    /// Opens an object's wrapped data key. A data key wrapped for another object, generation, subject or
    /// domain does not open.
    pub fn unwrap_dek(&self, object_id: &Id, wrapped: &WrappedDek) -> Result<Dek, VaultError> {
        if wrapped.subject_key_version != self.version {
            return Err(VaultError::Invalid(
                "data key was wrapped by a different subject key version",
            ));
        }
        let wctx = ctx::dek(
            &self.domain_id,
            &self.subject_hmac,
            self.version,
            object_id,
            wrapped.generation,
        )?;
        let key = wrap::unwrap(self.key.expose(), &wrapped.wrapped, &wctx)?;
        Ok(Dek {
            key: EphemeralKey::from_key(&key),
            domain_id: self.domain_id,
            object_id: *object_id,
            generation: wrapped.generation,
        })
    }
}

impl KeyMaterial for SubjectKey {
    fn expose(&self) -> &Key {
        self.key.expose()
    }
}

impl Dek {
    /// The domain the object belongs to. Pass it to the object header.
    pub fn domain_id(&self) -> &Id {
        &self.domain_id
    }

    /// The object this key is for.
    pub fn object_id(&self) -> &Id {
        &self.object_id
    }

    /// The DEK generation. Pass it to the object header.
    pub fn generation(&self) -> u32 {
        self.generation
    }
}

impl KeyMaterial for Dek {
    fn expose(&self) -> &Key {
        self.key.expose()
    }
}
