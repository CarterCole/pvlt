//! The running vault's key state: sealed, or unsealed with a root key and a cache of domain keys.
//!
//! There is deliberately no way to get a `DomainKeys` out of the keyring. [`Keyring::with_domain`] lends it to a
//! closure, and the closure runs while the keyring holds a read lock, so [`Keyring::seal`] (which needs the
//! write lock) waits for in-flight work and, once it returns, no key is left in memory, not even in a caller's
//! clone. The closures are synchronous on purpose: a key must not be held across an `.await`.
//!
//! The cache is only a way to skip three unwraps. It is checked against the wrapped bytes the caller read from
//! the key store in the same query (PLAN.md 3.2), so a domain whose keys were destroyed or rotated is never
//! served from the cache: the cached entry only matches if the key store still holds exactly the same bytes.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, PoisonError, RwLock, RwLockReadGuard};

use pvlt_format::Id;
use pvlt_format::wrap::SignPurpose;
use pvlt_mem::Arena;

use crate::VaultError;
use crate::keys::{DomainKeys, RootKey, WrappedDomainKeys, WrappedSigningKey};

struct Cached {
    wrapped: WrappedDomainKeys,
    keys: Arc<DomainKeys>,
}

struct Unsealed {
    root: RootKey,
    domains: Mutex<HashMap<Id, Cached>>,
}

/// The sealed or unsealed state of a vault. Starts sealed.
pub struct Keyring {
    arena: Arena,
    state: RwLock<Option<Unsealed>>,
}

impl core::fmt::Debug for Keyring {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keyring")
            .field("sealed", &self.is_sealed())
            .finish()
    }
}

impl Keyring {
    /// A sealed keyring. Domain keys are allocated from `arena`.
    pub fn new(arena: Arena) -> Self {
        Self {
            arena,
            state: RwLock::new(None),
        }
    }

    /// The arena that holds this keyring's keys.
    pub fn arena(&self) -> &Arena {
        &self.arena
    }

    fn read(&self) -> RwLockReadGuard<'_, Option<Unsealed>> {
        // A panic while holding the lock cannot leave this state half-updated, so carrying on is correct.
        self.state.read().unwrap_or_else(PoisonError::into_inner)
    }

    /// Whether no root key is loaded.
    pub fn is_sealed(&self) -> bool {
        self.read().is_none()
    }

    /// The id of the loaded root key, for `/readyz`.
    pub fn root_key_id(&self) -> Result<Id, VaultError> {
        Ok(*self.read().as_ref().ok_or(VaultError::Sealed)?.root.id())
    }

    /// Loads a root key, replacing any already loaded (and wiping it).
    pub fn unseal(&self, root: RootKey) {
        let fresh = Unsealed {
            root,
            domains: Mutex::new(HashMap::new()),
        };
        // Taking the old state out and dropping it after the lock is released keeps the wipe off the lock.
        let old = self
            .state
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .replace(fresh);
        drop(old);
    }

    /// Wipes the root key and every cached domain key. Waits for in-flight [`Keyring::with_domain`] calls to
    /// finish first. Returns whether the vault was unsealed.
    pub fn seal(&self) -> bool {
        let old = self
            .state
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .take();
        old.is_some()
    }

    /// Makes keys for a new domain, caches them, and returns the wrapped form for the key store to persist.
    pub fn create_domain(&self, domain_id: &Id) -> Result<WrappedDomainKeys, VaultError> {
        let state = self.read();
        let unsealed = state.as_ref().ok_or(VaultError::Sealed)?;
        let (keys, wrapped) = DomainKeys::create(&self.arena, &unsealed.root, domain_id)?;
        unsealed
            .domains
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(
                *domain_id,
                Cached {
                    wrapped: wrapped.clone(),
                    keys: Arc::new(keys),
                },
            );
        Ok(wrapped)
    }

    /// Makes a signing key for a domain and returns the wrapped form for the key store to persist.
    pub fn create_signing_key(
        &self,
        domain_id: &Id,
        purpose: SignPurpose,
    ) -> Result<WrappedSigningKey, VaultError> {
        let state = self.read();
        let unsealed = state.as_ref().ok_or(VaultError::Sealed)?;
        unsealed
            .root
            .new_signing_key(&self.arena, domain_id, purpose)
    }

    /// Signs a checkpoint with a domain's checkpoint key and returns the signature as hex.
    pub fn sign_checkpoint(
        &self,
        domain_id: &Id,
        key: &WrappedSigningKey,
        checkpoint: &serde_json::Value,
    ) -> Result<String, VaultError> {
        let state = self.read();
        let unsealed = state.as_ref().ok_or(VaultError::Sealed)?;
        unsealed
            .root
            .sign_checkpoint(&self.arena, domain_id, key, checkpoint)
    }

    /// Signs a ledger entry with a domain's signing key and returns the stored line. The seed is opened for the
    /// call and wiped when it returns.
    pub fn sign_ledger(
        &self,
        domain_id: &Id,
        key: &WrappedSigningKey,
        entry: &serde_json::Value,
    ) -> Result<Vec<u8>, VaultError> {
        let state = self.read();
        let unsealed = state.as_ref().ok_or(VaultError::Sealed)?;
        unsealed
            .root
            .sign_ledger(&self.arena, domain_id, key, entry)
    }

    /// Runs `f` with a domain's keys. `wrapped` is what the key store holds for the domain right now: if it is
    /// the cached bytes the cached keys are used, otherwise they are unwrapped (and cached if that works). A
    /// zeroed `wrapped` is [`VaultError::Shredded`] and also evicts the cache entry.
    ///
    /// `f` must be quick and must not call [`Keyring::seal`] or [`Keyring::unseal`] (it would deadlock).
    pub fn with_domain<R>(
        &self,
        domain_id: &Id,
        wrapped: &WrappedDomainKeys,
        f: impl FnOnce(&DomainKeys) -> Result<R, VaultError>,
    ) -> Result<R, VaultError> {
        let state = self.read();
        let unsealed = state.as_ref().ok_or(VaultError::Sealed)?;
        let keys = {
            let mut cache = unsealed
                .domains
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            match cache.get(domain_id) {
                Some(hit) if hit.wrapped == *wrapped => Arc::clone(&hit.keys),
                _ => match DomainKeys::unwrap(&self.arena, &unsealed.root, domain_id, wrapped) {
                    Ok(opened) => {
                        let keys = Arc::new(opened);
                        cache.insert(
                            *domain_id,
                            Cached {
                                wrapped: wrapped.clone(),
                                keys: Arc::clone(&keys),
                            },
                        );
                        keys
                    }
                    Err(e) => {
                        cache.remove(domain_id);
                        return Err(e);
                    }
                },
            }
        };
        let out = f(&keys);
        // Drop our handle while the read lock is still held, so that after `seal` returns none is left.
        drop(keys);
        out
    }
}
