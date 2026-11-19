//! State shared by every handler, and the unseal progress.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use crate::tokens::IssuerKeys;
use pvlt_core::VaultError;
use pvlt_core::audit::Auditor;
use pvlt_core::engine::Engine;
use pvlt_core::objects::ObjectStore;
use pvlt_core::seal::{SealConfig, SealMode, UnsealShare, unseal_with_shares};
use pvlt_core::store::{IssuerRecord, KeyStore};
use pvlt_format::Id;
use pvlt_policy::limits::RateLimiter;
use pvlt_policy::policy::Policy;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::error::ApiError;

/// The most shares held at once. A share has a number from 1 to 255, so this cannot be reached by valid ones.
const MAX_PENDING: usize = 255;

/// A token, kept as its SHA-256 so that comparing it takes the same time whatever the input's length.
#[derive(Clone, Copy)]
pub struct Token([u8; 32]);

impl Token {
    /// Hashes a token.
    pub fn new(token: &str) -> Self {
        Self(Sha256::digest(token.as_bytes()).into())
    }

    /// Whether `presented` is this token. Constant time.
    pub fn matches(&self, presented: &str) -> bool {
        let theirs: [u8; 32] = Sha256::digest(presented.as_bytes()).into();
        bool::from(self.0.ct_eq(&theirs))
    }
}

impl core::fmt::Debug for Token {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Token(..)")
    }
}

/// A named administrator. Two different names are what dual control means.
#[derive(Debug, Clone)]
pub struct Admin {
    /// The name that appears in audit entries and approvals.
    pub name: String,
    /// The credential.
    pub token: Token,
}

/// The registered issuers and the policy in force, loaded from the key store. Held behind an `Arc` and swapped
/// whole, so a request sees one consistent version of both.
#[derive(Debug, Default)]
pub struct Access {
    /// Enabled issuers by root key id, with the roles each may assert.
    pub issuers: HashMap<u32, IssuerRecord>,
    /// The policy. Empty (deny everything on `/v2`) until an admin sets one.
    pub policy: Policy,
    /// Its version and hash, 0 and zeros if none was ever set.
    pub policy_version: i64,
    /// The policy's hash.
    pub policy_hash: [u8; 32],
}

impl IssuerKeys for Access {
    fn public_key(&self, key_id: u32) -> Option<[u8; 32]> {
        self.issuers
            .get(&key_id)
            .filter(|i| i.enabled)
            .map(|i| i.public_key)
    }
}

/// Where unsealing stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UnsealStatus {
    /// Whether the vault is still sealed.
    pub sealed: bool,
    /// Shares needed.
    pub threshold: u8,
    /// Distinct shares received so far. Zero once unsealed.
    pub submitted: usize,
}

/// Everything a handler needs.
pub struct App<K, O, A> {
    /// The engine.
    pub engine: Engine<K, O, A>,
    /// The domain the compat token maps to.
    pub domain: Id,
    /// The static token for `/api/v1`. `None` disables those routes.
    pub compat_token: Option<Token>,
    /// How the root key is sealed.
    pub seal_config: SealConfig,
    /// Named administrators. Empty means the admin routes refuse everything but unseal.
    pub admins: Vec<Admin>,
    /// The longest a request token may live, in seconds.
    pub max_token_ttl: i64,
    /// Whether one admin may approve their own emergency read.
    pub break_glass: bool,
    /// Per-caller rate limits.
    pub limiter: RateLimiter,
    /// The largest blob, in plaintext bytes. Also bounds a proxied upload.
    pub max_blob_bytes: u64,
    /// How long a presigned upload or download address lives.
    pub presign_ttl: std::time::Duration,
    access: RwLock<Arc<Access>>,
    shares: Mutex<Vec<UnsealShare>>,
    domain_ready: AtomicBool,
}

impl<K: KeyStore, O: ObjectStore, A: Auditor> App<K, O, A> {
    /// Builds the state.
    pub fn new(
        engine: Engine<K, O, A>,
        domain: Id,
        compat_token: Option<Token>,
        admin_token: Option<Token>,
        seal_config: SealConfig,
    ) -> Self {
        Self {
            engine,
            domain,
            compat_token,
            seal_config,
            admins: admin_token
                .map(|token| {
                    vec![Admin {
                        name: "admin".to_owned(),
                        token,
                    }]
                })
                .unwrap_or_default(),
            max_token_ttl: 300,
            break_glass: false,
            limiter: RateLimiter::default(),
            max_blob_bytes: pvlt_core::engine::DEFAULT_MAX_BLOB_LEN,
            presign_ttl: std::time::Duration::from_secs(900),
            access: RwLock::new(Arc::new(Access::default())),
            shares: Mutex::new(Vec::new()),
            domain_ready: AtomicBool::new(false),
        }
    }

    /// Names the administrators. A `None` admin token given to [`App::new`] is replaced by these.
    pub fn with_admins(mut self, admins: Vec<Admin>) -> Self {
        self.admins = admins;
        self
    }

    /// Sets the longest request-token lifetime and whether break-glass approvals are allowed.
    pub fn with_access_limits(mut self, max_token_ttl: i64, break_glass: bool) -> Self {
        self.max_token_ttl = max_token_ttl;
        self.break_glass = break_glass;
        self
    }

    /// Sets the largest blob and how long a presigned address lives. The engine has its own limit: set both.
    pub fn with_blob_limits(
        mut self,
        max_blob_bytes: u64,
        presign_ttl: std::time::Duration,
    ) -> Self {
        self.max_blob_bytes = max_blob_bytes;
        self.presign_ttl = presign_ttl;
        self
    }

    /// The issuers and policy in force right now.
    pub fn access(&self) -> Arc<Access> {
        Arc::clone(&self.access.read().unwrap_or_else(PoisonError::into_inner))
    }

    /// Reads issuers and the current policy from the key store and swaps them in. Called at start, after an
    /// admin changes either, and periodically so other replicas converge. A policy that is stored but no longer
    /// parses is an error and is **not** swapped in: the previous policy stays.
    pub async fn reload_access(&self) -> Result<(), VaultError> {
        let issuers = self.engine.store().issuers().await?;
        let (policy, version, hash) = match self.engine.store().current_policy().await? {
            Some(rec) => (
                Policy::from_json(&rec.json)
                    .map_err(|_| VaultError::Integrity("the stored policy does not parse"))?,
                rec.version,
                rec.hash,
            ),
            None => (Policy::default(), 0, [0; 32]),
        };
        let fresh = Access {
            issuers: issuers.into_iter().map(|i| (i.key_id, i)).collect(),
            policy,
            policy_version: version,
            policy_hash: hash,
        };
        *self.access.write().unwrap_or_else(PoisonError::into_inner) = Arc::new(fresh);
        Ok(())
    }

    /// The admin whose credential this is, if any.
    pub fn admin_named_by(&self, presented: &str) -> Option<&Admin> {
        // Check every admin so the time taken does not say which one matched.
        let mut found = None;
        for a in &self.admins {
            if a.token.matches(presented) && found.is_none() {
                found = Some(a);
            }
        }
        found
    }

    /// Makes sure the compat domain exists. After the first success it is a no-op.
    pub async fn ensure_domain(&self) -> Result<(), VaultError> {
        if self.domain_ready.load(Ordering::Acquire) {
            return Ok(());
        }
        self.engine.ensure_domain(&self.domain).await?;
        self.domain_ready.store(true, Ordering::Release);
        Ok(())
    }

    fn threshold(&self) -> u8 {
        match &self.seal_config.mode {
            SealMode::Shamir { threshold, .. } => *threshold,
            _ => 0,
        }
    }

    /// The current unseal progress.
    pub fn unseal_status(&self) -> UnsealStatus {
        UnsealStatus {
            sealed: self.engine.keyring().is_sealed(),
            threshold: self.threshold(),
            submitted: self
                .shares
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .len(),
        }
    }

    /// Takes one share. When enough distinct shares have arrived it tries to unseal, and whatever the outcome
    /// it forgets them, so a wrong batch cannot be topped up one share at a time.
    pub fn submit_share(&self, text: &str) -> Result<UnsealStatus, ApiError> {
        if !self.engine.keyring().is_sealed() {
            return Ok(self.unseal_status());
        }
        if self.threshold() == 0 {
            return Err(ApiError::BadRequest("this vault is not sealed with shares"));
        }
        let share = UnsealShare::from_text(text)?;
        let info = share.info()?;
        if info.root_key_id != self.seal_config.root.id {
            return Err(ApiError::BadRequest("share is for a different vault"));
        }
        if info.threshold != self.threshold() {
            return Err(ApiError::BadRequest("share does not match this vault"));
        }
        let mut held = self.shares.lock().unwrap_or_else(PoisonError::into_inner);
        let mut have = Vec::with_capacity(held.len());
        for s in held.iter() {
            have.push(s.info()?.index);
        }
        if !have.contains(&info.index) && held.len() < MAX_PENDING {
            held.push(share);
        }
        let batch = if held.len() >= usize::from(self.threshold()) {
            Some(core::mem::take(&mut *held))
        } else {
            None
        };
        // Release the lock before anything else: `unseal_status` takes it too, and it is not reentrant.
        drop(held);
        if let Some(batch) = batch {
            let root =
                unseal_with_shares(self.engine.keyring().arena(), &self.seal_config, &batch)?;
            self.engine.keyring().unseal(root);
        }
        Ok(self.unseal_status())
    }

    /// Seals the vault: wipes the root key and every cached domain key, and forgets pending shares.
    pub fn seal(&self) {
        self.shares
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
        self.engine.keyring().seal();
    }
}
