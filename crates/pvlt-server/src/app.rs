//! State shared by every handler, and the unseal progress.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, PoisonError, RwLock};

use crate::tokens::IssuerKeys;
use pvlt_core::VaultError;
use pvlt_core::audit::Auditor;
use pvlt_core::engine::Engine;
use pvlt_core::objects::ObjectStore;
use pvlt_core::seal::{
    SealConfig, SealMode, UnsealKey, UnsealShare, unseal_with_key, unseal_with_shares,
};
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

/// GDPR mode (`PVLT_GDPR_MODE`): routes that answer a data subject's rights of access and portability (art. 15,
/// art. 20). Erasure (art. 17) is always available as a subject shred. Off by default. The parts that disclose
/// more than a normal read can each be turned off on their own.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GdprMode {
    /// Whether the GDPR routes are served at all.
    pub enabled: bool,
    /// `POST /v2/subject/export`: every readable value of one subject in a single response
    /// (`PVLT_GDPR_EXPORT`, default on). A stolen self token then gets everything at once, not one fact at a
    /// time, so a deployment that answers portability requests some other way can turn it off.
    pub export: bool,
    /// `POST /v2/admin/subject/facts`: lets an admin list a subject's facts, without values
    /// (`PVLT_GDPR_ADMIN_INVENTORY`, default on). An admin otherwise cannot tell which facts belong to whom.
    pub admin_inventory: bool,
}

impl GdprMode {
    /// Everything on.
    pub fn on() -> Self {
        Self {
            enabled: true,
            export: true,
            admin_inventory: true,
        }
    }

    /// Whether the export route is served.
    pub fn export_enabled(&self) -> bool {
        self.enabled && self.export
    }

    /// Whether the admin inventory route is served.
    pub fn admin_inventory_enabled(&self) -> bool {
        self.enabled && self.admin_inventory
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
    /// Which GDPR routes are served.
    pub gdpr: GdprMode,
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
            gdpr: GdprMode::default(),
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

    /// Whether changes to who may do what (policy, issuers) need a second admin. They do whenever there are two
    /// admins to ask; with one, that admin's word is all there is, and the server says so at start.
    pub fn changes_need_two_admins(&self) -> bool {
        self.admins.len() >= 2
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

    /// Sets which GDPR routes are served. Routers built after this see it.
    pub fn with_gdpr(mut self, gdpr: GdprMode) -> Self {
        self.gdpr = gdpr;
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
    ///
    /// A vault initialised with share checks refuses a share that is not the one dealt under its number the
    /// moment it arrives, so nobody who can reach this route can spoil an unseal by sending a forged share first.
    /// For an older vault without checks, a second, different share under a number already held is refused
    /// loudly instead of being dropped, so the holder of the real one finds out at once.
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
        pvlt_core::seal::check_share(&self.seal_config, &share)?;
        let mut held = self.shares.lock().unwrap_or_else(PoisonError::into_inner);
        let mut same_number = None;
        for s in held.iter() {
            if s.info()?.index == info.index {
                same_number = Some(s.to_text());
            }
        }
        match same_number {
            None if held.len() < MAX_PENDING => held.push(share),
            None => {}
            Some(previous)
                if !bool::from(previous.as_bytes().ct_eq(share.to_text().as_bytes())) =>
            {
                return Err(ApiError::Vault(VaultError::Conflict(
                    "a different share with this number was already submitted; seal the vault to clear \
                     pending shares and start again",
                )));
            }
            // The same share again: it is already held.
            Some(_) => {}
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

    /// Unseals with an unseal key a KMS returned (auto-unseal). A key that does not open the root key is an
    /// error and leaves the vault sealed.
    pub fn unseal_with_key(&self, key: &UnsealKey) -> Result<(), VaultError> {
        let root = unseal_with_key(self.engine.keyring().arena(), &self.seal_config, key)?;
        self.engine.keyring().unseal(root);
        Ok(())
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
