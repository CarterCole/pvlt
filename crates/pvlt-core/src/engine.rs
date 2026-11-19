//! The engine: create, read and shred facts over a key store and an object store (PLAN.md 3.3).
//!
//! Every method follows the same shape, which is what keeps keys out of futures (PLAN.md 3.1): fetch rows with
//! `.await`, then do **all** the key work in one synchronous closure, then `.await` again. No subject key or
//! data key exists while a future is suspended.
//!
//! Ordering, from the key store's guarantees:
//!
//! * **Create** seals the value, writes the object, then inserts the row. A crash or a lost race leaves an
//!   object nobody holds a key for; [`Engine::sweep_orphans`] removes it. The row is what makes a fact exist,
//!   so a fact is never visible without its object, and an object without a row is never readable.
//! * **Read** takes the fact, its subject key and its domain from one snapshot, so it cannot combine a key
//!   from before a shred with a fact from after it.
//! * **Shred** is a key-store write. It is complete when that returns. Deleting the object follows and is best
//!   effort, because without the key the object is noise anyway.
//!
//! **Not yet here** (PLAN.md M2 to M4): the shred ledger, so a shred does not survive restoring an older key
//! store; policy and delegated tokens; the durable audit log.

use core::time::Duration;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Mutex, PoisonError};
use std::time::Instant;

use pvlt_format::Suite;
use pvlt_format::blob::{self as blobfmt, BlobReader};
use pvlt_format::fact::{self, MAX_VALUE_LEN};
use pvlt_format::wrap::SignPurpose;
use pvlt_format::{ID_LEN, Id};
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::VaultError;
use crate::audit::{Action, AuditEvent, Auditor};
pub use crate::audit_log::Caller;
use crate::audit_log::{self, CheckpointLog, Item, Kind};
use crate::keyring::Keyring;
use crate::keys::KeyMaterial;
use crate::ledger::{self, Effect, Entry, Reason};
use crate::objects::{ObjectError, ObjectKey, ObjectStore};
use crate::rng;
use crate::store::{
    AuditAppend, AuditFilter, AuditRecord, Destroyed, DomainRecord, DueFact, FactId, FactKind,
    KeyStore, LedgerAppend, NewFact, NewSubjectKey, ReplayEffect, ShredFact, ShredPlan,
    ShredSubject, State, StoreError,
};

/// The largest blob accepted by default: 256 MiB.
pub const DEFAULT_MAX_BLOB_LEN: u64 = 256 * 1024 * 1024;

/// How long a blob that was created but not completed lives before the retention sweeper shreds it.
pub const BLOB_PENDING_TTL: Duration = Duration::from_secs(24 * 3600);

/// The most facts one atomic create may hold.
pub const MAX_BATCH: usize = 16;

/// What the key store says about a fact, without opening it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactMeta {
    /// The fact type.
    pub fact_type: String,
    /// The subject's blind identifier.
    pub subject_hmac: [u8; 32],
    /// The scope's blind identifier.
    pub scope_hmac: [u8; 32],
    /// Whether the fact can still be read: shredded if the fact, its subject or its domain was.
    pub state: State,
}

/// Longest fact type slug, in bytes.
pub const MAX_FACT_TYPE_LEN: usize = 64;

/// The longest subject, in bytes. Subjects are opaque ids like `user:123`; this only stops abuse.
pub const MAX_SUBJECT_LEN: usize = 256;

/// How many times a shred re-reads and retries when the ledger moves under it. Shreds of one domain take turns,
/// and every round one of them wins, so a burst of N concurrent shreds needs up to N rounds. Shreds are rare, so
/// the quadratic work in a burst is accepted.
const MAX_ATTEMPTS: usize = 256;

/// What a shred is aimed at.
enum Target<'a> {
    Fact(&'a FactId),
    Scope(&'a str),
    Subject(&'a str),
    Domain,
    Expired(u32),
}

enum Outcome {
    Done(Destroyed),
    AlreadyShredded,
    NothingFound,
}

enum Prepared {
    Skip(Outcome),
    Plan(ShredPlan, Effect),
}

/// What startup reconciliation did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct ReconcileReport {
    /// Domains looked at.
    pub domains: usize,
    /// Ledger entries replayed from the bucket into the key store.
    pub replayed: usize,
    /// Ledger entries written to the bucket that the key store had and the bucket lacked.
    pub republished: usize,
}

/// How many ids one sweeper query asks the key store about.
const SWEEP_BATCH: usize = 500;

fn object_error(_: ObjectError) -> VaultError {
    VaultError::Unavailable("object store")
}

/// A fact to create.
#[derive(Debug, Clone)]
pub struct CreateFact<'a> {
    /// The id to give it. `None` makes a random UUID. An admin import supplies one (REQUIREMENTS C3).
    pub fact_id: Option<FactId>,
    /// Who the fact is about. `None` files it under a pseudo-subject made from the scope, so that shredding
    /// the scope still destroys one key, and shredding a subject does **not** cover it (REQUIREMENTS C4).
    pub subject: Option<&'a str>,
    /// The scope, a free-form string.
    pub scope: &'a str,
    /// The fact type slug, 1 to 64 bytes. The caller validates the value against it.
    pub fact_type: &'a str,
    /// The value.
    pub value: &'a [u8],
    /// When the fact expires, if it does. A read after that is refused.
    pub expires_at: Option<OffsetDateTime>,
}

/// A fact that was read.
#[derive(Debug)]
pub struct FactValue {
    /// The fact's id.
    pub fact_id: FactId,
    /// Its type slug.
    pub fact_type: String,
    /// The value, wiped when dropped.
    pub value: Zeroizing<Vec<u8>>,
}

/// What a sweep did.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    /// Objects in the domain's prefix.
    pub listed: usize,
    /// Objects younger than the grace period, left alone.
    pub too_young: usize,
    /// Objects that belong to a readable fact, left alone.
    pub live: usize,
    /// Objects deleted.
    pub deleted: usize,
    /// Objects that should have been deleted and could not be.
    pub failed: usize,
}

/// Limits the engine enforces.
#[derive(Debug, Clone, Copy)]
pub struct Limits {
    /// The longest value accepted, in bytes. At most [`MAX_VALUE_LEN`].
    pub max_value_len: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_value_len: MAX_VALUE_LEN,
        }
    }
}

/// The engine.
pub struct Engine<K, O, A> {
    keyring: Keyring,
    store: K,
    objects: O,
    auditor: A,
    limits: Limits,
    audit_queue: Mutex<VecDeque<PendingAudit>>,
    audit_leading: AtomicBool,
    audit_blocked: AtomicBool,
    checkpointed: Mutex<HashMap<(Id, u8), Checkpointed>>,
    checkpoint_entries: u64,
    checkpoint_every: Duration,
    max_blob_len: u64,
}

/// The newest checkpoint written for a log: its sequence number, the head hash it named, and when.
type Checkpointed = (u64, [u8; 32], Instant);

/// An audit entry waiting for the next group commit, and the way to tell its caller how it went.
struct PendingAudit {
    domain_id: Id,
    item: Item,
    done: futures_channel::oneshot::Sender<Result<(), VaultError>>,
}

/// Clears the "a task is writing a batch" flag when that task finishes or is dropped, so a client that
/// disconnects mid-commit cannot leave the log without a writer.
struct LeaderGuard<'a>(&'a AtomicBool);

impl Drop for LeaderGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl<K, O, A> core::fmt::Debug for Engine<K, O, A> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Engine")
            .field("keyring", &self.keyring)
            .finish_non_exhaustive()
    }
}

impl<K: KeyStore, O: ObjectStore, A: Auditor> Engine<K, O, A> {
    /// An engine over a keyring (sealed or not), a key store, an object store and an auditor.
    pub fn new(keyring: Keyring, store: K, objects: O, auditor: A, limits: Limits) -> Self {
        Self {
            keyring,
            store,
            objects,
            auditor,
            limits: Limits {
                max_value_len: limits.max_value_len.min(MAX_VALUE_LEN),
            },
            audit_queue: Mutex::new(VecDeque::new()),
            audit_leading: AtomicBool::new(false),
            audit_blocked: AtomicBool::new(false),
            checkpointed: Mutex::new(HashMap::new()),
            checkpoint_entries: CHECKPOINT_ENTRIES,
            checkpoint_every: CHECKPOINT_EVERY,
            max_blob_len: DEFAULT_MAX_BLOB_LEN,
        }
    }

    /// Sets the largest blob (plaintext bytes) a client may declare.
    #[must_use]
    pub fn with_max_blob_len(mut self, bytes: u64) -> Self {
        self.max_blob_len = bytes;
        self
    }

    /// Changes when checkpoints are written: after this many new entries, or after this long with any new one.
    /// The defaults are FORMAT.md's 1000 entries and 60 seconds; tests use smaller ones.
    #[must_use]
    pub fn with_checkpoint_policy(mut self, entries: u64, every: Duration) -> Self {
        self.checkpoint_entries = entries;
        self.checkpoint_every = every;
        self
    }

    /// The keyring, for unsealing and sealing.
    pub fn keyring(&self) -> &Keyring {
        &self.keyring
    }

    /// The key store.
    pub fn store(&self) -> &K {
        &self.store
    }

    /// The object store.
    pub fn objects(&self) -> &O {
        &self.objects
    }

    /// Reports an event the engine did not itself produce, such as a policy denial decided in the server.
    pub fn report(
        &self,
        principal: &str,
        action: Action,
        fact_id: Option<FactId>,
        outcome: &'static str,
    ) {
        self.auditor.record(&AuditEvent {
            principal,
            action,
            fact_id,
            outcome,
        });
    }

    fn audit(
        &self,
        principal: &str,
        action: Action,
        fact_id: Option<FactId>,
        result: &Result<impl Sized, VaultError>,
    ) {
        self.auditor.record(&AuditEvent {
            principal,
            action,
            fact_id,
            outcome: match result {
                Ok(_) => "ok",
                Err(e) => e.code(),
            },
        });
    }

    /// Makes sure a domain exists, creating its keys and its ledger signing key if it does not, and returns it.
    /// Needs the vault unsealed only when it has to create something. Safe to call from many tasks: one wins and
    /// the rest read what it stored.
    pub async fn ensure_domain(&self, domain_id: &Id) -> Result<DomainRecord, VaultError> {
        let domain = match self.store.domain(domain_id).await {
            Ok(domain) => domain,
            Err(StoreError::NotFound) => {
                let wrapped = self.keyring.create_domain(domain_id)?;
                match self.store.create_domain(domain_id, &wrapped).await {
                    Ok(()) | Err(StoreError::AlreadyExists) => self.store.domain(domain_id).await?,
                    Err(e) => return Err(e.into()),
                }
            }
            Err(e) => return Err(e.into()),
        };
        if domain.state == State::Active {
            for purpose in [SignPurpose::Ledger, SignPurpose::Checkpoint] {
                if self.store.sign_key(domain_id, purpose).await?.is_none() {
                    let key = self.keyring.create_signing_key(domain_id, purpose)?;
                    self.store.get_or_insert_sign_key(domain_id, &key).await?;
                }
            }
        }
        Ok(domain)
    }

    /// Creates a fact and returns its id.
    pub async fn create_fact(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        request: &CreateFact<'_>,
    ) -> Result<FactId, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let fact_id = request.fact_id;
        let result = self.create_fact_inner(domain_id, request).await;
        self.audit(
            principal,
            Action::Create,
            result.as_ref().ok().map(|(id, _)| *id).or(fact_id),
            &result,
        );
        let (id, subject) = result?;
        self.audit_after(
            domain_id,
            Kind::Create,
            &caller,
            "create",
            Some(id),
            Some(subject),
        )
        .await;
        Ok(id)
    }

    /// Checks a request, makes (or finds) its subject key, and seals its value. Writes nothing to the bucket.
    async fn seal_new(
        &self,
        domain_id: &Id,
        domain: &DomainRecord,
        request: &CreateFact<'_>,
    ) -> Result<(NewFact, Vec<u8>), VaultError> {
        if request.value.len() > self.limits.max_value_len {
            return Err(VaultError::Invalid("value too long"));
        }
        if request.scope.is_empty() {
            return Err(VaultError::Invalid("scope is empty"));
        }
        if request.subject.is_some_and(str::is_empty) {
            return Err(VaultError::Invalid("subject is empty"));
        }
        if request.subject.is_some_and(|s| s.len() > MAX_SUBJECT_LEN) {
            return Err(VaultError::Invalid("subject too long"));
        }
        let type_len = request.fact_type.len();
        if type_len == 0 || type_len > MAX_FACT_TYPE_LEN {
            return Err(VaultError::Invalid("fact type length"));
        }
        let size_class = fact::size_class(request.value.len())
            .and_then(|c| u32::try_from(c).ok())
            .ok_or(VaultError::Invalid("value too long"))?;

        // Step 1 (sync): the blind identifiers, and a candidate subject key in case this subject is new.
        let (subject_hmac, scope_hmac, bik_version, candidate) =
            self.keyring.with_domain(domain_id, &domain.keys, |dk| {
                let subject_hmac = match request.subject {
                    Some(subject) => dk.subject_hmac(subject)?,
                    None => dk.pseudo_subject_hmac(request.scope)?,
                };
                let scope_hmac = dk.scope_hmac(request.scope)?;
                let (_key, wrapped) = dk.new_subject_key(&subject_hmac, 1)?;
                Ok((
                    subject_hmac,
                    scope_hmac,
                    dk.bik_version(),
                    NewSubjectKey {
                        domain_id: *domain_id,
                        subject_hmac,
                        bik_version: dk.bik_version(),
                        key: wrapped,
                    },
                ))
            })?;

        // Step 2 (async): the subject's key, whoever made it first.
        let subject = self.store.get_or_insert_subject_key(&candidate).await?;
        if subject.state == State::Shredded {
            return Err(VaultError::Shredded);
        }

        // Step 3 (sync): open the subject key, make the data key, seal the value.
        let object_id = rng::id()?;
        let salt = rng::salt()?;
        let (object, dek) = self.keyring.with_domain(domain_id, &domain.keys, |dk| {
            let subject_key = dk.unwrap_subject_key(&subject_hmac, &subject.key)?;
            let (dek, wrapped) = subject_key.new_dek(&object_id, 0)?;
            let object = fact::seal(
                dek.expose(),
                Suite::XChaCha20Poly1305,
                domain_id,
                &object_id,
                dek.generation(),
                &salt,
                request.value,
            )?;
            Ok((object, wrapped))
        })?;
        let fact_id = match request.fact_id {
            Some(id) => id,
            None => random_uuid()?,
        };
        Ok((
            NewFact {
                domain_id: *domain_id,
                fact_id,
                subject_hmac,
                bik_version,
                scope_hmac,
                fact_type: request.fact_type.to_owned(),
                object_id,
                size_class,
                dek,
                expires_at: request.expires_at,
                legal_hold: false,
            },
            object,
        ))
    }

    async fn create_fact_inner(
        &self,
        domain_id: &Id,
        request: &CreateFact<'_>,
    ) -> Result<(FactId, [u8; 32]), VaultError> {
        let domain = self.store.domain(domain_id).await?;
        if domain.state == State::Shredded {
            return Err(VaultError::Shredded);
        }
        let (new, object) = self.seal_new(domain_id, &domain, request).await?;
        // Step 4 (async): the object, then the row that makes the fact exist.
        let key = ObjectKey {
            domain_id: *domain_id,
            object_id: new.object_id,
        };
        self.objects.put(&key, object).await.map_err(object_error)?;
        if let Err(e) = self.store.insert_fact(&new).await {
            // Best effort: if this fails the sweeper finds the object.
            let _ = self.objects.delete(&key).await;
            return Err(e.into());
        }
        Ok((new.fact_id, new.subject_hmac))
    }

    /// Creates several facts atomically (REQUIREMENTS F7): every one is stored or none is, so a caller never
    /// leaves half a record, such as a document's key without its path. Returns the ids in request order.
    pub async fn create_facts(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        requests: &[CreateFact<'_>],
    ) -> Result<Vec<FactId>, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let result = self.create_facts_inner(domain_id, requests).await;
        let first = result
            .as_ref()
            .ok()
            .and_then(|v| v.first().map(|(id, _)| *id));
        self.audit(principal, Action::Create, first, &result);
        let created = result?;
        for (id, subject) in &created {
            self.audit_after(
                domain_id,
                Kind::Create,
                &caller,
                "create",
                Some(*id),
                Some(*subject),
            )
            .await;
        }
        Ok(created.into_iter().map(|(id, _)| id).collect())
    }

    async fn create_facts_inner(
        &self,
        domain_id: &Id,
        requests: &[CreateFact<'_>],
    ) -> Result<Vec<(FactId, [u8; 32])>, VaultError> {
        if requests.is_empty() {
            return Err(VaultError::Invalid("a batch needs at least one fact"));
        }
        if requests.len() > MAX_BATCH {
            return Err(VaultError::Invalid("too many facts in one batch"));
        }
        let domain = self.store.domain(domain_id).await?;
        if domain.state == State::Shredded {
            return Err(VaultError::Shredded);
        }
        let mut sealed = Vec::with_capacity(requests.len());
        for request in requests {
            sealed.push(self.seal_new(domain_id, &domain, request).await?);
        }
        let mut written: Vec<ObjectKey> = Vec::with_capacity(sealed.len());
        for (new, object) in &sealed {
            let key = ObjectKey {
                domain_id: *domain_id,
                object_id: new.object_id,
            };
            if let Err(e) = self.objects.put(&key, object.clone()).await {
                for k in &written {
                    let _ = self.objects.delete(k).await;
                }
                return Err(object_error(e));
            }
            written.push(key);
        }
        let facts: Vec<NewFact> = sealed.into_iter().map(|(n, _)| n).collect();
        if let Err(e) = self.store.insert_facts(&facts).await {
            for k in &written {
                let _ = self.objects.delete(k).await;
            }
            return Err(e.into());
        }
        Ok(facts
            .into_iter()
            .map(|f| (f.fact_id, f.subject_hmac))
            .collect())
    }

    /// What is known about a fact without opening it: its type and blind identifiers, from the key store.
    /// A shredded fact is returned, with [`State::Shredded`]. Reads nothing from the bucket.
    pub async fn fact_meta(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
    ) -> Result<FactMeta, VaultError> {
        let b = self.store.fact_for_read(domain_id, fact_id).await?;
        Ok(FactMeta {
            fact_type: b.fact.fact.fact_type,
            subject_hmac: b.fact.fact.subject_hmac,
            scope_hmac: b.fact.fact.scope_hmac,
            state: if b.fact.state == State::Shredded
                || b.subject_key.state == State::Shredded
                || b.domain.state == State::Shredded
            {
                State::Shredded
            } else {
                State::Active
            },
        })
    }

    /// The blind identifier of a subject in a domain.
    pub async fn subject_hmac(
        &self,
        domain_id: &Id,
        subject: &str,
    ) -> Result<[u8; 32], VaultError> {
        let domain = self.store.domain(domain_id).await?;
        self.keyring
            .with_domain(domain_id, &domain.keys, |dk| dk.subject_hmac(subject))
    }

    /// The blind identifier of a scope in a domain.
    pub async fn scope_hmac(&self, domain_id: &Id, scope: &str) -> Result<[u8; 32], VaultError> {
        let domain = self.store.domain(domain_id).await?;
        self.keyring
            .with_domain(domain_id, &domain.keys, |dk| dk.scope_hmac(scope))
    }

    /// Uses a dual-control approval, once, for reading this fact. [`VaultError::Conflict`] if it is not a valid
    /// approval for it.
    pub async fn consume_approval(
        &self,
        domain_id: &Id,
        approval_id: &Uuid,
        fact_id: &FactId,
    ) -> Result<(), VaultError> {
        Ok(self
            .store
            .consume_approval(domain_id, approval_id, fact_id, OffsetDateTime::now_utc())
            .await?)
    }

    /// Reads a fact. A shredded fact is [`VaultError::Shredded`], which is permanent and different from
    /// [`VaultError::NotFound`]. An expired fact is [`VaultError::NotFound`].
    pub async fn read_fact(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        fact_id: &FactId,
    ) -> Result<FactValue, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let result = self.read_fact_inner(&caller, domain_id, fact_id).await;
        self.audit(principal, Action::Read, Some(*fact_id), &result);
        result
    }

    async fn read_fact_inner(
        &self,
        caller: &Caller<'_>,
        domain_id: &Id,
        fact_id: &FactId,
    ) -> Result<FactValue, VaultError> {
        if self.audit_blocked() {
            return Err(VaultError::Unavailable("the audit log needs attention"));
        }
        let bundle = self.store.fact_for_read(domain_id, fact_id).await?;
        if bundle.domain.state == State::Shredded
            || bundle.subject_key.state == State::Shredded
            || bundle.fact.state == State::Shredded
        {
            return Err(VaultError::Shredded);
        }
        if bundle.fact.kind == FactKind::Blob {
            return Err(VaultError::Conflict("this is a blob: use the blob routes"));
        }
        if bundle
            .fact
            .fact
            .expires_at
            .is_some_and(|t| t <= OffsetDateTime::now_utc())
        {
            return Err(VaultError::NotFound);
        }
        let fact = &bundle.fact.fact;
        let key = ObjectKey {
            domain_id: *domain_id,
            object_id: fact.object_id,
        };
        let object = self
            .objects
            .get(&key)
            .await
            .map_err(object_error)?
            .ok_or(VaultError::Unavailable("object is missing from the bucket"))?;

        // The disclosure is written down, durably, before the value is opened. If it cannot be, the read does
        // not happen: the vault never reveals what it cannot account for.
        self.audit_event(
            domain_id,
            Kind::ReadGrant,
            caller,
            "read",
            Some(*fact_id),
            Some(fact.subject_hmac),
            None,
        )
        .await
        .map_err(|_| VaultError::Unavailable("audit log"))?;

        let opened = self
            .keyring
            .with_domain(domain_id, &bundle.domain.keys, |dk| {
                let subject_key =
                    dk.unwrap_subject_key(&fact.subject_hmac, &bundle.subject_key.key)?;
                let dek = subject_key.unwrap_dek(&fact.object_id, &fact.dek)?;
                Ok(fact::open(dek.expose(), &object)?)
            });
        let value = match opened {
            Ok(v) => v,
            Err(e) => {
                // The grant stands; say that it did not end in a disclosure.
                self.audit_after(
                    domain_id,
                    Kind::ReadFail,
                    caller,
                    "read",
                    Some(*fact_id),
                    Some(fact.subject_hmac),
                )
                .await;
                return Err(e);
            }
        };
        Ok(FactValue {
            fact_id: *fact_id,
            fact_type: fact.fact_type.clone(),
            value,
        })
    }

    // --- Shredding ---------------------------------------------------------------------------------------

    /// Shreds a fact. Succeeds if it is already shredded or never existed (REQUIREMENTS F3). A fact under
    /// legal hold is [`VaultError::Conflict`]. Needs the vault unsealed, to sign the ledger entry.
    pub async fn shred_fact(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        fact_id: &FactId,
        reason: Reason,
    ) -> Result<ShredFact, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        // The subject is looked up first, because after the shred the entry would like to name it.
        let subject = self
            .fact_meta(domain_id, fact_id)
            .await
            .ok()
            .map(|m| m.subject_hmac);
        let result = self
            .run_shred(domain_id, reason, Target::Fact(fact_id))
            .await
            .map(|o| match o {
                Outcome::Done(d) => ShredFact::Shredded {
                    object_id: d.object_ids.first().copied().unwrap_or([0; 16]),
                },
                Outcome::AlreadyShredded => ShredFact::AlreadyShredded,
                Outcome::NothingFound => ShredFact::NotFound,
            });
        self.audit(principal, Action::ShredFact, Some(*fact_id), &result);
        if matches!(result, Ok(ShredFact::Shredded { .. })) {
            self.audit_after(
                domain_id,
                Kind::Shred,
                &caller,
                "shred.fact",
                Some(*fact_id),
                subject,
            )
            .await;
        }
        result
    }

    /// Shreds a subject: every fact filed under it becomes unreadable at once, and their objects are deleted.
    pub async fn shred_subject(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        subject: &str,
        reason: Reason,
    ) -> Result<ShredSubject, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        if subject.is_empty() || subject.len() > MAX_SUBJECT_LEN {
            return Err(VaultError::Invalid("subject is empty or too long"));
        }
        let result = self
            .run_shred(domain_id, reason, Target::Subject(subject))
            .await
            .map(|o| match o {
                Outcome::Done(_) => ShredSubject::Shredded,
                Outcome::AlreadyShredded => ShredSubject::AlreadyShredded,
                Outcome::NothingFound => ShredSubject::NotFound,
            });
        self.audit(principal, Action::ShredSubject, None, &result);
        if matches!(result, Ok(ShredSubject::Shredded)) {
            let hmac = self.subject_hmac(domain_id, subject).await.ok();
            self.audit_after(domain_id, Kind::Shred, &caller, "shred.subject", None, hmac)
                .await;
        }
        result
    }

    /// Shreds every active fact in a scope. Returns how many.
    pub async fn shred_scope(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        scope: &str,
        reason: Reason,
    ) -> Result<usize, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        if scope.is_empty() {
            return Err(VaultError::Invalid("scope is empty"));
        }
        let result = self
            .run_shred(domain_id, reason, Target::Scope(scope))
            .await
            .map(|o| match o {
                Outcome::Done(d) => d.object_ids.len(),
                _ => 0,
            });
        self.audit(principal, Action::ShredScope, None, &result);
        if matches!(result, Ok(n) if n > 0) {
            self.audit_after(domain_id, Kind::Shred, &caller, "shred.scope", None, None)
                .await;
        }
        result
    }

    /// Shreds a whole domain. Everything in it becomes unreadable. A fact under legal hold stops it.
    pub async fn shred_domain(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        reason: Reason,
    ) -> Result<bool, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let result = self
            .run_shred(domain_id, reason, Target::Domain)
            .await
            .map(|o| matches!(o, Outcome::Done(_)));
        self.audit(principal, Action::ShredDomain, None, &result);
        if matches!(result, Ok(true)) {
            self.audit_after(domain_id, Kind::Shred, &caller, "shred.domain", None, None)
                .await;
        }
        result
    }

    /// Shreds up to `limit` facts whose `expires_at` has passed and that are not under legal hold, as one
    /// `expire` ledger entry. Returns how many. Call it repeatedly until it returns 0.
    pub async fn sweep_expired(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        limit: u32,
    ) -> Result<usize, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let result = self
            .run_shred(domain_id, Reason::Retention, Target::Expired(limit))
            .await
            .map(|o| match o {
                Outcome::Done(d) => d.object_ids.len(),
                _ => 0,
            });
        self.audit(principal, Action::Expire, None, &result);
        if matches!(result, Ok(n) if n > 0) {
            self.audit_after(domain_id, Kind::Shred, &caller, "expire", None, None)
                .await;
        }
        result
    }

    /// Sets or clears a fact's legal hold.
    pub async fn set_legal_hold(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        fact_id: &FactId,
        hold: bool,
    ) -> Result<(), VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let result = self
            .store
            .set_legal_hold(domain_id, fact_id, hold)
            .await
            .map_err(VaultError::from);
        self.audit(principal, Action::LegalHold, Some(*fact_id), &result);
        if result.is_ok() {
            let action = if hold {
                "legal_hold.set"
            } else {
                "legal_hold.clear"
            };
            self.audit_after(
                domain_id,
                Kind::Admin,
                &caller,
                action,
                Some(*fact_id),
                None,
            )
            .await;
        }
        result
    }

    /// Moves a fact to another scope without re-encrypting it (REQUIREMENTS F8).
    pub async fn rebind_scope(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        fact_id: &FactId,
        new_scope: &str,
    ) -> Result<(), VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let result = self.rebind_inner(domain_id, fact_id, new_scope).await;
        self.audit(principal, Action::Rebind, Some(*fact_id), &result);
        if result.is_ok() {
            self.audit_after(
                domain_id,
                Kind::Rebind,
                &caller,
                "rebind",
                Some(*fact_id),
                None,
            )
            .await;
        }
        result
    }

    async fn rebind_inner(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
        new_scope: &str,
    ) -> Result<(), VaultError> {
        if new_scope.is_empty() {
            return Err(VaultError::Invalid("scope is empty"));
        }
        let domain = self.store.domain(domain_id).await?;
        let (hmac, bik) = self.keyring.with_domain(domain_id, &domain.keys, |dk| {
            Ok((dk.scope_hmac(new_scope)?, dk.bik_version()))
        })?;
        Ok(self
            .store
            .rebind_scope(domain_id, fact_id, &hmac, bik)
            .await?)
    }

    /// Works out what a shred of `target` would destroy. Reads only.
    async fn prepare(
        &self,
        domain_id: &Id,
        domain: &DomainRecord,
        target: &Target<'_>,
    ) -> Result<Prepared, VaultError> {
        Ok(match target {
            Target::Fact(fact_id) => match self.store.fact_for_read(domain_id, fact_id).await {
                Err(StoreError::NotFound) => Prepared::Skip(Outcome::NothingFound),
                Err(e) => return Err(e.into()),
                Ok(b) if b.fact.state == State::Shredded => {
                    Prepared::Skip(Outcome::AlreadyShredded)
                }
                Ok(b) => Prepared::Plan(
                    ShredPlan::Facts {
                        fact_ids: vec![**fact_id],
                    },
                    Effect::Facts {
                        fact_ids: vec![**fact_id],
                        object_ids: vec![b.fact.fact.object_id],
                        expire: false,
                    },
                ),
            },
            Target::Expired(limit) => {
                let due: Vec<DueFact> = self.store.due_facts(domain_id, *limit).await?;
                if due.is_empty() {
                    Prepared::Skip(Outcome::NothingFound)
                } else {
                    Prepared::Plan(
                        ShredPlan::Facts {
                            fact_ids: due.iter().map(|d| d.fact_id).collect(),
                        },
                        Effect::Facts {
                            fact_ids: due.iter().map(|d| d.fact_id).collect(),
                            object_ids: due.iter().map(|d| d.object_id).collect(),
                            expire: true,
                        },
                    )
                }
            }
            Target::Scope(scope) => {
                let (hmac, bik) = self.keyring.with_domain(domain_id, &domain.keys, |dk| {
                    Ok((dk.scope_hmac(scope)?, dk.bik_version()))
                })?;
                let facts = self.store.active_facts_in_scope(domain_id, &hmac).await?;
                if facts.is_empty() {
                    Prepared::Skip(Outcome::NothingFound)
                } else {
                    Prepared::Plan(
                        ShredPlan::Scope {
                            scope_hmac: hmac,
                            fact_ids: facts.iter().map(|(f, _)| *f).collect(),
                        },
                        Effect::Scope {
                            scope_hmac: hmac,
                            bik_version: bik,
                            fact_ids: facts.iter().map(|(f, _)| *f).collect(),
                            object_ids: facts.iter().map(|(_, o)| *o).collect(),
                        },
                    )
                }
            }
            Target::Subject(subject) => {
                let hmac = self
                    .keyring
                    .with_domain(domain_id, &domain.keys, |dk| dk.subject_hmac(subject))?;
                match self.store.subject_active_versions(domain_id, &hmac).await? {
                    None => Prepared::Skip(Outcome::NothingFound),
                    Some((_, versions)) if versions.is_empty() => {
                        Prepared::Skip(Outcome::AlreadyShredded)
                    }
                    Some((bik, versions)) => Prepared::Plan(
                        ShredPlan::Subject {
                            subject_hmac: hmac,
                            versions: versions.clone(),
                        },
                        Effect::Subject {
                            subject_hmac: hmac,
                            bik_version: bik,
                            subject_key_versions: versions,
                        },
                    ),
                }
            }
            Target::Domain => {
                if domain.state == State::Shredded {
                    Prepared::Skip(Outcome::AlreadyShredded)
                } else {
                    Prepared::Plan(ShredPlan::Domain, Effect::Domain)
                }
            }
        })
    }

    /// The one path every shred takes: plan, sign, destroy and append in one transaction, publish the entry to
    /// the bucket, then delete the objects. It returns success only after the entry is in the bucket, because
    /// until then a restored key store would bring the data back.
    async fn run_shred(
        &self,
        domain_id: &Id,
        reason: Reason,
        target: Target<'_>,
    ) -> Result<Outcome, VaultError> {
        // Earlier entries that never reached the bucket go first, so the bucket stays a prefix of the ledger.
        self.publish_pending(domain_id).await?;
        let request_id = hex::encode(rng::id()?);
        for _ in 0..MAX_ATTEMPTS {
            let domain = self.store.domain(domain_id).await?;
            let sign_key = match self.store.sign_key(domain_id, SignPurpose::Ledger).await? {
                Some(k) => k,
                None => {
                    // A domain made before the ledger existed, or never written to: make its key now.
                    let made = self
                        .keyring
                        .create_signing_key(domain_id, SignPurpose::Ledger)?;
                    self.store.get_or_insert_sign_key(domain_id, &made).await?
                }
            };
            let (plan, effect) = match self.prepare(domain_id, &domain, &target).await? {
                Prepared::Skip(outcome) => return Ok(outcome),
                Prepared::Plan(plan, effect) => (plan, effect),
            };
            let head = self.store.ledger_head(domain_id).await?;
            let (seq, prev) = match head {
                Some(h) => (h.seq + 1, h.hash),
                None => (0, ledger::GENESIS),
            };
            let entry = Entry {
                seq,
                prev,
                time: OffsetDateTime::now_utc(),
                effect,
                request_id: request_id.clone(),
                reason,
            };
            let json = ledger::to_json(domain_id, &entry);
            let hash = ledger::hash_of(&json)?;
            let line = self.keyring.sign_ledger(domain_id, &sign_key, &json)?;
            let append = LedgerAppend {
                seq,
                prev,
                hash,
                line: line.clone(),
            };
            match self.store.apply_shred(domain_id, &plan, &append).await {
                Ok(destroyed) => {
                    self.publish(domain_id, seq, line).await?;
                    self.delete_objects(domain_id, &destroyed).await;
                    return Ok(Outcome::Done(destroyed));
                }
                // The ledger moved or the plan went stale: read again and retry.
                Err(StoreError::Conflict(_)) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(VaultError::Conflict(
            "too many concurrent changes; try again",
        ))
    }

    async fn delete_objects(&self, domain_id: &Id, destroyed: &Destroyed) {
        for object_id in &destroyed.object_ids {
            // Without the key the object is noise, so a failure here only leaves work for the sweeper.
            let _ = self
                .objects
                .delete(&ObjectKey {
                    domain_id: *domain_id,
                    object_id: *object_id,
                })
                .await;
        }
    }

    /// Writes a ledger line to the bucket and marks it published.
    async fn publish(&self, domain_id: &Id, seq: u64, line: Vec<u8>) -> Result<(), VaultError> {
        self.objects
            .put_path(&ledger::path_for(domain_id, seq), line)
            .await
            .map_err(|_| VaultError::Unavailable("ledger bucket"))?;
        self.store.ledger_mark_published(domain_id, seq).await?;
        Ok(())
    }

    /// Publishes every entry the key store has that the bucket may not.
    pub async fn publish_pending(&self, domain_id: &Id) -> Result<usize, VaultError> {
        let pending = self.store.ledger_unpublished(domain_id).await?;
        let n = pending.len();
        for rec in pending {
            self.publish(domain_id, rec.seq, rec.line).await?;
        }
        Ok(n)
    }

    // --- Startup and readiness ---------------------------------------------------------------------------

    /// Brings the key store in line with the bucket's ledger. **Run before any listener opens.** It needs no
    /// key, so it works while the vault is sealed.
    ///
    /// For every domain it verifies the bucket's ledger (signatures, hash chain, no gaps), checks that the key
    /// store's own entries are the same entries, publishes entries the key store has and the bucket lacks, and
    /// replays entries the bucket has and the key store lacks, which is what a restored old backup looks like.
    /// A disagreement it cannot explain (a fork, a bad signature, a published entry gone from the bucket) is
    /// [`VaultError::Integrity`], and the server must not start.
    pub async fn reconcile(&self) -> Result<ReconcileReport, VaultError> {
        let mut report = ReconcileReport::default();
        for domain_id in self.store.list_domains().await? {
            self.reconcile_domain(&domain_id, &mut report).await?;
            report.domains += 1;
        }
        Ok(report)
    }

    async fn reconcile_domain(
        &self,
        domain_id: &Id,
        report: &mut ReconcileReport,
    ) -> Result<(), VaultError> {
        let db = self.store.ledger_records(domain_id, 0).await?;
        let files = self
            .objects
            .list_prefix(&ledger::prefix_for(domain_id))
            .await
            .map_err(object_error)?;
        let mut seqs: Vec<u64> = files
            .iter()
            .filter_map(|(path, _)| ledger::seq_of(domain_id, path))
            .collect();
        seqs.sort_unstable();
        if db.is_empty() && seqs.is_empty() {
            return Ok(());
        }
        let sign_key = self
            .store
            .sign_key(domain_id, SignPurpose::Ledger)
            .await?
            .ok_or(VaultError::Integrity(
                "a ledger exists but the domain has no signing key",
            ))?;

        // The bucket's ledger, verified end to end.
        let mut bucket: Vec<(Entry, [u8; 32], Vec<u8>)> = Vec::with_capacity(seqs.len());
        let mut prev = ledger::GENESIS;
        for (i, seq) in seqs.iter().enumerate() {
            if u64::try_from(i).ok() != Some(*seq) {
                return Err(VaultError::Integrity("the bucket's ledger has a gap"));
            }
            let line = self
                .objects
                .get_path(&ledger::path_for(domain_id, *seq))
                .await
                .map_err(object_error)?
                .ok_or(VaultError::Integrity(
                    "a ledger file vanished while it was read",
                ))?;
            let (entry, hash, _) = ledger::verify_line(domain_id, &sign_key.public_key, &line)
                .map_err(|_| VaultError::Integrity("a ledger entry failed verification"))?;
            if entry.seq != *seq || entry.prev != prev {
                return Err(VaultError::Integrity("the bucket's ledger chain is broken"));
            }
            prev = hash;
            bucket.push((entry, hash, line));
        }

        // The key store's entries must be the same entries.
        for rec in &db {
            match usize::try_from(rec.seq).ok().and_then(|i| bucket.get(i)) {
                Some((_, hash, _)) if *hash == rec.hash => {}
                Some(_) => {
                    return Err(VaultError::Integrity(
                        "the key store and the bucket hold different ledgers",
                    ));
                }
                None if rec.published => {
                    return Err(VaultError::Integrity(
                        "the bucket lost a ledger entry that was published",
                    ));
                }
                None => {
                    self.publish(domain_id, rec.seq, rec.line.clone()).await?;
                    report.republished += 1;
                }
            }
        }

        // Entries the bucket has and the key store lacks: replay them.
        let have = u64::try_from(db.len()).unwrap_or(u64::MAX);
        for (entry, hash, line) in bucket
            .iter()
            .skip(usize::try_from(have).unwrap_or(usize::MAX))
        {
            let effect = match &entry.effect {
                Effect::Facts { object_ids, .. } | Effect::Scope { object_ids, .. } => {
                    ReplayEffect::Objects {
                        object_ids: object_ids.clone(),
                    }
                }
                Effect::Subject {
                    subject_hmac,
                    bik_version,
                    subject_key_versions,
                } => ReplayEffect::Subject {
                    subject_hmac: *subject_hmac,
                    bik_version: *bik_version,
                    versions: subject_key_versions.clone(),
                },
                Effect::Domain => ReplayEffect::Domain,
            };
            let append = LedgerAppend {
                seq: entry.seq,
                prev: entry.prev,
                hash: *hash,
                line: line.clone(),
            };
            match self.store.replay_entry(domain_id, &effect, &append).await {
                Ok(()) => report.replayed += 1,
                Err(StoreError::Conflict(_)) => {
                    return Err(VaultError::Integrity(
                        "a ledger entry could not be replayed",
                    ));
                }
                Err(e) => return Err(e.into()),
            }
        }
        Ok(())
    }

    /// For `/readyz`: whether every domain's key-store ledger head is the bucket's head. Reads at most two
    /// files per domain. `false` also means something is wrong with the bucket.
    pub async fn ledger_in_sync(&self) -> Result<bool, VaultError> {
        for domain_id in self.store.list_domains().await? {
            let Some(head) = self.store.ledger_head(&domain_id).await? else {
                continue;
            };
            let Some(line) = self
                .objects
                .get_path(&ledger::path_for(&domain_id, head.seq))
                .await
                .map_err(object_error)?
            else {
                return Ok(false);
            };
            let same = serde_json::from_slice::<serde_json::Value>(&line)
                .ok()
                .and_then(|v| v.get("entry").and_then(|e| ledger::hash_of(e).ok()))
                == Some(head.hash);
            let ahead = self
                .objects
                .get_path(&ledger::path_for(&domain_id, head.seq + 1))
                .await
                .map_err(object_error)?
                .is_some();
            if !same || ahead {
                return Ok(false);
            }
        }
        Ok(true)
    }

    /// Deletes objects in a domain's prefix that no readable fact holds a key for: leftovers of a failed
    /// create, of a fact shred whose delete failed, and of a subject shred. An object younger than `grace` is
    /// left alone, because a create writes the object before it inserts the row. Pick `grace` well above the
    /// longest a create can take.
    pub async fn sweep_orphans(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        grace: Duration,
    ) -> Result<SweepReport, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let result = self.sweep_inner(domain_id, grace).await;
        self.audit(principal, Action::Sweep, None, &result);
        result
    }

    async fn sweep_inner(
        &self,
        domain_id: &Id,
        grace: Duration,
    ) -> Result<SweepReport, VaultError> {
        let cutoff = OffsetDateTime::now_utc()
            - time::Duration::try_from(grace).map_err(|_| VaultError::Invalid("grace period"))?;
        let listed = self.objects.list(domain_id).await.map_err(object_error)?;
        let mut report = SweepReport {
            listed: listed.len(),
            ..SweepReport::default()
        };
        let (old, young): (Vec<_>, Vec<_>) =
            listed.into_iter().partition(|m| m.last_modified <= cutoff);
        report.too_young = young.len();
        for batch in old.chunks(SWEEP_BATCH) {
            let ids: Vec<Id> = batch.iter().map(|m| m.key.object_id).collect();
            let live = self.store.live_object_ids(domain_id, &ids).await?;
            for meta in batch {
                if live.contains(&meta.key.object_id) {
                    report.live += 1;
                } else if self.objects.delete(&meta.key).await.is_ok() {
                    report.deleted += 1;
                } else {
                    report.failed += 1;
                }
            }
        }
        Ok(report)
    }
}

/// A random version-4 UUID from the OS random number generator.
fn random_uuid() -> Result<Uuid, VaultError> {
    let mut bytes = [0u8; ID_LEN];
    rng::fill(&mut bytes)?;
    Ok(uuid::Builder::from_random_bytes(bytes).into_uuid())
}

// --- The audit log ------------------------------------------------------------------------------------------

/// The result of checking a domain's audit log.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuditStatus {
    /// The chain verifies and every checkpoint agrees with it.
    Ok,
    /// The log is shorter than a signed checkpoint says it was. Entries were lost: a restored backup, or
    /// truncation. Reads stop until an admin acknowledges it ([`Engine::acknowledge_audit_rollback`]).
    Truncated {
        /// The highest checkpointed sequence number.
        checkpoint_seq: u64,
        /// How many entries the log has.
        entries: u64,
    },
    /// An entry or checkpoint was changed, or a chain link or signature is wrong. The server must not start.
    Tampered(&'static str),
}

/// What [`Engine::verify_audit`] found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuditVerification {
    /// How many entries were checked.
    pub entries: u64,
    /// How many checkpoints were checked.
    pub checkpoints: usize,
    /// The verdict.
    pub status: AuditStatus,
}

/// Entries per read when verifying.
const AUDIT_PAGE: u32 = 1000;
/// The most entries in one group commit.
const AUDIT_BATCH: usize = 256;
/// How many times a commit re-reads the head and retries when another writer moved it.
const AUDIT_ATTEMPTS: usize = 32;
/// A checkpoint is written when this many entries have been added, or after [`CHECKPOINT_EVERY`].
pub const CHECKPOINT_ENTRIES: u64 = 1000;
/// A checkpoint is written at least this often while there are new entries (FORMAT.md section 8).
pub const CHECKPOINT_EVERY: Duration = Duration::from_secs(60);

impl<K: KeyStore, O: ObjectStore, A: Auditor> Engine<K, O, A> {
    /// Whether reads are stopped because the audit log lost entries and nobody has acknowledged it.
    pub fn audit_blocked(&self) -> bool {
        self.audit_blocked.load(Ordering::Acquire)
    }

    /// Writes an audit entry and returns when it is **durable** in the key store. A read calls this before it
    /// releases a value and fails if it fails (fail closed). Many concurrent entries share one transaction.
    #[allow(clippy::too_many_arguments)]
    pub async fn audit_event(
        &self,
        domain_id: &Id,
        kind: Kind,
        caller: &Caller<'_>,
        action: &str,
        fact_id: Option<FactId>,
        subject_hmac: Option<[u8; 32]>,
        denial: Option<&str>,
    ) -> Result<(), VaultError> {
        let mut rid = [0u8; 8];
        rng::fill(&mut rid)?;
        let item = Item::new(
            kind,
            caller,
            action,
            fact_id,
            subject_hmac,
            denial,
            &format!("eng-{}", hex::encode(rid)),
        );
        let (tx, rx) = futures_channel::oneshot::channel();
        self.audit_queue
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push_back(PendingAudit {
                domain_id: *domain_id,
                item,
                done: tx,
            });
        self.drive_audit().await;
        // If the task that was writing our batch was dropped, our sender is gone: that is a failure, not a
        // silent success.
        rx.await.map_err(|_| VaultError::Unavailable("audit log"))?
    }

    /// Writes an entry whose failure must not fail the operation it describes (the operation already
    /// happened). The failure is reported to the auditor, so it is never silent.
    #[allow(clippy::too_many_arguments)]
    async fn audit_after(
        &self,
        domain_id: &Id,
        kind: Kind,
        caller: &Caller<'_>,
        action: &str,
        fact_id: Option<FactId>,
        subject_hmac: Option<[u8; 32]>,
    ) {
        if self
            .audit_event(domain_id, kind, caller, action, fact_id, subject_hmac, None)
            .await
            .is_err()
        {
            self.auditor.record(&AuditEvent {
                principal: caller.principal,
                action: Action::AuditFailure,
                fact_id,
                outcome: "audit_failed",
            });
        }
    }

    /// Becomes the writer if nobody is, and writes batches until the queue is empty.
    async fn drive_audit(&self) {
        loop {
            if self
                .audit_leading
                .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                // Someone else is writing; they will pick our entry up.
                return;
            }
            {
                let _guard = LeaderGuard(&self.audit_leading);
                loop {
                    let batch: Vec<PendingAudit> = {
                        let mut q = self
                            .audit_queue
                            .lock()
                            .unwrap_or_else(PoisonError::into_inner);
                        let n = q.len().min(AUDIT_BATCH);
                        q.drain(..n).collect()
                    };
                    if batch.is_empty() {
                        break;
                    }
                    self.flush_audit(batch).await;
                }
            }
            // An entry may have been queued after we saw the queue empty and before we stopped writing: look
            // again, so nothing waits for a writer that has gone.
            if self
                .audit_queue
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .is_empty()
            {
                return;
            }
        }
    }

    /// Writes one batch: per domain, one transaction that extends the chain.
    async fn flush_audit(&self, batch: Vec<PendingAudit>) {
        let mut by_domain: Vec<(Id, Vec<PendingAudit>)> = Vec::new();
        for p in batch {
            match by_domain.iter_mut().find(|(d, _)| *d == p.domain_id) {
                Some((_, v)) => v.push(p),
                None => by_domain.push((p.domain_id, vec![p])),
            }
        }
        for (domain_id, pending) in by_domain {
            let outcome = self.commit_audit(&domain_id, &pending).await;
            for p in pending {
                let _ = p.done.send(outcome);
            }
        }
    }

    async fn commit_audit(
        &self,
        domain_id: &Id,
        pending: &[PendingAudit],
    ) -> Result<(), VaultError> {
        for _ in 0..AUDIT_ATTEMPTS {
            let head = self.store.audit_head(domain_id).await?;
            let (mut seq, mut prev) = match head {
                Some(h) => (h.seq + 1, h.hash),
                None => (0, [0u8; 32]),
            };
            let mut appends = Vec::with_capacity(pending.len());
            for p in pending {
                let at = OffsetDateTime::now_utc();
                let built = audit_log::build(domain_id, seq, &prev, at, &p.item)?;
                appends.push(AuditAppend {
                    seq,
                    prev,
                    hash: built.hash,
                    line: built.line,
                    kind: p.item.kind.name().to_owned(),
                    principal: p.item.principal.clone(),
                    fact_id: p.item.fact_id,
                    subject_hmac: p.item.subject_hmac,
                    at,
                });
                prev = built.hash;
                seq += 1;
            }
            match self.store.append_audit(domain_id, &appends).await {
                Ok(()) => return Ok(()),
                // Another replica extended the log first: read the new head and try again.
                Err(StoreError::Conflict("audit log moved")) => {}
                Err(e) => return Err(e.into()),
            }
        }
        Err(VaultError::Unavailable("audit log is too busy"))
    }

    /// Audit entries matching a filter, parsed and checked against their own lines, oldest first. The caller
    /// gives plaintext subject and principal; the engine blinds the subject.
    pub async fn audit_query(
        &self,
        domain_id: &Id,
        filter: &AuditFilter,
    ) -> Result<Vec<AuditRecord>, VaultError> {
        let rows = self.store.audit_query(domain_id, filter).await?;
        for r in &rows {
            let parsed = audit_log::parse(domain_id, &r.line)?;
            if parsed.hash != r.hash || parsed.seq != r.seq {
                return Err(VaultError::Integrity(
                    "an audit row disagrees with its line",
                ));
            }
        }
        Ok(rows)
    }

    // --- Checkpoints -------------------------------------------------------------------------------------

    /// Writes a signed checkpoint of the audit log and of the shred ledger for every domain whose log has grown
    /// by [`CHECKPOINT_ENTRIES`] entries, or has any new entry and was last checkpointed [`CHECKPOINT_EVERY`]
    /// ago. Needs the vault unsealed. Returns how many it wrote. Call it every few seconds.
    pub async fn write_checkpoints(&self, policy_hash: &[u8; 32]) -> Result<usize, VaultError> {
        let mut written = 0;
        for domain_id in self.store.list_domains().await? {
            let Some(key) = self
                .store
                .sign_key(&domain_id, SignPurpose::Checkpoint)
                .await?
            else {
                continue;
            };
            for log in [CheckpointLog::Audit, CheckpointLog::Ledger] {
                let head = match log {
                    CheckpointLog::Audit => self.store.audit_head(&domain_id).await?,
                    CheckpointLog::Ledger => self.store.ledger_head(&domain_id).await?,
                };
                let Some(head) = head else { continue };
                let slot = (domain_id, u8::from(log == CheckpointLog::Ledger));
                let due = {
                    let seen = self
                        .checkpointed
                        .lock()
                        .unwrap_or_else(PoisonError::into_inner);
                    match seen.get(&slot) {
                        None => true,
                        // The same entry as last time: nothing new. (Compared by hash too: a log that was
                        // rolled back and has grown to the same length again is not the same log.)
                        Some((seq, hash, _)) if *seq == head.seq && *hash == head.hash => false,
                        Some((seq, _, at)) => {
                            head.seq.saturating_sub(*seq) >= self.checkpoint_entries
                                || at.elapsed() >= self.checkpoint_every
                        }
                    }
                };
                if !due {
                    continue;
                }
                self.write_checkpoint(&domain_id, log, head.seq, &head.hash, policy_hash, &key)
                    .await?;
                self.checkpointed
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .insert(slot, (head.seq, head.hash, Instant::now()));
                written += 1;
            }
        }
        Ok(written)
    }

    async fn write_checkpoint(
        &self,
        domain_id: &Id,
        log: CheckpointLog,
        seq: u64,
        head: &[u8; 32],
        policy_hash: &[u8; 32],
        key: &crate::keys::WrappedSigningKey,
    ) -> Result<(), VaultError> {
        let cp = audit_log::checkpoint_json(
            log.name(),
            domain_id,
            seq,
            head,
            OffsetDateTime::now_utc(),
            policy_hash,
            &key.key_id,
        );
        let sig = self.keyring.sign_checkpoint(domain_id, key, &cp)?;
        let file = audit_log::checkpoint_file(&cp, &sig)?;
        self.objects
            .put_path(
                &audit_log::checkpoint_path(log.name(), domain_id, seq),
                file,
            )
            .await
            .map_err(|_| VaultError::Unavailable("checkpoint bucket"))
    }

    // --- Verification ------------------------------------------------------------------------------------

    /// Checks a domain's audit log: every entry's hash, link and columns, and every signed checkpoint in the
    /// bucket against the chain. Reads only. A checkpoint that a signed acknowledgement covers is skipped.
    pub async fn verify_audit(&self, domain_id: &Id) -> Result<AuditVerification, VaultError> {
        let tampered = |entries: u64, checkpoints: usize, why: &'static str| AuditVerification {
            entries,
            checkpoints,
            status: AuditStatus::Tampered(why),
        };
        let key = self
            .store
            .sign_key(domain_id, SignPurpose::Checkpoint)
            .await?;

        // Checkpoints first, so the scan knows which hashes to keep.
        let mut checkpoints: Vec<(u64, [u8; 32])> = Vec::new();
        let mut covered_set: Vec<(u64, [u8; 32])> = Vec::new();
        let files = self
            .objects
            .list_prefix(&audit_log::checkpoint_prefix("audit", domain_id))
            .await
            .map_err(object_error)?;
        let ack_files = self
            .objects
            .list_prefix(&audit_log::checkpoint_prefix("audit-ack", domain_id))
            .await
            .map_err(object_error)?;
        if (!files.is_empty() || !ack_files.is_empty()) && key.is_none() {
            return Ok(tampered(
                0,
                0,
                "checkpoints exist but the domain has no checkpoint key",
            ));
        }
        if let Some(key) = &key {
            for (path, _) in &files {
                let Some(bytes) = self.objects.get_path(path).await.map_err(object_error)? else {
                    continue;
                };
                let Ok(cp) = audit_log::verify_checkpoint_file(&key.public_key, &bytes) else {
                    return Ok(tampered(0, 0, "a checkpoint failed verification"));
                };
                let ok = cp.get("log").and_then(|v| v.as_str()) == Some("audit")
                    && cp.get("domain_id").and_then(|v| v.as_str())
                        == Some(hex::encode(domain_id).as_str());
                let seq = cp.get("seq").and_then(serde_json::Value::as_u64);
                let head: Option<[u8; 32]> = cp
                    .get("head")
                    .and_then(|v| v.as_str())
                    .and_then(|h| hex::decode(h).ok())
                    .and_then(|v| v.try_into().ok());
                match (ok, seq, head) {
                    (true, Some(seq), Some(head)) => checkpoints.push((seq, head)),
                    _ => return Ok(tampered(0, 0, "a checkpoint is malformed")),
                }
            }
            for (path, _) in &ack_files {
                let Some(bytes) = self.objects.get_path(path).await.map_err(object_error)? else {
                    continue;
                };
                let Ok(cp) = audit_log::verify_checkpoint_file(&key.public_key, &bytes) else {
                    return Ok(tampered(0, 0, "an acknowledgement failed verification"));
                };
                let Some(list) = cp.get("covered").and_then(|v| v.as_array()) else {
                    return Ok(tampered(0, 0, "an acknowledgement is malformed"));
                };
                for item in list {
                    let seq = item.get("seq").and_then(serde_json::Value::as_u64);
                    let head: Option<[u8; 32]> = item
                        .get("head")
                        .and_then(|v| v.as_str())
                        .and_then(|h| hex::decode(h).ok())
                        .and_then(|v| v.try_into().ok());
                    match (seq, head) {
                        (Some(seq), Some(head)) => covered_set.push((seq, head)),
                        _ => return Ok(tampered(0, 0, "an acknowledgement is malformed")),
                    }
                }
            }
        }
        // An acknowledgement excuses exactly the checkpoints it names, by sequence number and head hash. A
        // checkpoint written after it, even at the same sequence number, is not excused.
        let covered =
            |seq: u64, head: &[u8; 32]| covered_set.iter().any(|(s, h)| *s == seq && h == head);
        let wanted: Vec<u64> = checkpoints
            .iter()
            .filter(|(s, h)| !covered(*s, h))
            .map(|(s, _)| *s)
            .collect();

        // The chain.
        let mut entries: u64 = 0;
        let mut prev = [0u8; 32];
        let mut kept: HashMap<u64, [u8; 32]> = HashMap::new();
        loop {
            let page = self
                .store
                .audit_records(domain_id, entries, AUDIT_PAGE)
                .await?;
            if page.is_empty() {
                break;
            }
            for r in &page {
                if r.seq != entries || r.prev != prev {
                    return Ok(tampered(entries, 0, "the audit chain is broken"));
                }
                let Ok(parsed) = audit_log::parse(domain_id, &r.line) else {
                    return Ok(tampered(entries, 0, "an audit entry does not parse"));
                };
                if parsed.seq != r.seq
                    || parsed.prev != r.prev
                    || parsed.hash != r.hash
                    || parsed.kind != r.kind
                    || parsed.principal != r.principal
                    || parsed.fact_id != r.fact_id
                    || parsed.subject_hmac != r.subject_hmac
                {
                    return Ok(tampered(
                        entries,
                        0,
                        "an audit row disagrees with its entry",
                    ));
                }
                if wanted.contains(&r.seq) {
                    kept.insert(r.seq, r.hash);
                }
                prev = r.hash;
                entries += 1;
            }
        }

        // The checkpoints against the chain.
        let mut checked = 0;
        let mut truncated: Option<u64> = None;
        for (seq, head) in &checkpoints {
            if covered(*seq, head) {
                continue;
            }
            checked += 1;
            if *seq >= entries {
                truncated = Some(truncated.map_or(*seq, |t| t.max(*seq)));
            } else if kept.get(seq) != Some(head) {
                return Ok(tampered(
                    entries,
                    checked,
                    "a checkpoint disagrees with the audit chain",
                ));
            }
        }
        let status = match truncated {
            Some(checkpoint_seq) => AuditStatus::Truncated {
                checkpoint_seq,
                entries,
            },
            None => AuditStatus::Ok,
        };
        Ok(AuditVerification {
            entries,
            checkpoints: checked,
            status,
        })
    }

    /// Verifies every domain. **Run at start.** Tampering is [`VaultError::Integrity`] and the server must not
    /// start. Lost entries stop reads (see [`AuditStatus::Truncated`]) until an admin acknowledges them. Returns
    /// each domain's result.
    pub async fn check_audit(&self) -> Result<Vec<(Id, AuditVerification)>, VaultError> {
        let mut out = Vec::new();
        for domain_id in self.store.list_domains().await? {
            let v = self.verify_audit(&domain_id).await?;
            match v.status {
                AuditStatus::Tampered(why) => return Err(VaultError::Integrity(why)),
                AuditStatus::Truncated { .. } => self.audit_blocked.store(true, Ordering::Release),
                AuditStatus::Ok => {}
            }
            out.push((domain_id, v));
        }
        Ok(out)
    }

    /// Acknowledges that the audit log lost entries (a restore from backup, say), so reads can resume. It
    /// writes a signed marker naming the lost range, so verification stops flagging the old checkpoints and
    /// still flags anything else, and records the acknowledgement in the log. Needs the vault unsealed.
    pub async fn acknowledge_audit_rollback(
        &self,
        caller: &Caller<'_>,
        domain_id: &Id,
        policy_hash: &[u8; 32],
    ) -> Result<(u64, u64), VaultError> {
        let v = self.verify_audit(domain_id).await?;
        let AuditStatus::Truncated {
            checkpoint_seq,
            entries,
        } = v.status
        else {
            return Err(VaultError::Conflict(
                "there is no lost audit range to acknowledge",
            ));
        };
        let key = self
            .store
            .sign_key(domain_id, SignPurpose::Checkpoint)
            .await?
            .ok_or(VaultError::Integrity("no checkpoint key"))?;
        // Name the lost checkpoints exactly: every valid checkpoint beyond the end of the log.
        let mut lost = Vec::new();
        for (path, _) in self
            .objects
            .list_prefix(&audit_log::checkpoint_prefix("audit", domain_id))
            .await
            .map_err(object_error)?
        {
            let Some(bytes) = self.objects.get_path(&path).await.map_err(object_error)? else {
                continue;
            };
            let cp = audit_log::verify_checkpoint_file(&key.public_key, &bytes)?;
            let seq = cp.get("seq").and_then(serde_json::Value::as_u64);
            let head = cp.get("head").cloned();
            if let (Some(seq), Some(head)) = (seq, head)
                && seq >= entries
            {
                lost.push(serde_json::json!({"seq": seq, "head": head}));
            }
        }
        let mut cp = audit_log::checkpoint_json(
            "audit-ack",
            domain_id,
            checkpoint_seq,
            &[0; 32],
            OffsetDateTime::now_utc(),
            policy_hash,
            &key.key_id,
        );
        if let Some(m) = cp.as_object_mut() {
            m.insert("from_seq".into(), entries.into());
            m.insert("covered".into(), serde_json::Value::Array(lost));
        }
        let sig = self.keyring.sign_checkpoint(domain_id, &key, &cp)?;
        let file = audit_log::checkpoint_file(&cp, &sig)?;
        self.objects
            .put_path(
                &audit_log::checkpoint_path("audit-ack", domain_id, checkpoint_seq),
                file,
            )
            .await
            .map_err(|_| VaultError::Unavailable("checkpoint bucket"))?;
        self.audit_event(
            domain_id,
            Kind::Admin,
            caller,
            "audit.rollback_acknowledged",
            None,
            None,
            None,
        )
        .await?;
        self.audit_blocked.store(false, Ordering::Release);
        Ok((entries, checkpoint_seq))
    }
}

// --- Blobs ----------------------------------------------------------------------------------------------------

/// A blob to create. The client encrypts it itself; the vault only makes the key and records the row.
#[derive(Debug, Clone)]
pub struct CreateBlob<'a> {
    /// Who it is about. `None` files it under a pseudo-subject from the scope, as for facts.
    pub subject: Option<&'a str>,
    /// The scope.
    pub scope: &'a str,
    /// The fact type, which policy keys on.
    pub fact_type: &'a str,
    /// The plaintext length in bytes. Fixed now: it decides the padding, and the upload is checked against it.
    pub len: u64,
    /// Plaintext bytes per chunk, a multiple of 1024 from 1024 to 16 MiB. 0 means the default, 64 KiB.
    pub chunk_size: u32,
    /// When the blob expires once complete, if it does.
    pub expires_at: Option<OffsetDateTime>,
}

/// What a client needs to encrypt and upload a blob. **The key is shown once**: it is not stored in the clear,
/// and a client that loses it has to ask again through [`Engine::open_blob`], which is audited.
#[derive(Debug)]
pub struct BlobTicket {
    /// The blob's id, which is also its fact id.
    pub blob_id: FactId,
    /// The domain, for the object header.
    pub domain_id: Id,
    /// The object id, for the header and the upload address.
    pub object_id: Id,
    /// The key generation, for the header.
    pub dek_generation: u32,
    /// Plaintext bytes per chunk.
    pub chunk_size: u32,
    /// The suite a browser should use.
    pub suite: Suite,
    /// The data key, wiped when dropped.
    pub dek: Zeroizing<[u8; 32]>,
}

/// What a client needs to download and decrypt a blob.
#[derive(Debug)]
pub struct BlobAccess {
    /// The blob's id.
    pub blob_id: FactId,
    /// Its fact type.
    pub fact_type: String,
    /// The domain.
    pub domain_id: Id,
    /// The object.
    pub object_id: Id,
    /// The key generation.
    pub dek_generation: u32,
    /// Plaintext bytes per chunk.
    pub chunk_size: u32,
    /// The plaintext length.
    pub len: u64,
    /// The data key, wiped when dropped.
    pub dek: Zeroizing<[u8; 32]>,
}

/// A blob being decrypted a chunk at a time on the server. The reader (and so the key) is on the heap and wiped
/// when this is dropped. This is the one place a derived key outlives a single synchronous step: for the length
/// of one authorized, audited download.
pub struct BlobStream {
    reader: Option<Box<BlobReader>>,
    path: String,
    pos: u64,
    size: u64,
    chunk: u64,
}

impl core::fmt::Debug for BlobStream {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BlobStream")
            .field("pos", &self.pos)
            .finish_non_exhaustive()
    }
}

impl<K: KeyStore, O: ObjectStore, A: Auditor> Engine<K, O, A> {
    /// Creates a blob's row and its key and returns what the client needs to encrypt and upload it. Nothing is
    /// written to the bucket: the client does that, then calls [`Engine::complete_blob`].
    pub async fn create_blob(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        request: &CreateBlob<'_>,
    ) -> Result<BlobTicket, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let result = self.create_blob_inner(domain_id, request).await;
        self.audit(
            principal,
            Action::Create,
            result.as_ref().ok().map(|(t, _)| t.blob_id),
            &result,
        );
        let (ticket, subject) = result?;
        self.audit_after(
            domain_id,
            Kind::Create,
            &caller,
            "blob.create",
            Some(ticket.blob_id),
            Some(subject),
        )
        .await;
        Ok(ticket)
    }

    async fn create_blob_inner(
        &self,
        domain_id: &Id,
        request: &CreateBlob<'_>,
    ) -> Result<(BlobTicket, [u8; 32]), VaultError> {
        if request.scope.is_empty() || request.subject.is_some_and(str::is_empty) {
            return Err(VaultError::Invalid("scope or subject is empty"));
        }
        let type_len = request.fact_type.len();
        if type_len == 0 || type_len > MAX_FACT_TYPE_LEN {
            return Err(VaultError::Invalid("fact type length"));
        }
        if request.len > self.max_blob_len {
            return Err(VaultError::Invalid("blob is larger than the limit"));
        }
        let chunk_size = if request.chunk_size == 0 {
            blobfmt::CHUNK_DEFAULT
        } else {
            request.chunk_size
        };
        if blobfmt::sealed_len(request.len, chunk_size).is_none() {
            return Err(VaultError::Invalid("bad chunk size or length"));
        }
        let domain = self.store.domain(domain_id).await?;
        if domain.state == State::Shredded {
            return Err(VaultError::Shredded);
        }
        let (subject_hmac, scope_hmac, bik_version, candidate) =
            self.keyring.with_domain(domain_id, &domain.keys, |dk| {
                let subject_hmac = match request.subject {
                    Some(s) => dk.subject_hmac(s)?,
                    None => dk.pseudo_subject_hmac(request.scope)?,
                };
                let (_key, wrapped) = dk.new_subject_key(&subject_hmac, 1)?;
                Ok((
                    subject_hmac,
                    dk.scope_hmac(request.scope)?,
                    dk.bik_version(),
                    NewSubjectKey {
                        domain_id: *domain_id,
                        subject_hmac,
                        bik_version: dk.bik_version(),
                        key: wrapped,
                    },
                ))
            })?;
        let subject = self.store.get_or_insert_subject_key(&candidate).await?;
        if subject.state == State::Shredded {
            return Err(VaultError::Shredded);
        }
        let object_id = rng::id()?;
        let blob_id = random_uuid()?;
        let (dek_bytes, wrapped) = self.keyring.with_domain(domain_id, &domain.keys, |dk| {
            let subject_key = dk.unwrap_subject_key(&subject_hmac, &subject.key)?;
            let (dek, wrapped) = subject_key.new_dek(&object_id, 0)?;
            Ok((Zeroizing::new(*dek.expose()), wrapped))
        })?;
        let pending_until = OffsetDateTime::now_utc()
            + time::Duration::try_from(BLOB_PENDING_TTL).map_err(|_| VaultError::Invalid("ttl"))?;
        self.store
            .insert_blob(
                &NewFact {
                    domain_id: *domain_id,
                    fact_id: blob_id,
                    subject_hmac,
                    bik_version,
                    scope_hmac,
                    fact_type: request.fact_type.to_owned(),
                    object_id,
                    size_class: 0,
                    dek: wrapped,
                    // Short until the upload is completed, so one that never is gets cleaned up.
                    expires_at: Some(pending_until),
                    legal_hold: false,
                },
                chunk_size,
                request.len,
                request.expires_at,
            )
            .await?;
        Ok((
            BlobTicket {
                blob_id,
                domain_id: *domain_id,
                object_id,
                dek_generation: 0,
                chunk_size,
                suite: Suite::Aes256Gcm,
                dek: dek_bytes,
            },
            subject_hmac,
        ))
    }

    /// Checks an upload and makes the blob readable. The object must exist and be exactly the size the declared
    /// length gives, and its header must name this domain, object, generation and chunk size and prove, through
    /// its key commitment, that the client used the key it was given. The chunks themselves are **not** checked:
    /// the vault does not decrypt them. A client that uploads garbage after a good header gets a blob that fails
    /// to open, and harms only itself. Needs the vault unsealed.
    pub async fn complete_blob(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        blob_id: &FactId,
    ) -> Result<(), VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let result = self.complete_blob_inner(domain_id, blob_id).await;
        self.audit(principal, Action::Create, Some(*blob_id), &result);
        result?;
        self.audit_after(
            domain_id,
            Kind::Create,
            &caller,
            "blob.complete",
            Some(*blob_id),
            None,
        )
        .await;
        Ok(())
    }

    async fn complete_blob_inner(
        &self,
        domain_id: &Id,
        blob_id: &FactId,
    ) -> Result<(), VaultError> {
        let bundle = self.store.fact_for_read(domain_id, blob_id).await?;
        if bundle.domain.state == State::Shredded
            || bundle.subject_key.state == State::Shredded
            || bundle.fact.state == State::Shredded
        {
            return Err(VaultError::Shredded);
        }
        let info = bundle
            .fact
            .blob
            .ok_or(VaultError::Conflict("this is not a blob"))?;
        if info.ready {
            return Err(VaultError::Conflict("the blob is already complete"));
        }
        let fact = &bundle.fact.fact;
        let path = ObjectKey {
            domain_id: *domain_id,
            object_id: fact.object_id,
        }
        .path();
        let size = self
            .objects
            .head_path(&path)
            .await
            .map_err(object_error)?
            .ok_or(VaultError::Conflict("the object has not been uploaded"))?;
        if Some(size) != blobfmt::sealed_len(info.len, info.chunk_size) {
            return Err(VaultError::Conflict(
                "the object is not the size that was declared",
            ));
        }
        let header = self
            .objects
            .get_range(&path, 0, 104)
            .await
            .map_err(object_error)?
            .ok_or(VaultError::Conflict("the object has not been uploaded"))?;
        let checked = self
            .keyring
            .with_domain(domain_id, &bundle.domain.keys, |dk| {
                let subject_key =
                    dk.unwrap_subject_key(&fact.subject_hmac, &bundle.subject_key.key)?;
                let dek = subject_key.unwrap_dek(&fact.object_id, &fact.dek)?;
                Ok(blobfmt::check_header(dek.expose(), &header))
            })?;
        let ok = checked.is_ok_and(|h| {
            h.domain_id == *domain_id
                && h.object_id == fact.object_id
                && h.dek_generation == fact.dek.generation
                && h.chunk_size == info.chunk_size
                && matches!(h.suite, Suite::Aes256Gcm | Suite::XChaCha20Poly1305)
        });
        if !ok {
            return Err(VaultError::Conflict(
                "the uploaded header does not match the blob",
            ));
        }
        Ok(self.store.complete_blob(domain_id, blob_id).await?)
    }

    /// Where a blob that is waiting for its upload goes, and how big the object must be. Does not disclose
    /// anything, so it is not audited. [`VaultError::Conflict`] if the blob is not waiting for an upload.
    pub async fn blob_upload_target(
        &self,
        domain_id: &Id,
        blob_id: &FactId,
    ) -> Result<(ObjectKey, u64), VaultError> {
        let bundle = self.store.fact_for_read(domain_id, blob_id).await?;
        if bundle.domain.state == State::Shredded
            || bundle.subject_key.state == State::Shredded
            || bundle.fact.state == State::Shredded
        {
            return Err(VaultError::Shredded);
        }
        let info = bundle
            .fact
            .blob
            .ok_or(VaultError::Conflict("this is not a blob"))?;
        if info.ready {
            return Err(VaultError::Conflict("the blob is already complete"));
        }
        let size = blobfmt::sealed_len(info.len, info.chunk_size)
            .ok_or(VaultError::Invalid("bad chunk size or length"))?;
        Ok((
            ObjectKey {
                domain_id: *domain_id,
                object_id: bundle.fact.fact.object_id,
            },
            size,
        ))
    }

    /// The object key and size of a blob that is ready, for a download. Does not disclose a key and is not
    /// audited: the ciphertext is not secret, but callers must still authorize the request.
    pub async fn blob_download_target(
        &self,
        domain_id: &Id,
        blob_id: &FactId,
    ) -> Result<(ObjectKey, u64), VaultError> {
        let bundle = self.store.fact_for_read(domain_id, blob_id).await?;
        if bundle.domain.state == State::Shredded
            || bundle.subject_key.state == State::Shredded
            || bundle.fact.state == State::Shredded
        {
            return Err(VaultError::Shredded);
        }
        let info = bundle
            .fact
            .blob
            .filter(|b| b.ready)
            .ok_or(VaultError::Conflict("the blob has not been completed"))?;
        let size = blobfmt::sealed_len(info.len, info.chunk_size)
            .ok_or(VaultError::Invalid("bad chunk size or length"))?;
        Ok((
            ObjectKey {
                domain_id: *domain_id,
                object_id: bundle.fact.fact.object_id,
            },
            size,
        ))
    }

    /// Opens a blob for download: **writes the disclosure to the audit log first**, then returns the data key and
    /// the layout. The client downloads the ciphertext (a presigned URL, or through the vault) and decrypts it
    /// itself. A blob that is not complete, is shredded or has expired cannot be opened. Fails closed if the
    /// audit entry cannot be written.
    pub async fn open_blob(
        &self,
        caller: impl Into<Caller<'_>>,
        domain_id: &Id,
        blob_id: &FactId,
    ) -> Result<BlobAccess, VaultError> {
        let caller = caller.into();
        let principal = caller.principal;
        let result = self.open_blob_inner(&caller, domain_id, blob_id).await;
        self.audit(principal, Action::Read, Some(*blob_id), &result);
        result
    }

    async fn open_blob_inner(
        &self,
        caller: &Caller<'_>,
        domain_id: &Id,
        blob_id: &FactId,
    ) -> Result<BlobAccess, VaultError> {
        if self.audit_blocked() {
            return Err(VaultError::Unavailable("the audit log needs attention"));
        }
        let bundle = self.store.fact_for_read(domain_id, blob_id).await?;
        if bundle.domain.state == State::Shredded
            || bundle.subject_key.state == State::Shredded
            || bundle.fact.state == State::Shredded
        {
            return Err(VaultError::Shredded);
        }
        let info = bundle
            .fact
            .blob
            .filter(|_| bundle.fact.kind == FactKind::Blob)
            .ok_or(VaultError::Conflict("this is not a blob"))?;
        if !info.ready {
            return Err(VaultError::Conflict("the blob has not been completed"));
        }
        if bundle
            .fact
            .fact
            .expires_at
            .is_some_and(|t| t <= OffsetDateTime::now_utc())
        {
            return Err(VaultError::NotFound);
        }
        let fact = &bundle.fact.fact;
        // The key is released only after the disclosure is on record.
        self.audit_event(
            domain_id,
            Kind::ReadGrant,
            caller,
            "blob.access",
            Some(*blob_id),
            Some(fact.subject_hmac),
            None,
        )
        .await
        .map_err(|_| VaultError::Unavailable("audit log"))?;
        let dek = self
            .keyring
            .with_domain(domain_id, &bundle.domain.keys, |dk| {
                let subject_key =
                    dk.unwrap_subject_key(&fact.subject_hmac, &bundle.subject_key.key)?;
                let dek = subject_key.unwrap_dek(&fact.object_id, &fact.dek)?;
                Ok(Zeroizing::new(*dek.expose()))
            });
        let dek = match dek {
            Ok(d) => d,
            Err(e) => {
                self.audit_after(
                    domain_id,
                    Kind::ReadFail,
                    caller,
                    "blob.access",
                    Some(*blob_id),
                    Some(fact.subject_hmac),
                )
                .await;
                return Err(e);
            }
        };
        Ok(BlobAccess {
            blob_id: *blob_id,
            fact_type: fact.fact_type.clone(),
            domain_id: *domain_id,
            object_id: fact.object_id,
            dek_generation: fact.dek.generation,
            chunk_size: info.chunk_size,
            len: info.len,
            dek,
        })
    }

    /// Starts decrypting an opened blob on the server, for callers that want plaintext and not a key. Reads the
    /// header and checks the key commitment; then [`Engine::next_blob_chunk`] returns plaintext a chunk at a time.
    pub async fn blob_stream(&self, access: &BlobAccess) -> Result<BlobStream, VaultError> {
        let path = ObjectKey {
            domain_id: access.domain_id,
            object_id: access.object_id,
        }
        .path();
        let size = self
            .objects
            .head_path(&path)
            .await
            .map_err(object_error)?
            .ok_or(VaultError::Unavailable("object is missing from the bucket"))?;
        let header = self
            .objects
            .get_range(&path, 0, 104)
            .await
            .map_err(object_error)?
            .ok_or(VaultError::Unavailable("object is missing from the bucket"))?;
        let reader = BlobReader::new(&access.dek, &header)?;
        Ok(BlobStream {
            reader: Some(Box::new(reader)),
            path,
            pos: 104,
            size,
            chunk: u64::from(access.chunk_size) + 16,
        })
    }

    /// The next piece of plaintext, or `None` at the end. A failure (a bad tag, a truncated object) is an error
    /// and the stream is finished: whatever the caller already received must be discarded.
    pub async fn next_blob_chunk(
        &self,
        stream: &mut BlobStream,
    ) -> Result<Option<Zeroizing<Vec<u8>>>, VaultError> {
        loop {
            let Some(reader) = stream.reader.as_mut() else {
                return Ok(None);
            };
            if stream.pos >= stream.size {
                let done = stream.reader.take().ok_or(VaultError::OpenFailed)?;
                let rest = done.finish()?;
                return Ok((!rest.is_empty()).then_some(rest));
            }
            // One chunk at a time: the reader holds one back until it knows it is not the last.
            let bytes = self
                .objects
                .get_range(&stream.path, stream.pos, stream.chunk)
                .await
                .map_err(object_error)?
                .ok_or(VaultError::Unavailable("object is missing from the bucket"))?;
            if bytes.is_empty() {
                stream.reader = None;
                return Err(VaultError::OpenFailed);
            }
            stream.pos += u64::try_from(bytes.len()).unwrap_or(u64::MAX);
            match reader.push(&bytes) {
                Ok(plain) if plain.is_empty() => {}
                Ok(plain) => return Ok(Some(plain)),
                Err(e) => {
                    stream.reader = None;
                    return Err(e.into());
                }
            }
        }
    }
}
