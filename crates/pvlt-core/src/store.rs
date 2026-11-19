//! The key store: where wrapped keys and fact metadata live (PLAN.md 3.3, 3.6).
//!
//! **What can and cannot be stored is decided by these types.** Every key is a wrapped key (ciphertext), every
//! subject and scope is a 32-byte blind identifier, and there is no field that holds a fact value, a plaintext
//! subject or scope, or an unwrapped key. An implementation cannot be handed those, so it cannot leak them. The
//! ciphertext of the values is in the object store, not here.
//!
//! The only implementation is Postgres (`pvlt_server::pg`). The trait exists as the seam that engine unit tests fake.
//! Every method returns a future that is `Send`, so an implementation can be called from any task.
//!
//! # What an implementation must guarantee
//!
//! * **Linearizable writes.** A shred is visible to every later read, on every connection, before the call
//!   returns.
//! * **A shredded row never changes.** Once a fact, subject key or domain is shredded its wrapped keys are
//!   zeros, it stays shredded, and nothing can write a key back into it.
//! * **Inserting a fact is ordered against shredding its subject.** Either the fact is stored and a later
//!   shred covers it, or the shred came first and the insert fails with [`StoreError::SubjectShredded`]. No
//!   interleaving stores a fact under a subject key that was already destroyed.
//! * **`fact_for_read` is one consistent snapshot** of the fact, its subject key and its domain, so a read never
//!   combines a key from before a shred with a fact from after it (PLAN.md 3.2).

use core::fmt;
use core::future::Future;

use pvlt_format::Id;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::VaultError;
use crate::keys::{WrappedDek, WrappedDomainKeys, WrappedSigningKey, WrappedSubjectKey};
use crate::seal::SealConfig;
use pvlt_format::wrap::SignPurpose;

/// A fact id. FORMAT.md section 8 requires UUIDs, so a free-form id cannot reach a log that is never deleted.
pub type FactId = Uuid;

/// Whether a record is live or has been shredded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    /// The keys are intact.
    Active,
    /// The wrapped keys were overwritten with zeros. Permanent.
    Shredded,
}

/// A domain as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DomainRecord {
    /// The domain id.
    pub domain_id: Id,
    /// The domain's three wrapped keys.
    pub keys: WrappedDomainKeys,
    /// Whether the domain was shredded.
    pub state: State,
    /// When the row was created, by the database clock.
    pub created_at: OffsetDateTime,
}

/// A subject key to store.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewSubjectKey {
    /// The domain.
    pub domain_id: Id,
    /// The subject's blind identifier (FORMAT.md section 6).
    pub subject_hmac: [u8; 32],
    /// Version of the blind-index key that made `subject_hmac`. Ledger entries record it.
    pub bik_version: u32,
    /// The wrapped key, with its version and the KEK version that wrapped it.
    pub key: WrappedSubjectKey,
}

/// A subject key as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubjectKeyRecord {
    /// The domain.
    pub domain_id: Id,
    /// The subject's blind identifier.
    pub subject_hmac: [u8; 32],
    /// Version of the blind-index key that made `subject_hmac`.
    pub bik_version: u32,
    /// The wrapped key. All zeros when `state` is [`State::Shredded`].
    pub key: WrappedSubjectKey,
    /// Whether the subject was shredded.
    pub state: State,
}

/// A fact to store. There is no value here: the sealed value is in the object store under `object_id`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewFact {
    /// The domain.
    pub domain_id: Id,
    /// The id the API returns. Unique within the domain.
    pub fact_id: FactId,
    /// The subject's blind identifier. Must match an existing subject key.
    pub subject_hmac: [u8; 32],
    /// Version of the blind-index key that made `subject_hmac` and `scope_hmac`.
    pub bik_version: u32,
    /// The scope's blind identifier.
    pub scope_hmac: [u8; 32],
    /// The fact type, such as `ascii` or `json`. Validation is the engine's job.
    pub fact_type: String,
    /// The random id of the object in the bucket (FORMAT.md section 4). Unique within the domain.
    pub object_id: Id,
    /// The padded size class of the value (FORMAT.md section 4.1).
    pub size_class: u32,
    /// The data key, wrapped by the subject key. Its `subject_key_version` selects the subject key.
    pub dek: WrappedDek,
    /// When the fact expires, if it does.
    pub expires_at: Option<OffsetDateTime>,
    /// A fact under legal hold cannot be shredded.
    pub legal_hold: bool,
}

/// What a stored fact holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FactKind {
    /// A small value, sealed in one piece.
    Fact,
    /// A streamed object the client encrypted itself.
    Blob,
}

/// How a blob is laid out.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BlobInfo {
    /// Plaintext bytes per chunk.
    pub chunk_size: u32,
    /// The plaintext length the client declared. The object's size is checked against it.
    pub len: u64,
    /// Whether the upload was completed and checked. A blob that is not ready cannot be read.
    pub ready: bool,
    /// When the blob expires once it is complete. Until then its row carries a short expiry of its own.
    pub final_expires_at: Option<OffsetDateTime>,
}

/// A fact as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactRecord {
    /// The stored fields. `dek.wrapped` is all zeros when `state` is [`State::Shredded`].
    pub fact: NewFact,
    /// Whether the fact was shredded.
    pub state: State,
    /// When the row was created, by the database clock.
    pub created_at: OffsetDateTime,
    /// When it was shredded.
    pub shredded_at: Option<OffsetDateTime>,
    /// A fact or a blob.
    pub kind: FactKind,
    /// The blob's layout, for a blob.
    pub blob: Option<BlobInfo>,
}

/// Everything a read needs, from one snapshot.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FactBundle {
    /// The fact.
    pub fact: FactRecord,
    /// Its subject key.
    pub subject_key: SubjectKeyRecord,
    /// Its domain.
    pub domain: DomainRecord,
}

/// The result of shredding a fact.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredFact {
    /// Shredded just now. The caller should delete the object `object_id` from the bucket, best effort.
    Shredded {
        /// The bucket object that held the sealed value.
        object_id: Id,
    },
    /// It was already shredded. The API treats this as success (REQUIREMENTS F3).
    AlreadyShredded,
    /// There is no such fact. The API also treats this as success.
    NotFound,
}

/// The result of shredding a subject.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ShredSubject {
    /// Shredded just now: every fact under the subject is now unreadable.
    Shredded,
    /// It was already shredded.
    AlreadyShredded,
    /// There is no such subject.
    NotFound,
}

/// The newest ledger entry of a domain.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LedgerHead {
    /// Its sequence number.
    pub seq: u64,
    /// Its hash.
    pub hash: [u8; 32],
}

/// A ledger entry as the key store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerRecord {
    /// Position, from 0.
    pub seq: u64,
    /// The entry's hash.
    pub hash: [u8; 32],
    /// The signed line (FORMAT.md section 8), exactly as it is written to the bucket.
    pub line: Vec<u8>,
    /// Whether the line has been written to the bucket. A shred is not complete until it has.
    pub published: bool,
}

/// An entry to append. The store checks that `seq` follows its head and that `prev` is the head's hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerAppend {
    /// The sequence number. 0 for the first entry.
    pub seq: u64,
    /// The previous entry's hash, or zeros for `seq` 0.
    pub prev: [u8; 32],
    /// This entry's hash.
    pub hash: [u8; 32],
    /// The signed line.
    pub line: Vec<u8>,
}

/// What a shred is about to destroy. The store checks it against what it holds, inside the transaction that
/// destroys it, so a plan made from a stale read is refused with [`StoreError::Conflict`] and not applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShredPlan {
    /// Exactly these facts, which must all be active.
    Facts {
        /// The facts.
        fact_ids: Vec<FactId>,
    },
    /// Exactly the active facts in a scope.
    Scope {
        /// The scope's blind identifier.
        scope_hmac: [u8; 32],
        /// The facts, which must be exactly the active facts with that scope.
        fact_ids: Vec<FactId>,
    },
    /// Exactly these active key versions of a subject.
    Subject {
        /// The subject's blind identifier.
        subject_hmac: [u8; 32],
        /// The active versions.
        versions: Vec<u32>,
    },
    /// The whole domain.
    Domain,
}

/// What a shred destroyed.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Destroyed {
    /// Bucket objects that no longer have a key. The caller deletes them, best effort.
    pub object_ids: Vec<Id>,
}

/// An entry to apply during replay, by id only. The ledger is authoritative, so a legal hold does not stop it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplayEffect {
    /// Facts to destroy, found by their object ids. Ones that are not in this key store are ignored.
    Objects {
        /// The object ids.
        object_ids: Vec<Id>,
    },
    /// A subject to destroy. A tombstone is written if the key store has no row for it, so a later write cannot
    /// reopen it.
    Subject {
        /// The subject's blind identifier.
        subject_hmac: [u8; 32],
        /// The blind-index key version.
        bik_version: u32,
        /// The key versions.
        versions: Vec<u32>,
    },
    /// The whole domain.
    Domain,
}

/// A fact that has expired.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DueFact {
    /// The fact.
    pub fact_id: FactId,
    /// Its object.
    pub object_id: Id,
}

/// A registered token issuer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IssuerRecord {
    /// The id written as the root key id of its tokens.
    pub key_id: u32,
    /// A unique name, for people and audit entries.
    pub name: String,
    /// The Ed25519 public key its tokens are verified with.
    pub public_key: [u8; 32],
    /// The only roles it may assert (REQUIREMENTS 3.7).
    pub roles: Vec<String>,
    /// A disabled issuer's tokens are refused.
    pub enabled: bool,
}

/// A stored policy version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyRecord {
    /// Versions count up from 1.
    pub version: i64,
    /// The canonical JSON.
    pub json: Vec<u8>,
    /// Its hash, which audit entries name.
    pub hash: [u8; 32],
    /// The admin who set it.
    pub created_by: String,
}

/// A dual-control approval to read one fact, once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalRecord {
    /// Its id, named in the token that uses it.
    pub id: Uuid,
    /// The domain.
    pub domain_id: Id,
    /// The one fact it covers.
    pub fact_id: FactId,
    /// The admin who asked.
    pub requested_by: String,
    /// The admin who approved. A different one, unless this is break-glass.
    pub approved_by: Option<String>,
    /// Approved by the requester alone, in an emergency. Always audited, and shorter.
    pub break_glass: bool,
    /// After this it is useless.
    pub expires_at: OffsetDateTime,
    /// It has been used. It can be used once.
    pub used: bool,
}

/// An approval to create.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewApproval {
    /// Its id.
    pub id: Uuid,
    /// The domain.
    pub domain_id: Id,
    /// The fact.
    pub fact_id: FactId,
    /// The admin asking.
    pub requested_by: String,
    /// Approve it at once, by the requester (break-glass).
    pub break_glass: bool,
    /// When it stops being useful.
    pub expires_at: OffsetDateTime,
}

/// An audit entry to append. The store checks that `seq` follows its head and that `prev` is the head's hash. The
/// last five fields are copies of fields in `line`, kept so queries can use an index; verification checks them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditAppend {
    /// The sequence number. 0 for the first entry.
    pub seq: u64,
    /// The previous entry's hash, or zeros for `seq` 0.
    pub prev: [u8; 32],
    /// This entry's hash.
    pub hash: [u8; 32],
    /// The canonical JSON entry.
    pub line: Vec<u8>,
    /// The entry type, such as `read.grant`.
    pub kind: String,
    /// Who acted.
    pub principal: String,
    /// The fact, if the entry is about one.
    pub fact_id: Option<FactId>,
    /// The subject's blind identifier, if known.
    pub subject_hmac: Option<[u8; 32]>,
    /// When it was written.
    pub at: OffsetDateTime,
}

/// An audit entry as stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditRecord {
    /// The sequence number.
    pub seq: u64,
    /// The previous entry's hash.
    pub prev: [u8; 32],
    /// This entry's hash.
    pub hash: [u8; 32],
    /// The canonical JSON entry.
    pub line: Vec<u8>,
    /// When it was written, by the database clock.
    pub at: OffsetDateTime,
    /// The entry type.
    pub kind: String,
    /// Who acted.
    pub principal: String,
    /// The fact.
    pub fact_id: Option<FactId>,
    /// The subject's blind identifier.
    pub subject_hmac: Option<[u8; 32]>,
}

/// What an audit query asks for. Every field that is set must match.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AuditFilter {
    /// Entries about this subject.
    pub subject_hmac: Option<[u8; 32]>,
    /// Entries by this principal.
    pub principal: Option<String>,
    /// Entries about this fact.
    pub fact_id: Option<FactId>,
    /// Entries of this type.
    pub kind: Option<String>,
    /// Entries at or after this time.
    pub from: Option<OffsetDateTime>,
    /// Entries before this time.
    pub to: Option<OffsetDateTime>,
    /// Only entries with a sequence number above this, for paging.
    pub after_seq: Option<u64>,
    /// At most this many, oldest first.
    pub limit: u32,
}

/// Why a store operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum StoreError {
    /// There is no such record.
    NotFound,
    /// A record with that id already exists.
    AlreadyExists,
    /// The request clashes with what is stored. The string names the clash.
    Conflict(&'static str),
    /// The fact's subject key was shredded, so nothing can be stored under it.
    SubjectShredded,
    /// The fact is under legal hold.
    LegalHold,
    /// A stored row is not valid, for example a wrong key length. The string names the check. This means
    /// someone changed the database outside the vault.
    Corrupt(&'static str),
    /// The database failed or could not be reached. The text comes from the driver. It cannot contain a value,
    /// a key or a plaintext subject or scope, because the store is never given any.
    Backend(String),
}

impl fmt::Display for StoreError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            StoreError::NotFound => f.write_str("not found"),
            StoreError::AlreadyExists => f.write_str("already exists"),
            StoreError::Conflict(what) => write!(f, "conflict: {what}"),
            StoreError::SubjectShredded => f.write_str("the subject was shredded"),
            StoreError::LegalHold => f.write_str("the fact is under legal hold"),
            StoreError::Corrupt(what) => write!(f, "invalid stored record: {what}"),
            StoreError::Backend(what) => write!(f, "key store failure: {what}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<StoreError> for VaultError {
    fn from(e: StoreError) -> Self {
        match e {
            StoreError::NotFound => VaultError::NotFound,
            StoreError::AlreadyExists => VaultError::Conflict("already exists"),
            StoreError::Conflict(what) => VaultError::Conflict(what),
            StoreError::SubjectShredded => VaultError::Shredded,
            StoreError::LegalHold => VaultError::Conflict("the fact is under legal hold"),
            StoreError::Corrupt(_) => VaultError::Unavailable("key store holds an invalid record"),
            StoreError::Backend(_) => VaultError::Unavailable("key store"),
        }
    }
}

/// The key store. See the module documentation for the guarantees an implementation must keep.
pub trait KeyStore: Send + Sync {
    /// Checks that the store is reachable. Never writes. For `/readyz`.
    fn ping(&self) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The stored seal configuration, or `None` if the vault was never initialised.
    fn seal_config(&self) -> impl Future<Output = Result<Option<SealConfig>, StoreError>> + Send;

    /// Stores the seal configuration once. [`StoreError::AlreadyExists`] if there already is one: a vault is
    /// initialised exactly once.
    fn init_seal_config(
        &self,
        config: &SealConfig,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Stores a new domain's wrapped keys. [`StoreError::AlreadyExists`] if the domain exists.
    fn create_domain(
        &self,
        domain_id: &Id,
        keys: &WrappedDomainKeys,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// A domain. [`StoreError::NotFound`] if there is none.
    fn domain(
        &self,
        domain_id: &Id,
    ) -> impl Future<Output = Result<DomainRecord, StoreError>> + Send;

    /// A subject's current key (the highest version), or `None`.
    fn subject_key(
        &self,
        domain_id: &Id,
        subject_hmac: &[u8; 32],
    ) -> impl Future<Output = Result<Option<SubjectKeyRecord>, StoreError>> + Send;

    /// Stores a subject key unless the subject already has one, and returns what is stored. Safe to call from
    /// many tasks at once: they all get the same key back, and the extra ones the callers made are discarded.
    /// If the stored key was shredded the returned record says so; the caller must not use it.
    fn get_or_insert_subject_key(
        &self,
        new: &NewSubjectKey,
    ) -> impl Future<Output = Result<SubjectKeyRecord, StoreError>> + Send;

    /// Destroys a subject's key, which makes every fact and blob under it unreadable at once.
    fn shred_subject_key(
        &self,
        domain_id: &Id,
        subject_hmac: &[u8; 32],
    ) -> impl Future<Output = Result<ShredSubject, StoreError>> + Send;

    /// Stores a fact's metadata and wrapped key. Fails with [`StoreError::SubjectShredded`] if its subject key
    /// was shredded, [`StoreError::Conflict`] if the subject key does not exist, and
    /// [`StoreError::AlreadyExists`] if the fact id is taken.
    fn insert_fact(&self, fact: &NewFact) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// A fact with its subject key and domain, from one snapshot. A shredded fact is returned, with
    /// [`State::Shredded`] and zeroed keys, so the caller can tell "gone for good" from "never existed".
    fn fact_for_read(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
    ) -> impl Future<Output = Result<FactBundle, StoreError>> + Send;

    /// Destroys a fact's wrapped key. [`StoreError::LegalHold`] if it is under hold.
    fn shred_fact(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
    ) -> impl Future<Output = Result<ShredFact, StoreError>> + Send;

    /// Which of `object_ids` still belong to a fact that can be read: the fact is active and so is its subject
    /// key. Every other id, including ones the key store has never heard of, is an object nobody can open, so
    /// the sweeper may delete it once it is old enough (PLAN.md step 6).
    fn live_object_ids(
        &self,
        domain_id: &Id,
        object_ids: &[Id],
    ) -> impl Future<Output = Result<Vec<Id>, StoreError>> + Send;

    /// The domain ids, for startup reconciliation.
    fn list_domains(&self) -> impl Future<Output = Result<Vec<Id>, StoreError>> + Send;

    /// A domain's signing key for a purpose, or `None` if it has none yet.
    fn sign_key(
        &self,
        domain_id: &Id,
        purpose: SignPurpose,
    ) -> impl Future<Output = Result<Option<WrappedSigningKey>, StoreError>> + Send;

    /// Stores a domain's signing key for its purpose unless it already has one, and returns what is stored.
    fn get_or_insert_sign_key(
        &self,
        domain_id: &Id,
        key: &WrappedSigningKey,
    ) -> impl Future<Output = Result<WrappedSigningKey, StoreError>> + Send;

    /// The newest ledger entry, or `None` if the ledger is empty.
    fn ledger_head(
        &self,
        domain_id: &Id,
    ) -> impl Future<Output = Result<Option<LedgerHead>, StoreError>> + Send;

    /// Ledger entries from `from_seq` on, oldest first.
    fn ledger_records(
        &self,
        domain_id: &Id,
        from_seq: u64,
    ) -> impl Future<Output = Result<Vec<LedgerRecord>, StoreError>> + Send;

    /// Entries not yet written to the bucket, oldest first.
    fn ledger_unpublished(
        &self,
        domain_id: &Id,
    ) -> impl Future<Output = Result<Vec<LedgerRecord>, StoreError>> + Send;

    /// Marks an entry as written to the bucket.
    fn ledger_mark_published(
        &self,
        domain_id: &Id,
        seq: u64,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Destroys what `plan` names **and** appends `append` to the ledger, in one transaction. If either fails,
    /// neither happens. Fails with [`StoreError::Conflict`] if the ledger moved or the plan is stale (the caller
    /// re-reads and tries again), and [`StoreError::LegalHold`] if a fact in the plan is under hold.
    fn apply_shred(
        &self,
        domain_id: &Id,
        plan: &ShredPlan,
        append: &LedgerAppend,
    ) -> impl Future<Output = Result<Destroyed, StoreError>> + Send;

    /// Applies an entry that came from the bucket, and appends it already marked published, in one transaction.
    fn replay_entry(
        &self,
        domain_id: &Id,
        effect: &ReplayEffect,
        append: &LedgerAppend,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The active facts in a scope, with their objects.
    fn active_facts_in_scope(
        &self,
        domain_id: &Id,
        scope_hmac: &[u8; 32],
    ) -> impl Future<Output = Result<Vec<(FactId, Id)>, StoreError>> + Send;

    /// The active key versions of a subject, and the bik version it was made with.
    fn subject_active_versions(
        &self,
        domain_id: &Id,
        subject_hmac: &[u8; 32],
    ) -> impl Future<Output = Result<Option<(u32, Vec<u32>)>, StoreError>> + Send;

    /// Active facts whose `expires_at` has passed and that are not under legal hold, oldest first.
    fn due_facts(
        &self,
        domain_id: &Id,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<DueFact>, StoreError>> + Send;

    /// Sets or clears a fact's legal hold. [`StoreError::NotFound`] if there is no such fact, and
    /// [`StoreError::Conflict`] if it is shredded.
    fn set_legal_hold(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
        hold: bool,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Moves an active fact to another scope without touching its encryption (REQUIREMENTS F8).
    fn rebind_scope(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
        scope_hmac: &[u8; 32],
        bik_version: u32,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Stores several facts in one transaction: all of them or none. The same checks as [`KeyStore::insert_fact`]
    /// apply to each.
    fn insert_facts(
        &self,
        facts: &[NewFact],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Every registered issuer.
    fn issuers(&self) -> impl Future<Output = Result<Vec<IssuerRecord>, StoreError>> + Send;

    /// Registers an issuer, enabled. [`StoreError::AlreadyExists`] if the name is taken.
    fn create_issuer(
        &self,
        name: &str,
        public_key: &[u8; 32],
        roles: &[String],
    ) -> impl Future<Output = Result<IssuerRecord, StoreError>> + Send;

    /// Enables or disables an issuer. [`StoreError::NotFound`] if there is none.
    fn set_issuer_enabled(
        &self,
        key_id: u32,
        enabled: bool,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The newest policy, or `None` if none was ever set.
    fn current_policy(
        &self,
    ) -> impl Future<Output = Result<Option<PolicyRecord>, StoreError>> + Send;

    /// Stores a new policy version. Old versions are kept.
    fn put_policy(
        &self,
        json: &[u8],
        hash: &[u8; 32],
        created_by: &str,
    ) -> impl Future<Output = Result<PolicyRecord, StoreError>> + Send;

    /// Records a request for an approval.
    fn create_approval(
        &self,
        new: &NewApproval,
    ) -> impl Future<Output = Result<ApprovalRecord, StoreError>> + Send;

    /// Approves a pending request as `approver`, who must not be the requester, before it expires.
    /// [`StoreError::Conflict`] otherwise.
    fn approve(
        &self,
        id: &Uuid,
        approver: &str,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<ApprovalRecord, StoreError>> + Send;

    /// Uses an approval, once: it must be approved, unused, unexpired at `now`, and for this fact in this
    /// domain. Any other case is [`StoreError::Conflict`], and a second use fails.
    fn consume_approval(
        &self,
        domain_id: &Id,
        id: &Uuid,
        fact_id: &FactId,
        now: OffsetDateTime,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// The newest audit entry of a domain, or `None` if the log is empty.
    fn audit_head(
        &self,
        domain_id: &Id,
    ) -> impl Future<Output = Result<Option<LedgerHead>, StoreError>> + Send;

    /// Appends entries to a domain's audit log in one transaction. `entries[0]` must follow the head, and each
    /// entry the one before it. [`StoreError::Conflict`] if the log moved, so the caller reads the head and
    /// tries again.
    fn append_audit(
        &self,
        domain_id: &Id,
        entries: &[AuditAppend],
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Audit entries from `from_seq` on, oldest first, at most `limit`. For verification and export.
    fn audit_records(
        &self,
        domain_id: &Id,
        from_seq: u64,
        limit: u32,
    ) -> impl Future<Output = Result<Vec<AuditRecord>, StoreError>> + Send;

    /// Audit entries matching a filter, oldest first.
    fn audit_query(
        &self,
        domain_id: &Id,
        filter: &AuditFilter,
    ) -> impl Future<Output = Result<Vec<AuditRecord>, StoreError>> + Send;

    /// Stores a blob's row: like [`KeyStore::insert_fact`], with `kind = blob`, not yet ready. `fact.size_class`
    /// is ignored and stored as 0. `fact.expires_at` should be short, so an upload nobody finishes is cleaned up.
    fn insert_blob(
        &self,
        fact: &NewFact,
        chunk_size: u32,
        len: u64,
        final_expires_at: Option<OffsetDateTime>,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;

    /// Marks a blob ready after its upload was checked, and gives it the expiry it was created with.
    /// [`StoreError::Conflict`] if it is not an active blob that is waiting for completion.
    fn complete_blob(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
    ) -> impl Future<Output = Result<(), StoreError>> + Send;
}
