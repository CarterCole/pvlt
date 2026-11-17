//! In-process key store and object store, for tests and for running the engine without a database.
//!
//! [`MemKeyStore`] keeps the guarantees of the [`KeyStore`] trait (shredded rows hold zeros and never change,
//! an insert is refused once its subject is shredded) but only inside one process and one lock, so it proves
//! the engine's logic and not the database's concurrency behaviour. The Postgres suite does that.
//! Nothing here is persisted. Do not use it for real data.

use std::collections::HashMap;
use std::sync::{Mutex, MutexGuard, PoisonError};

use pvlt_format::Id;
use pvlt_format::wrap::{SignPurpose, WRAPPED_LEN};
use time::OffsetDateTime;

use crate::keys::{WrappedDomainKeys, WrappedSigningKey, WrappedSubjectKey};
use crate::objects::{ObjectError, ObjectInfo, ObjectKey, ObjectStore};
use crate::seal::SealConfig;
use crate::store::{
    ApprovalRecord, AuditAppend, AuditFilter, AuditRecord, BlobInfo, Destroyed, DomainRecord,
    DueFact, FactBundle, FactId, FactKind, FactRecord, IssuerRecord, KeyStore, LedgerAppend,
    LedgerHead, LedgerRecord, NewApproval, NewFact, NewSubjectKey, PolicyRecord, ReplayEffect,
    ShredFact, ShredPlan, ShredSubject, State, StoreError, SubjectKeyRecord,
};
use uuid::Uuid;

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

fn zeros() -> Vec<u8> {
    vec![0; WRAPPED_LEN]
}

#[derive(Default, Clone)]
struct KeyState {
    seal: Option<SealConfig>,
    domains: HashMap<Id, DomainRecord>,
    subjects: HashMap<(Id, [u8; 32]), Vec<SubjectKeyRecord>>,
    facts: HashMap<(Id, FactId), FactRecord>,
    sign_keys: HashMap<(Id, u8), WrappedSigningKey>,
    ledgers: HashMap<Id, Vec<LedgerRecord>>,
    audits: HashMap<Id, Vec<AuditRecord>>,
    issuers: Vec<IssuerRecord>,
    policies: Vec<PolicyRecord>,
    approvals: HashMap<Uuid, ApprovalRecord>,
}

fn purpose_byte(p: SignPurpose) -> u8 {
    match p {
        SignPurpose::Ledger => 0,
        SignPurpose::Checkpoint => 1,
    }
}

fn zero_wrapped_domain(keys: &WrappedDomainKeys) -> WrappedDomainKeys {
    WrappedDomainKeys {
        kek: zeros(),
        bik: zeros(),
        bix: zeros(),
        ..keys.clone()
    }
}

impl KeyState {
    fn head(&self, domain_id: &Id) -> Option<LedgerHead> {
        self.ledgers
            .get(domain_id)
            .and_then(|l| l.last())
            .map(|r| LedgerHead {
                seq: r.seq,
                hash: r.hash,
            })
    }

    /// The ledger must move by exactly one entry from the head the caller saw.
    fn check_append(&self, domain_id: &Id, a: &LedgerAppend) -> Result<(), StoreError> {
        let (seq, prev) = match self.head(domain_id) {
            Some(h) => (h.seq + 1, h.hash),
            None => (0, [0u8; 32]),
        };
        if a.seq != seq || a.prev != prev {
            return Err(StoreError::Conflict("ledger moved"));
        }
        Ok(())
    }

    fn push_ledger(&mut self, domain_id: &Id, a: &LedgerAppend, published: bool) {
        self.ledgers
            .entry(*domain_id)
            .or_default()
            .push(LedgerRecord {
                seq: a.seq,
                hash: a.hash,
                line: a.line.clone(),
                published,
            });
    }

    fn destroy_fact(&mut self, key: &(Id, FactId)) {
        if let Some(f) = self.facts.get_mut(key) {
            f.state = State::Shredded;
            f.shredded_at = Some(OffsetDateTime::now_utc());
            f.fact.dek.wrapped = zeros();
        }
    }

    fn destroy_subject_facts(&mut self, domain_id: &Id, subject_hmac: &[u8; 32]) {
        let keys: Vec<_> = self
            .active_facts(domain_id)
            .filter(|f| f.fact.subject_hmac == *subject_hmac)
            .map(|f| (*domain_id, f.fact.fact_id))
            .collect();
        for k in keys {
            self.destroy_fact(&k);
        }
    }

    fn active_facts<'a>(&'a self, domain_id: &'a Id) -> impl Iterator<Item = &'a FactRecord> + 'a {
        self.facts
            .values()
            .filter(move |f| f.fact.domain_id == *domain_id && f.state == State::Active)
    }
}

fn sorted<T: Ord + Clone>(v: &[T]) -> Vec<T> {
    let mut v = v.to_vec();
    v.sort();
    v
}

/// A key store that lives in memory.
#[derive(Default)]
pub struct MemKeyStore {
    state: Mutex<KeyState>,
    fail_audit: std::sync::atomic::AtomicBool,
    audit_appends: std::sync::atomic::AtomicUsize,
}

impl MemKeyStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every wrapped key and id the store holds, as one byte string, for tests that look for plaintext.
    pub fn dump(&self) -> Vec<u8> {
        let s = lock(&self.state);
        let mut out = Vec::new();
        for d in s.domains.values() {
            out.extend_from_slice(&d.domain_id);
            out.extend_from_slice(&d.keys.kek);
            out.extend_from_slice(&d.keys.bik);
            out.extend_from_slice(&d.keys.bix);
        }
        for k in s.subjects.values().flatten() {
            out.extend_from_slice(&k.subject_hmac);
            out.extend_from_slice(&k.key.wrapped);
        }
        for f in s.facts.values() {
            out.extend_from_slice(f.fact.fact_type.as_bytes());
            out.extend_from_slice(&f.fact.subject_hmac);
            out.extend_from_slice(&f.fact.scope_hmac);
            out.extend_from_slice(&f.fact.dek.wrapped);
        }
        out
    }

    /// A deep copy of the whole key store, standing in for a database backup in tests.
    pub fn snapshot(&self) -> MemKeyStore {
        MemKeyStore {
            state: Mutex::new(lock(&self.state).clone()),
            ..Self::default()
        }
    }

    /// Makes every audit append fail, to show that a read then fails closed.
    pub fn set_audit_failure(&self, fail: bool) {
        self.fail_audit
            .store(fail, std::sync::atomic::Ordering::SeqCst);
    }

    /// How many times the audit log was appended to (batches, not entries).
    pub fn audit_append_calls(&self) -> usize {
        self.audit_appends.load(std::sync::atomic::Ordering::SeqCst)
    }

    /// For tamper tests: drops audit entries from `keep` on, as a truncation or a restore would.
    pub fn truncate_audit(&self, domain_id: &Id, keep: usize) {
        if let Some(l) = lock(&self.state).audits.get_mut(domain_id) {
            l.truncate(keep);
        }
    }

    /// For tamper tests: replaces the line of an audit entry, leaving everything else as it was.
    pub fn replace_audit_line(&self, domain_id: &Id, seq: u64, line: Vec<u8>) {
        if let Some(r) = lock(&self.state)
            .audits
            .get_mut(domain_id)
            .and_then(|l| l.iter_mut().find(|r| r.seq == seq))
        {
            r.line = line;
        }
    }

    /// For tamper tests: replaces an audit entry completely, line, hash and columns, as an attacker who could
    /// write the table would. The chain stays valid if it was the last entry.
    pub fn replace_audit_entry(&self, domain_id: &Id, seq: u64, with: AuditAppend) {
        if let Some(r) = lock(&self.state)
            .audits
            .get_mut(domain_id)
            .and_then(|l| l.iter_mut().find(|r| r.seq == seq))
        {
            *r = AuditRecord {
                seq,
                prev: with.prev,
                hash: with.hash,
                line: with.line,
                at: with.at,
                kind: with.kind,
                principal: with.principal,
                fact_id: with.fact_id,
                subject_hmac: with.subject_hmac,
            };
        }
    }
}

impl KeyStore for MemKeyStore {
    async fn ping(&self) -> Result<(), StoreError> {
        Ok(())
    }

    async fn seal_config(&self) -> Result<Option<SealConfig>, StoreError> {
        Ok(lock(&self.state).seal.clone())
    }

    async fn init_seal_config(&self, config: &SealConfig) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        if s.seal.is_some() {
            return Err(StoreError::AlreadyExists);
        }
        s.seal = Some(config.clone());
        Ok(())
    }

    async fn create_domain(
        &self,
        domain_id: &Id,
        keys: &WrappedDomainKeys,
    ) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        if s.domains.contains_key(domain_id) {
            return Err(StoreError::AlreadyExists);
        }
        s.domains.insert(
            *domain_id,
            DomainRecord {
                domain_id: *domain_id,
                keys: keys.clone(),
                state: State::Active,
                created_at: OffsetDateTime::now_utc(),
            },
        );
        Ok(())
    }

    async fn domain(&self, domain_id: &Id) -> Result<DomainRecord, StoreError> {
        lock(&self.state)
            .domains
            .get(domain_id)
            .cloned()
            .ok_or(StoreError::NotFound)
    }

    async fn subject_key(
        &self,
        domain_id: &Id,
        subject_hmac: &[u8; 32],
    ) -> Result<Option<SubjectKeyRecord>, StoreError> {
        Ok(lock(&self.state)
            .subjects
            .get(&(*domain_id, *subject_hmac))
            .and_then(|v| v.iter().max_by_key(|k| k.key.version).cloned()))
    }

    async fn get_or_insert_subject_key(
        &self,
        new: &NewSubjectKey,
    ) -> Result<SubjectKeyRecord, StoreError> {
        let mut s = lock(&self.state);
        if !s.domains.contains_key(&new.domain_id) {
            return Err(StoreError::Conflict("domain does not exist"));
        }
        let versions = s
            .subjects
            .entry((new.domain_id, new.subject_hmac))
            .or_default();
        if let Some(current) = versions.iter().max_by_key(|k| k.key.version) {
            return Ok(current.clone());
        }
        let record = SubjectKeyRecord {
            domain_id: new.domain_id,
            subject_hmac: new.subject_hmac,
            bik_version: new.bik_version,
            key: new.key.clone(),
            state: State::Active,
        };
        versions.push(record.clone());
        Ok(record)
    }

    async fn shred_subject_key(
        &self,
        domain_id: &Id,
        subject_hmac: &[u8; 32],
    ) -> Result<ShredSubject, StoreError> {
        let mut s = lock(&self.state);
        let Some(versions) = s.subjects.get_mut(&(*domain_id, *subject_hmac)) else {
            return Ok(ShredSubject::NotFound);
        };
        if versions.iter().all(|k| k.state == State::Shredded) {
            return Ok(ShredSubject::AlreadyShredded);
        }
        for k in versions.iter_mut().filter(|k| k.state == State::Active) {
            k.state = State::Shredded;
            k.key = WrappedSubjectKey {
                wrapped: zeros(),
                ..k.key.clone()
            };
        }
        Ok(ShredSubject::Shredded)
    }

    async fn insert_fact(&self, fact: &NewFact) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        let key = s
            .subjects
            .get(&(fact.domain_id, fact.subject_hmac))
            .and_then(|v| {
                v.iter()
                    .find(|k| k.key.version == fact.dek.subject_key_version)
            })
            .ok_or(StoreError::Conflict("subject key does not exist"))?;
        if key.state == State::Shredded {
            return Err(StoreError::SubjectShredded);
        }
        if s.facts.contains_key(&(fact.domain_id, fact.fact_id)) {
            return Err(StoreError::AlreadyExists);
        }
        if s.facts
            .values()
            .any(|f| f.fact.domain_id == fact.domain_id && f.fact.object_id == fact.object_id)
        {
            return Err(StoreError::Conflict("object id already in use"));
        }
        s.facts.insert(
            (fact.domain_id, fact.fact_id),
            FactRecord {
                fact: fact.clone(),
                state: State::Active,
                created_at: OffsetDateTime::now_utc(),
                shredded_at: None,
                kind: FactKind::Fact,
                blob: None,
            },
        );
        Ok(())
    }

    async fn fact_for_read(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
    ) -> Result<FactBundle, StoreError> {
        let s = lock(&self.state);
        let fact = s
            .facts
            .get(&(*domain_id, *fact_id))
            .ok_or(StoreError::NotFound)?;
        let subject_key = s
            .subjects
            .get(&(*domain_id, fact.fact.subject_hmac))
            .and_then(|v| {
                v.iter()
                    .find(|k| k.key.version == fact.fact.dek.subject_key_version)
            })
            .ok_or(StoreError::Corrupt("fact without a subject key"))?;
        let domain = s
            .domains
            .get(domain_id)
            .ok_or(StoreError::Corrupt("fact without a domain"))?;
        Ok(FactBundle {
            fact: fact.clone(),
            subject_key: subject_key.clone(),
            domain: domain.clone(),
        })
    }

    async fn shred_fact(&self, domain_id: &Id, fact_id: &FactId) -> Result<ShredFact, StoreError> {
        let mut s = lock(&self.state);
        let Some(f) = s.facts.get_mut(&(*domain_id, *fact_id)) else {
            return Ok(ShredFact::NotFound);
        };
        if f.state == State::Shredded {
            return Ok(ShredFact::AlreadyShredded);
        }
        if f.fact.legal_hold {
            return Err(StoreError::LegalHold);
        }
        f.state = State::Shredded;
        f.shredded_at = Some(OffsetDateTime::now_utc());
        f.fact.dek.wrapped = zeros();
        Ok(ShredFact::Shredded {
            object_id: f.fact.object_id,
        })
    }

    async fn live_object_ids(
        &self,
        domain_id: &Id,
        object_ids: &[Id],
    ) -> Result<Vec<Id>, StoreError> {
        let s = lock(&self.state);
        Ok(s.facts
            .values()
            .filter(|f| f.fact.domain_id == *domain_id && f.state == State::Active)
            .filter(|f| object_ids.contains(&f.fact.object_id))
            .filter(|f| {
                s.subjects
                    .get(&(*domain_id, f.fact.subject_hmac))
                    .is_some_and(|v| {
                        v.iter().any(|k| {
                            k.key.version == f.fact.dek.subject_key_version
                                && k.state == State::Active
                        })
                    })
            })
            .map(|f| f.fact.object_id)
            .collect())
    }

    async fn audit_head(&self, domain_id: &Id) -> Result<Option<LedgerHead>, StoreError> {
        Ok(lock(&self.state)
            .audits
            .get(domain_id)
            .and_then(|l| l.last())
            .map(|r| LedgerHead {
                seq: r.seq,
                hash: r.hash,
            }))
    }

    async fn append_audit(
        &self,
        domain_id: &Id,
        entries: &[AuditAppend],
    ) -> Result<(), StoreError> {
        self.audit_appends
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        if self.fail_audit.load(std::sync::atomic::Ordering::SeqCst) {
            return Err(StoreError::Backend("the audit log is down".into()));
        }
        let mut s = lock(&self.state);
        if !s.domains.contains_key(domain_id) {
            return Err(StoreError::Conflict("domain does not exist"));
        }
        let log = s.audits.entry(*domain_id).or_default();
        let (mut seq, mut prev) = match log.last() {
            Some(r) => (r.seq + 1, r.hash),
            None => (0, [0u8; 32]),
        };
        for e in entries {
            if e.seq != seq || e.prev != prev {
                return Err(StoreError::Conflict("audit log moved"));
            }
            seq += 1;
            prev = e.hash;
        }
        for e in entries {
            log.push(AuditRecord {
                seq: e.seq,
                prev: e.prev,
                hash: e.hash,
                line: e.line.clone(),
                at: e.at,
                kind: e.kind.clone(),
                principal: e.principal.clone(),
                fact_id: e.fact_id,
                subject_hmac: e.subject_hmac,
            });
        }
        Ok(())
    }

    async fn audit_records(
        &self,
        domain_id: &Id,
        from_seq: u64,
        limit: u32,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        Ok(lock(&self.state)
            .audits
            .get(domain_id)
            .map(|l| {
                l.iter()
                    .filter(|r| r.seq >= from_seq)
                    .take(usize::try_from(limit).unwrap_or(usize::MAX))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn audit_query(
        &self,
        domain_id: &Id,
        f: &AuditFilter,
    ) -> Result<Vec<AuditRecord>, StoreError> {
        Ok(lock(&self.state)
            .audits
            .get(domain_id)
            .map(|l| {
                l.iter()
                    .filter(|r| f.after_seq.is_none_or(|a| r.seq > a))
                    .filter(|r| f.subject_hmac.is_none_or(|h| r.subject_hmac == Some(h)))
                    .filter(|r| f.principal.as_ref().is_none_or(|p| &r.principal == p))
                    .filter(|r| f.fact_id.is_none_or(|x| r.fact_id == Some(x)))
                    .filter(|r| f.kind.as_ref().is_none_or(|k| &r.kind == k))
                    .filter(|r| f.from.is_none_or(|t| r.at >= t))
                    .filter(|r| f.to.is_none_or(|t| r.at < t))
                    .take(usize::try_from(f.limit).unwrap_or(usize::MAX))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default())
    }

    async fn insert_facts(&self, facts: &[NewFact]) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        // Check everything first, so a failure leaves nothing behind.
        for (i, fact) in facts.iter().enumerate() {
            let key = s
                .subjects
                .get(&(fact.domain_id, fact.subject_hmac))
                .and_then(|v| {
                    v.iter()
                        .find(|k| k.key.version == fact.dek.subject_key_version)
                })
                .ok_or(StoreError::Conflict("subject key does not exist"))?;
            if key.state == State::Shredded {
                return Err(StoreError::SubjectShredded);
            }
            let dup_in_batch = facts.iter().take(i).any(|o| {
                o.domain_id == fact.domain_id
                    && (o.fact_id == fact.fact_id || o.object_id == fact.object_id)
            });
            if dup_in_batch || s.facts.contains_key(&(fact.domain_id, fact.fact_id)) {
                return Err(StoreError::AlreadyExists);
            }
            if s.facts
                .values()
                .any(|f| f.fact.domain_id == fact.domain_id && f.fact.object_id == fact.object_id)
            {
                return Err(StoreError::Conflict("object id already in use"));
            }
        }
        for fact in facts {
            s.facts.insert(
                (fact.domain_id, fact.fact_id),
                FactRecord {
                    fact: fact.clone(),
                    state: State::Active,
                    created_at: OffsetDateTime::now_utc(),
                    shredded_at: None,
                    kind: FactKind::Fact,
                    blob: None,
                },
            );
        }
        Ok(())
    }

    async fn insert_blob(
        &self,
        fact: &NewFact,
        chunk_size: u32,
        len: u64,
        final_expires_at: Option<OffsetDateTime>,
    ) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        let key = s
            .subjects
            .get(&(fact.domain_id, fact.subject_hmac))
            .and_then(|v| {
                v.iter()
                    .find(|k| k.key.version == fact.dek.subject_key_version)
            })
            .ok_or(StoreError::Conflict("subject key does not exist"))?;
        if key.state == State::Shredded {
            return Err(StoreError::SubjectShredded);
        }
        if s.facts.contains_key(&(fact.domain_id, fact.fact_id)) {
            return Err(StoreError::AlreadyExists);
        }
        if s.facts
            .values()
            .any(|f| f.fact.domain_id == fact.domain_id && f.fact.object_id == fact.object_id)
        {
            return Err(StoreError::Conflict("object id already in use"));
        }
        let mut stored = fact.clone();
        stored.size_class = 0;
        s.facts.insert(
            (fact.domain_id, fact.fact_id),
            FactRecord {
                fact: stored,
                state: State::Active,
                created_at: OffsetDateTime::now_utc(),
                shredded_at: None,
                kind: FactKind::Blob,
                blob: Some(BlobInfo {
                    chunk_size,
                    len,
                    ready: false,
                    final_expires_at,
                }),
            },
        );
        Ok(())
    }

    async fn complete_blob(&self, domain_id: &Id, fact_id: &FactId) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        let f = s
            .facts
            .get_mut(&(*domain_id, *fact_id))
            .ok_or(StoreError::NotFound)?;
        match (&mut f.blob, f.state) {
            (Some(b), State::Active) if !b.ready => {
                b.ready = true;
                f.fact.expires_at = b.final_expires_at;
                Ok(())
            }
            _ => Err(StoreError::Conflict("not a blob waiting for completion")),
        }
    }

    async fn issuers(&self) -> Result<Vec<IssuerRecord>, StoreError> {
        Ok(lock(&self.state).issuers.clone())
    }

    async fn create_issuer(
        &self,
        name: &str,
        public_key: &[u8; 32],
        roles: &[String],
    ) -> Result<IssuerRecord, StoreError> {
        let mut s = lock(&self.state);
        if s.issuers.iter().any(|i| i.name == name) {
            return Err(StoreError::AlreadyExists);
        }
        let rec = IssuerRecord {
            key_id: u32::try_from(s.issuers.len() + 1).unwrap_or(u32::MAX),
            name: name.to_owned(),
            public_key: *public_key,
            roles: roles.to_vec(),
            enabled: true,
        };
        s.issuers.push(rec.clone());
        Ok(rec)
    }

    async fn set_issuer_enabled(&self, key_id: u32, enabled: bool) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        let i = s
            .issuers
            .iter_mut()
            .find(|i| i.key_id == key_id)
            .ok_or(StoreError::NotFound)?;
        i.enabled = enabled;
        Ok(())
    }

    async fn current_policy(&self) -> Result<Option<PolicyRecord>, StoreError> {
        Ok(lock(&self.state).policies.last().cloned())
    }

    async fn put_policy(
        &self,
        json: &[u8],
        hash: &[u8; 32],
        created_by: &str,
    ) -> Result<PolicyRecord, StoreError> {
        let mut s = lock(&self.state);
        let rec = PolicyRecord {
            version: i64::try_from(s.policies.len() + 1).unwrap_or(i64::MAX),
            json: json.to_vec(),
            hash: *hash,
            created_by: created_by.to_owned(),
        };
        s.policies.push(rec.clone());
        Ok(rec)
    }

    async fn create_approval(&self, new: &NewApproval) -> Result<ApprovalRecord, StoreError> {
        let mut s = lock(&self.state);
        if s.approvals.contains_key(&new.id) {
            return Err(StoreError::AlreadyExists);
        }
        let rec = ApprovalRecord {
            id: new.id,
            domain_id: new.domain_id,
            fact_id: new.fact_id,
            requested_by: new.requested_by.clone(),
            approved_by: new.break_glass.then(|| new.requested_by.clone()),
            break_glass: new.break_glass,
            expires_at: new.expires_at,
            used: false,
        };
        s.approvals.insert(new.id, rec.clone());
        Ok(rec)
    }

    async fn approve(
        &self,
        id: &Uuid,
        approver: &str,
        now: OffsetDateTime,
    ) -> Result<ApprovalRecord, StoreError> {
        let mut s = lock(&self.state);
        let a = s.approvals.get_mut(id).ok_or(StoreError::NotFound)?;
        if a.approved_by.is_some() {
            return Err(StoreError::Conflict("already approved"));
        }
        if a.expires_at <= now {
            return Err(StoreError::Conflict("the request expired"));
        }
        if a.requested_by == approver {
            return Err(StoreError::Conflict(
                "an approver must not be the requester",
            ));
        }
        a.approved_by = Some(approver.to_owned());
        Ok(a.clone())
    }

    async fn consume_approval(
        &self,
        domain_id: &Id,
        id: &Uuid,
        fact_id: &FactId,
        now: OffsetDateTime,
    ) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        let a = s
            .approvals
            .get_mut(id)
            .ok_or(StoreError::Conflict("approval is not valid"))?;
        if a.domain_id != *domain_id
            || a.fact_id != *fact_id
            || a.approved_by.is_none()
            || a.used
            || a.expires_at <= now
        {
            return Err(StoreError::Conflict("approval is not valid"));
        }
        a.used = true;
        Ok(())
    }

    async fn list_domains(&self) -> Result<Vec<Id>, StoreError> {
        let mut v: Vec<Id> = lock(&self.state).domains.keys().copied().collect();
        v.sort();
        Ok(v)
    }

    async fn sign_key(
        &self,
        domain_id: &Id,
        purpose: SignPurpose,
    ) -> Result<Option<WrappedSigningKey>, StoreError> {
        Ok(lock(&self.state)
            .sign_keys
            .get(&(*domain_id, purpose_byte(purpose)))
            .cloned())
    }

    async fn get_or_insert_sign_key(
        &self,
        domain_id: &Id,
        key: &WrappedSigningKey,
    ) -> Result<WrappedSigningKey, StoreError> {
        let mut s = lock(&self.state);
        if !s.domains.contains_key(domain_id) {
            return Err(StoreError::Conflict("domain does not exist"));
        }
        Ok(s.sign_keys
            .entry((*domain_id, purpose_byte(key.purpose)))
            .or_insert_with(|| key.clone())
            .clone())
    }

    async fn ledger_head(&self, domain_id: &Id) -> Result<Option<LedgerHead>, StoreError> {
        Ok(lock(&self.state).head(domain_id))
    }

    async fn ledger_records(
        &self,
        domain_id: &Id,
        from_seq: u64,
    ) -> Result<Vec<LedgerRecord>, StoreError> {
        Ok(lock(&self.state)
            .ledgers
            .get(domain_id)
            .map(|l| l.iter().filter(|r| r.seq >= from_seq).cloned().collect())
            .unwrap_or_default())
    }

    async fn ledger_unpublished(&self, domain_id: &Id) -> Result<Vec<LedgerRecord>, StoreError> {
        Ok(lock(&self.state)
            .ledgers
            .get(domain_id)
            .map(|l| l.iter().filter(|r| !r.published).cloned().collect())
            .unwrap_or_default())
    }

    async fn ledger_mark_published(&self, domain_id: &Id, seq: u64) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        let rec = s
            .ledgers
            .get_mut(domain_id)
            .and_then(|l| l.iter_mut().find(|r| r.seq == seq))
            .ok_or(StoreError::NotFound)?;
        rec.published = true;
        Ok(())
    }

    async fn apply_shred(
        &self,
        domain_id: &Id,
        plan: &ShredPlan,
        append: &LedgerAppend,
    ) -> Result<Destroyed, StoreError> {
        let mut s = lock(&self.state);
        if !s.domains.contains_key(domain_id) {
            return Err(StoreError::NotFound);
        }
        s.check_append(domain_id, append)?;
        let mut destroyed = Destroyed::default();
        match plan {
            ShredPlan::Facts { fact_ids } => {
                for id in fact_ids {
                    let f = s
                        .facts
                        .get(&(*domain_id, *id))
                        .ok_or(StoreError::Conflict("plan names an unknown fact"))?;
                    if f.state != State::Active {
                        return Err(StoreError::Conflict("plan names a shredded fact"));
                    }
                    if f.fact.legal_hold {
                        return Err(StoreError::LegalHold);
                    }
                }
                for id in fact_ids {
                    if let Some(f) = s.facts.get(&(*domain_id, *id)) {
                        destroyed.object_ids.push(f.fact.object_id);
                    }
                    s.destroy_fact(&(*domain_id, *id));
                }
            }
            ShredPlan::Scope {
                scope_hmac,
                fact_ids,
            } => {
                let now: Vec<_> = s
                    .active_facts(domain_id)
                    .filter(|f| f.fact.scope_hmac == *scope_hmac)
                    .collect();
                if sorted(&now.iter().map(|f| f.fact.fact_id).collect::<Vec<_>>())
                    != sorted(fact_ids)
                {
                    return Err(StoreError::Conflict("scope changed since the plan"));
                }
                if now.iter().any(|f| f.fact.legal_hold) {
                    return Err(StoreError::LegalHold);
                }
                destroyed.object_ids = now.iter().map(|f| f.fact.object_id).collect();
                for id in fact_ids {
                    s.destroy_fact(&(*domain_id, *id));
                }
            }
            ShredPlan::Subject {
                subject_hmac,
                versions,
            } => {
                let active: Vec<u32> = s
                    .subjects
                    .get(&(*domain_id, *subject_hmac))
                    .map(|v| {
                        v.iter()
                            .filter(|k| k.state == State::Active)
                            .map(|k| k.key.version)
                            .collect()
                    })
                    .unwrap_or_default();
                if sorted(&active) != sorted(versions) || active.is_empty() {
                    return Err(StoreError::Conflict("subject changed since the plan"));
                }
                let under: Vec<_> = s
                    .active_facts(domain_id)
                    .filter(|f| f.fact.subject_hmac == *subject_hmac)
                    .collect();
                if under.iter().any(|f| f.fact.legal_hold) {
                    return Err(StoreError::LegalHold);
                }
                destroyed.object_ids = under.iter().map(|f| f.fact.object_id).collect();
                if let Some(rows) = s.subjects.get_mut(&(*domain_id, *subject_hmac)) {
                    for k in rows.iter_mut().filter(|k| k.state == State::Active) {
                        k.state = State::Shredded;
                        k.key.wrapped = zeros();
                    }
                }
                s.destroy_subject_facts(domain_id, subject_hmac);
            }
            ShredPlan::Domain => {
                if s.active_facts(domain_id).any(|f| f.fact.legal_hold) {
                    return Err(StoreError::LegalHold);
                }
                destroyed.object_ids = s
                    .active_facts(domain_id)
                    .map(|f| f.fact.object_id)
                    .collect();
                shred_domain_state(&mut s, domain_id);
            }
        }
        s.push_ledger(domain_id, append, false);
        Ok(destroyed)
    }

    async fn replay_entry(
        &self,
        domain_id: &Id,
        effect: &ReplayEffect,
        append: &LedgerAppend,
    ) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        let kek_version = s
            .domains
            .get(domain_id)
            .ok_or(StoreError::NotFound)?
            .keys
            .kek_version;
        s.check_append(domain_id, append)?;
        match effect {
            ReplayEffect::Objects { object_ids } => {
                let keys: Vec<_> = s
                    .active_facts(domain_id)
                    .filter(|f| object_ids.contains(&f.fact.object_id))
                    .map(|f| (*domain_id, f.fact.fact_id))
                    .collect();
                for k in keys {
                    s.destroy_fact(&k);
                }
            }
            ReplayEffect::Subject {
                subject_hmac,
                bik_version,
                versions,
            } => {
                let rows = s.subjects.entry((*domain_id, *subject_hmac)).or_default();
                for v in versions {
                    match rows.iter_mut().find(|k| k.key.version == *v) {
                        Some(k) => {
                            k.state = State::Shredded;
                            k.key.wrapped = zeros();
                        }
                        None => rows.push(SubjectKeyRecord {
                            domain_id: *domain_id,
                            subject_hmac: *subject_hmac,
                            bik_version: *bik_version,
                            key: WrappedSubjectKey {
                                version: *v,
                                kek_version,
                                wrapped: zeros(),
                            },
                            state: State::Shredded,
                        }),
                    }
                }
                s.destroy_subject_facts(domain_id, subject_hmac);
            }
            ReplayEffect::Domain => shred_domain_state(&mut s, domain_id),
        }
        s.push_ledger(domain_id, append, true);
        Ok(())
    }

    async fn active_facts_in_scope(
        &self,
        domain_id: &Id,
        scope_hmac: &[u8; 32],
    ) -> Result<Vec<(FactId, Id)>, StoreError> {
        let s = lock(&self.state);
        let mut v: Vec<_> = s
            .active_facts(domain_id)
            .filter(|f| f.fact.scope_hmac == *scope_hmac)
            .map(|f| (f.fact.fact_id, f.fact.object_id))
            .collect();
        v.sort();
        Ok(v)
    }

    async fn subject_active_versions(
        &self,
        domain_id: &Id,
        subject_hmac: &[u8; 32],
    ) -> Result<Option<(u32, Vec<u32>)>, StoreError> {
        let s = lock(&self.state);
        Ok(s.subjects
            .get(&(*domain_id, *subject_hmac))
            .and_then(|rows| {
                let bik = rows.first()?.bik_version;
                let mut active: Vec<u32> = rows
                    .iter()
                    .filter(|k| k.state == State::Active)
                    .map(|k| k.key.version)
                    .collect();
                active.sort_unstable();
                Some((bik, active))
            }))
    }

    async fn due_facts(&self, domain_id: &Id, limit: u32) -> Result<Vec<DueFact>, StoreError> {
        let now = OffsetDateTime::now_utc();
        let s = lock(&self.state);
        let mut due: Vec<_> = s
            .active_facts(domain_id)
            .filter(|f| !f.fact.legal_hold && f.fact.expires_at.is_some_and(|t| t <= now))
            .map(|f| (f.fact.expires_at, f.fact.fact_id, f.fact.object_id))
            .collect();
        due.sort();
        Ok(due
            .into_iter()
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .map(|(_, fact_id, object_id)| DueFact { fact_id, object_id })
            .collect())
    }

    async fn set_legal_hold(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
        hold: bool,
    ) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        let f = s
            .facts
            .get_mut(&(*domain_id, *fact_id))
            .ok_or(StoreError::NotFound)?;
        if f.state != State::Active {
            return Err(StoreError::Conflict("fact is shredded"));
        }
        f.fact.legal_hold = hold;
        Ok(())
    }

    async fn rebind_scope(
        &self,
        domain_id: &Id,
        fact_id: &FactId,
        scope_hmac: &[u8; 32],
        bik_version: u32,
    ) -> Result<(), StoreError> {
        let mut s = lock(&self.state);
        let f = s
            .facts
            .get_mut(&(*domain_id, *fact_id))
            .ok_or(StoreError::NotFound)?;
        if f.state != State::Active {
            return Err(StoreError::Conflict("fact is shredded"));
        }
        f.fact.scope_hmac = *scope_hmac;
        f.fact.bik_version = bik_version;
        Ok(())
    }
}

fn shred_domain_state(s: &mut KeyState, domain_id: &Id) {
    if let Some(d) = s.domains.get_mut(domain_id) {
        d.keys = zero_wrapped_domain(&d.keys);
        d.state = State::Shredded;
    }
    for ((d, _), rows) in &mut s.subjects {
        if d == domain_id {
            for k in rows.iter_mut().filter(|k| k.state == State::Active) {
                k.state = State::Shredded;
                k.key.wrapped = zeros();
            }
        }
    }
    let keys: Vec<_> = s
        .facts
        .iter()
        .filter(|((d, _), f)| d == domain_id && f.state == State::Active)
        .map(|(k, _)| *k)
        .collect();
    for k in keys {
        s.destroy_fact(&k);
    }
}

/// An object store that lives in memory.
#[derive(Default)]
pub struct MemObjectStore {
    files: Mutex<HashMap<String, (Vec<u8>, OffsetDateTime)>>,
}

impl MemObjectStore {
    /// An empty store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Every file's bytes joined, for tests that look for plaintext.
    pub fn dump(&self) -> Vec<u8> {
        lock(&self.files)
            .values()
            .flat_map(|(b, _)| b.iter().copied())
            .collect()
    }

    /// How many files there are, of any kind.
    pub fn len(&self) -> usize {
        lock(&self.files).len()
    }

    /// How many sealed objects there are, not counting ledger and checkpoint files.
    pub fn object_count(&self) -> usize {
        lock(&self.files)
            .keys()
            .filter(|p| ObjectKey::from_path(p).is_some())
            .count()
    }

    /// Whether there are none.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Pretends an object was written at `when`, for sweeper tests.
    pub fn backdate(&self, key: &ObjectKey, when: OffsetDateTime) {
        if let Some(entry) = lock(&self.files).get_mut(&key.path()) {
            entry.1 = when;
        }
    }

    /// Whether an object exists.
    pub fn contains(&self, key: &ObjectKey) -> bool {
        lock(&self.files).contains_key(&key.path())
    }

    /// A deep copy, standing in for a bucket backup in tests.
    pub fn snapshot(&self) -> MemObjectStore {
        MemObjectStore {
            files: Mutex::new(lock(&self.files).clone()),
        }
    }
}

impl ObjectStore for MemObjectStore {
    async fn ping(&self) -> Result<(), ObjectError> {
        Ok(())
    }

    async fn put_path(&self, path: &str, bytes: Vec<u8>) -> Result<(), ObjectError> {
        lock(&self.files).insert(path.to_owned(), (bytes, OffsetDateTime::now_utc()));
        Ok(())
    }

    async fn get_path(&self, path: &str) -> Result<Option<Vec<u8>>, ObjectError> {
        Ok(lock(&self.files).get(path).map(|(b, _)| b.clone()))
    }

    async fn delete_path(&self, path: &str) -> Result<(), ObjectError> {
        lock(&self.files).remove(path);
        Ok(())
    }

    async fn head_path(&self, path: &str) -> Result<Option<u64>, ObjectError> {
        Ok(lock(&self.files)
            .get(path)
            .map(|(b, _)| u64::try_from(b.len()).unwrap_or(u64::MAX)))
    }

    async fn get_range(
        &self,
        path: &str,
        start: u64,
        len: u64,
    ) -> Result<Option<Vec<u8>>, ObjectError> {
        Ok(lock(&self.files).get(path).map(|(b, _)| {
            let from = usize::try_from(start).unwrap_or(usize::MAX).min(b.len());
            let to = usize::try_from(start.saturating_add(len))
                .unwrap_or(usize::MAX)
                .min(b.len());
            b.get(from..to).unwrap_or_default().to_vec()
        }))
    }

    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, ObjectInfo)>, ObjectError> {
        Ok(lock(&self.files)
            .iter()
            .filter(|(p, _)| p.starts_with(prefix))
            .map(|(p, (b, t))| {
                (
                    p.clone(),
                    ObjectInfo {
                        last_modified: *t,
                        size: b.len() as u64,
                    },
                )
            })
            .collect())
    }
}
