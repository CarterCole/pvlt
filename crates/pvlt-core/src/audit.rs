//! What the engine reports about each operation (PLAN.md 3.4).
//!
//! In M1 this is a trait whose implementation writes a log line. The tamper-evident audit log, with an entry
//! made durable before every read and reads that fail closed, is M4. Until then **a read is not audited
//! durably**: do not hold real PII on this.
//!
//! An event never carries a value, a key, a subject or a scope.

use crate::store::FactId;

/// What was attempted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// A fact was created.
    Create,
    /// A fact was read.
    Read,
    /// A fact was shredded.
    ShredFact,
    /// A subject was shredded.
    ShredSubject,
    /// A scope was shredded.
    ShredScope,
    /// A whole domain was shredded.
    ShredDomain,
    /// The retention sweeper expired facts.
    Expire,
    /// A legal hold was set or cleared.
    LegalHold,
    /// A fact was moved to another scope.
    Rebind,
    /// The orphan sweeper ran.
    Sweep,
    /// A durable audit entry could not be written.
    AuditFailure,
}

impl Action {
    /// A stable name for logs.
    pub fn name(self) -> &'static str {
        match self {
            Action::Create => "create",
            Action::Read => "read",
            Action::ShredFact => "shred_fact",
            Action::ShredSubject => "shred_subject",
            Action::ShredScope => "shred_scope",
            Action::ShredDomain => "shred_domain",
            Action::Expire => "expire",
            Action::LegalHold => "legal_hold",
            Action::Rebind => "rebind",
            Action::Sweep => "sweep",
            Action::AuditFailure => "audit_failure",
        }
    }
}

/// One operation and how it ended.
#[derive(Debug, Clone, Copy)]
pub struct AuditEvent<'a> {
    /// Who asked: the name of the principal, never a token.
    pub principal: &'a str,
    /// What they asked for.
    pub action: Action,
    /// The fact, if the operation was about one.
    pub fact_id: Option<FactId>,
    /// `"ok"`, or the name of the error.
    pub outcome: &'static str,
}

/// Receives an event for every engine operation.
pub trait Auditor: Send + Sync {
    /// Records an event. Must not block for long and must not fail the operation.
    fn record(&self, event: &AuditEvent<'_>);
}

/// An auditor that drops every event, for tests.
#[derive(Debug, Default, Clone, Copy)]
pub struct NullAuditor;

impl Auditor for NullAuditor {
    fn record(&self, _event: &AuditEvent<'_>) {}
}
