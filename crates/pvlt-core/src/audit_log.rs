//! The audit log: who did what to which fact, hash-chained and checkpointed (FORMAT.md section 8).
//!
//! Every disclosure is written here **before** the value leaves the vault, and a read fails if the entry cannot be
//! made durable. An entry never holds a value, a key, or a plaintext subject or scope: it holds blind
//! identifiers and the caller's own account of who they are. (A `principal` and a `caller` are the
//! caller's own identifiers, such as `user:77`: they are not PII the vault was asked to protect, but a deployment
//! that uses an email address as a caller id should know that it is written here in the clear.)
//!
//! This module is the pure part: entry types and their JSON. Writing, group commit, checkpoints and verification
//! are in [`crate::engine`].

use pvlt_format::Id;
use pvlt_format::log::{self, Log};
use serde_json::{Map, Value};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::VaultError;
use crate::ledger::format_time;

/// Who is acting and why, as far as the engine is told. A bare `&str` converts to a caller with only a
/// principal, which is what the operator tools and tests use.
#[derive(Debug, Clone, Copy, Default)]
pub struct Caller<'a> {
    /// The acting principal, such as `backend/user:77` or `admin`. Never a token.
    pub principal: &'a str,
    /// The end user on whose behalf it acts, if the token names one.
    pub caller: Option<&'a str>,
    /// The roles the vault accepted for this request.
    pub roles: &'a [String],
    /// The stated purpose.
    pub purpose: Option<&'a str>,
    /// The stated reason.
    pub reason: Option<&'a str>,
    /// The caller's request id.
    pub request_id: Option<&'a str>,
    /// The hash of the policy that decided.
    pub policy_hash: Option<[u8; 32]>,
}

impl<'a> From<&'a str> for Caller<'a> {
    fn from(principal: &'a str) -> Self {
        Self {
            principal,
            ..Self::default()
        }
    }
}

impl<'a> From<&'a String> for Caller<'a> {
    fn from(principal: &'a String) -> Self {
        Self::from(principal.as_str())
    }
}

/// The entry types of FORMAT.md section 8.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// A value or blob key is about to be released.
    ReadGrant,
    /// A granted read could not be completed.
    ReadFail,
    /// A fact was created.
    Create,
    /// Something was shredded.
    Shred,
    /// A fact was moved to another scope.
    Rebind,
    /// Policy refused a request.
    Deny,
    /// An admin-listener action.
    Admin,
}

impl Kind {
    /// The name written to the log.
    pub fn name(self) -> &'static str {
        match self {
            Kind::ReadGrant => "read.grant",
            Kind::ReadFail => "read.fail",
            Kind::Create => "create",
            Kind::Shred => "shred",
            Kind::Rebind => "rebind",
            Kind::Deny => "deny",
            Kind::Admin => "admin",
        }
    }

    /// Reads a name back.
    pub fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "read.grant" => Kind::ReadGrant,
            "read.fail" => Kind::ReadFail,
            "create" => Kind::Create,
            "shred" => Kind::Shred,
            "rebind" => Kind::Rebind,
            "deny" => Kind::Deny,
            "admin" => Kind::Admin,
            _ => return None,
        })
    }
}

/// An entry waiting to be written. Owned, because it waits in a queue for a group commit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Item {
    /// The entry type.
    pub kind: Kind,
    /// Who acted.
    pub principal: String,
    /// The end user, if any.
    pub caller: Option<String>,
    /// The roles accepted.
    pub roles: Vec<String>,
    /// The purpose.
    pub purpose: Option<String>,
    /// The reason.
    pub reason: Option<String>,
    /// What was attempted: `read`, `create`, `shred.subject`, `policy.set`, and so on.
    pub action: String,
    /// The fact, if the entry is about one.
    pub fact_id: Option<Uuid>,
    /// The subject's blind identifier, if known.
    pub subject_hmac: Option<[u8; 32]>,
    /// Why a request was refused: a stable code.
    pub denial: Option<String>,
    /// The caller's request id, or a generated one.
    pub request_id: String,
    /// The hash of the policy in force.
    pub policy_hash: [u8; 32],
}

/// The longest any free-form field may be. Longer is cut, never refused: a long reason must not be a way to
/// stop an entry being written.
pub const MAX_FIELD: usize = 256;

fn clip(s: &str) -> String {
    s.chars().take(MAX_FIELD).collect()
}

impl Item {
    /// Builds an entry from a caller and what happened. `request_id` is what the caller gave, or the engine's.
    pub fn new(
        kind: Kind,
        caller: &Caller<'_>,
        action: &str,
        fact_id: Option<Uuid>,
        subject_hmac: Option<[u8; 32]>,
        denial: Option<&str>,
        generated_request_id: &str,
    ) -> Self {
        Self {
            kind,
            principal: clip(caller.principal),
            caller: caller.caller.map(clip),
            roles: caller.roles.iter().take(32).map(|r| clip(r)).collect(),
            purpose: caller.purpose.map(clip),
            reason: caller.reason.map(clip),
            action: clip(action),
            fact_id,
            subject_hmac,
            denial: denial.map(clip),
            request_id: clip(caller.request_id.unwrap_or(generated_request_id)),
            policy_hash: caller.policy_hash.unwrap_or([0; 32]),
        }
    }

    fn body(&self) -> Value {
        let opt = |v: &Option<String>| v.as_ref().map_or(Value::Null, |s| Value::from(s.as_str()));
        let mut m = Map::new();
        m.insert("principal".into(), self.principal.as_str().into());
        m.insert("caller".into(), opt(&self.caller));
        m.insert(
            "roles".into(),
            Value::Array(self.roles.iter().map(|r| Value::from(r.as_str())).collect()),
        );
        m.insert("purpose".into(), opt(&self.purpose));
        m.insert("reason".into(), opt(&self.reason));
        m.insert("action".into(), self.action.as_str().into());
        m.insert(
            "fact_id".into(),
            self.fact_id
                .map_or(Value::Null, |f| Value::from(f.to_string())),
        );
        m.insert(
            "subject_hmac".into(),
            self.subject_hmac
                .map_or(Value::Null, |h| Value::from(hex::encode(h))),
        );
        m.insert("denial".into(), opt(&self.denial));
        m.insert("request_id".into(), self.request_id.as_str().into());
        m.insert("policy_hash".into(), hex::encode(self.policy_hash).into());
        Value::Object(m)
    }
}

/// An entry ready to store: its JSON, hash and canonical bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Built {
    /// The entry.
    pub json: Value,
    /// Its hash.
    pub hash: [u8; 32],
    /// Its canonical JSON.
    pub line: Vec<u8>,
}

/// Builds the entry at `seq` after `prev`.
pub fn build(
    domain_id: &Id,
    seq: u64,
    prev: &[u8; 32],
    time: OffsetDateTime,
    item: &Item,
) -> Result<Built, VaultError> {
    let json = log::entry(
        Log::Audit,
        domain_id,
        seq,
        &hex::encode(prev),
        &format_time(time),
        item.kind.name(),
        item.body(),
    );
    let hash = log::entry_hash(&json)?;
    let line = log::jcs(&json)?;
    Ok(Built { json, hash, line })
}

/// What an audit line says, read back and checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Parsed {
    /// The sequence number.
    pub seq: u64,
    /// The previous hash.
    pub prev: [u8; 32],
    /// The entry type name.
    pub kind: String,
    /// Who acted.
    pub principal: String,
    /// The fact.
    pub fact_id: Option<Uuid>,
    /// The subject's blind identifier.
    pub subject_hmac: Option<[u8; 32]>,
    /// The entry's hash, recomputed.
    pub hash: [u8; 32],
}

/// Reads a stored line back. The line must be canonical JSON (so it is exactly what was hashed), for this
/// domain, of a known type, with every field the right shape.
pub fn parse(domain_id: &Id, line: &[u8]) -> Result<Parsed, VaultError> {
    let bad = |what: &'static str| VaultError::Invalid(what);
    let v: Value = serde_json::from_slice(line).map_err(|_| bad("audit line is not JSON"))?;
    if log::jcs(&v)? != line {
        return Err(bad("audit line is not canonical"));
    }
    if v.get("log").and_then(Value::as_str) != Some("audit") {
        return Err(bad("not an audit entry"));
    }
    if v.get("domain_id").and_then(Value::as_str) != Some(hex::encode(domain_id).as_str()) {
        return Err(bad("audit entry is for another domain"));
    }
    let hex32 = |x: &Value| -> Option<[u8; 32]> { hex::decode(x.as_str()?).ok()?.try_into().ok() };
    let kind = v
        .get("type")
        .and_then(Value::as_str)
        .filter(|k| Kind::parse(k).is_some())
        .ok_or(bad("audit entry type"))?;
    let body = v.get("body").ok_or(bad("audit body"))?;
    let fact_id = match body.get("fact_id") {
        Some(Value::Null) | None => None,
        Some(x) => Some(
            x.as_str()
                .and_then(|s| Uuid::parse_str(s).ok())
                .ok_or(bad("audit fact id"))?,
        ),
    };
    let subject_hmac = match body.get("subject_hmac") {
        Some(Value::Null) | None => None,
        Some(x) => Some(hex32(x).ok_or(bad("audit subject"))?),
    };
    Ok(Parsed {
        seq: v
            .get("seq")
            .and_then(Value::as_u64)
            .ok_or(bad("audit seq"))?,
        prev: hex32(v.get("prev").ok_or(bad("audit prev"))?).ok_or(bad("audit prev"))?,
        kind: kind.to_owned(),
        principal: body
            .get("principal")
            .and_then(Value::as_str)
            .ok_or(bad("audit principal"))?
            .to_owned(),
        fact_id,
        subject_hmac,
        hash: log::entry_hash(&v)?,
    })
}

// --- Checkpoints ------------------------------------------------------------------------------------------

/// Which log a checkpoint covers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckpointLog {
    /// The audit log.
    Audit,
    /// The shred ledger.
    Ledger,
}

impl CheckpointLog {
    /// The name in the checkpoint and its path.
    pub fn name(self) -> &'static str {
        match self {
            CheckpointLog::Audit => "audit",
            CheckpointLog::Ledger => "ledger",
        }
    }
}

/// `checkpoints/<log>/<hex(domain)>/<20-digit seq>.json` (FORMAT.md section 7).
pub fn checkpoint_path(log: &str, domain_id: &Id, seq: u64) -> String {
    format!("{}{seq:020}.json", checkpoint_prefix(log, domain_id))
}

/// The prefix that holds a domain's checkpoints for a log.
pub fn checkpoint_prefix(log: &str, domain_id: &Id) -> String {
    format!("checkpoints/{log}/{}/", hex::encode(domain_id))
}

/// A checkpoint body (FORMAT.md section 8).
pub fn checkpoint_json(
    log: &str,
    domain_id: &Id,
    seq: u64,
    head: &[u8; 32],
    time: OffsetDateTime,
    policy_hash: &[u8; 32],
    key_id: &Id,
) -> Value {
    let mut m = Map::new();
    m.insert("log".into(), log.into());
    m.insert("domain_id".into(), hex::encode(domain_id).into());
    m.insert("seq".into(), seq.into());
    m.insert("head".into(), hex::encode(head).into());
    m.insert("time".into(), format_time(time).into());
    m.insert("policy_hash".into(), hex::encode(policy_hash).into());
    m.insert("key_id".into(), hex::encode(key_id).into());
    Value::Object(m)
}

/// A checkpoint file: `JCS({"checkpoint": ..., "sig": ...})`.
pub fn checkpoint_file(checkpoint: &Value, sig_hex: &str) -> Result<Vec<u8>, VaultError> {
    let mut m = Map::new();
    m.insert("checkpoint".into(), checkpoint.clone());
    m.insert("sig".into(), sig_hex.into());
    Ok(log::jcs(&Value::Object(m))?)
}

/// Verifies a checkpoint file against the checkpoint public key and returns its body.
pub fn verify_checkpoint_file(public_key: &[u8; 32], bytes: &[u8]) -> Result<Value, VaultError> {
    let v: Value =
        serde_json::from_slice(bytes).map_err(|_| VaultError::Invalid("checkpoint is not JSON"))?;
    if log::jcs(&v)? != bytes {
        return Err(VaultError::Invalid("checkpoint is not canonical"));
    }
    let sig = v
        .get("sig")
        .and_then(Value::as_str)
        .ok_or(VaultError::Invalid("checkpoint has no signature"))?;
    let cp = v
        .get("checkpoint")
        .ok_or(VaultError::Invalid("checkpoint has no body"))?;
    log::checkpoint_verify(public_key, cp, sig)?;
    Ok(cp.clone())
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;

    fn item() -> Item {
        Item::new(
            Kind::ReadGrant,
            &Caller {
                principal: "backend/user:77",
                caller: Some("user:77"),
                roles: &["verifier".to_owned()],
                purpose: Some("kyc-review"),
                reason: Some("ticket 4411"),
                request_id: Some("req-1"),
                policy_hash: Some([7; 32]),
            },
            "read",
            Some(Uuid::from_bytes([5; 16])),
            Some([9; 32]),
            None,
            "eng-0",
        )
    }

    fn when() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp_nanos(1_763_294_400_123_000_000).unwrap()
    }

    #[test]
    fn an_entry_is_canonical_chained_and_reads_back() {
        let domain = [3u8; 16];
        let built = build(&domain, 4, &[1; 32], when(), &item()).unwrap();
        let parsed = parse(&domain, &built.line).unwrap();
        assert_eq!(parsed.seq, 4);
        assert_eq!(parsed.prev, [1; 32]);
        assert_eq!(parsed.hash, built.hash);
        assert_eq!(parsed.kind, "read.grant");
        assert_eq!(parsed.principal, "backend/user:77");
        assert_eq!(parsed.fact_id, Some(Uuid::from_bytes([5; 16])));
        assert_eq!(parsed.subject_hmac, Some([9; 32]));
        // Another domain does not accept it.
        assert!(parse(&[4; 16], &built.line).is_err());
    }

    #[test]
    fn every_body_field_is_always_present_with_null_for_what_does_not_apply() {
        let bare = Item::new(
            Kind::Deny,
            &Caller::from("x"),
            "read",
            None,
            None,
            Some("not_allowed"),
            "eng-1",
        );
        let built = build(&[3; 16], 0, &[0; 32], when(), &bare).unwrap();
        let body = built.json.get("body").unwrap().as_object().unwrap();
        let mut keys: Vec<&str> = body.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(
            keys,
            [
                "action",
                "caller",
                "denial",
                "fact_id",
                "policy_hash",
                "principal",
                "purpose",
                "reason",
                "request_id",
                "roles",
                "subject_hmac"
            ]
        );
        assert!(
            body["caller"].is_null() && body["fact_id"].is_null() && body["subject_hmac"].is_null()
        );
        assert_eq!(body["denial"], "not_allowed");
        assert_eq!(body["request_id"], "eng-1");
    }

    #[test]
    fn a_line_that_was_edited_or_is_not_canonical_is_refused() {
        let built = build(&[3; 16], 0, &[0; 32], when(), &item()).unwrap();
        // Spaces: same JSON, not the bytes that were hashed.
        let spaced = String::from_utf8(built.line.clone())
            .unwrap()
            .replacen(":", ": ", 1);
        assert!(parse(&[3; 16], spaced.as_bytes()).is_err());
        let mut altered = built.line.clone();
        let at = altered.len() / 2;
        altered[at] ^= 1;
        assert!(
            parse(&[3; 16], &altered).is_err()
                || parse(&[3; 16], &altered).unwrap().hash != built.hash
        );
        assert!(parse(&[3; 16], b"").is_err());
    }

    #[test]
    fn long_fields_are_cut_not_refused() {
        let long = "x".repeat(10_000);
        let i = Item::new(
            Kind::Deny,
            &Caller {
                principal: &long,
                reason: Some(&long),
                ..Caller::default()
            },
            &long,
            None,
            None,
            Some(&long),
            "eng",
        );
        assert_eq!(i.principal.len(), MAX_FIELD);
        assert_eq!(i.reason.as_ref().unwrap().len(), MAX_FIELD);
        assert!(build(&[3; 16], 0, &[0; 32], when(), &i).is_ok());
    }

    #[test]
    fn checkpoint_paths_follow_the_layout() {
        assert_eq!(
            checkpoint_path("audit", &[0xab; 16], 12),
            "checkpoints/audit/abababababababababababababababab/00000000000000000012.json"
        );
    }
}
