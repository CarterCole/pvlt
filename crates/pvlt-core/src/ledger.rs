//! The shred ledger (FORMAT.md section 8, PLAN.md 3.3 and 3.4).
//!
//! Every shred is a signed, hash-chained entry that lists what it destroyed by id. The entry is committed in
//! the same database transaction that destroys the keys, and a copy is written to the bucket. The bucket copy is
//! what makes a shred survive restoring an older key store: on start, entries the database does not have are
//! replayed against it ([`crate::engine::Engine::reconcile`]).
//!
//! An entry never holds key material, a plaintext subject or scope, or free text. Reasons are a fixed list.

use pvlt_format::Id;
use pvlt_format::log::{self, Log, ZERO_HASH};
use serde_json::{Map, Value, json};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::VaultError;

/// Why something was destroyed. A fixed list, because free text is where PII leaks (FORMAT.md section 8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The data subject asked.
    SubjectRequest,
    /// A retention period ended.
    Retention,
    /// A legal obligation.
    Legal,
    /// An operator decided.
    Admin,
    /// Part of moving data between systems.
    Migration,
}

impl Reason {
    /// The code written to the ledger.
    pub fn code(self) -> &'static str {
        match self {
            Reason::SubjectRequest => "subject_request",
            Reason::Retention => "retention",
            Reason::Legal => "legal",
            Reason::Admin => "admin",
            Reason::Migration => "migration",
        }
    }

    fn from_code(code: &str) -> Option<Self> {
        Some(match code {
            "subject_request" => Reason::SubjectRequest,
            "retention" => Reason::Retention,
            "legal" => Reason::Legal,
            "admin" => Reason::Admin,
            "migration" => Reason::Migration,
            _ => return None,
        })
    }
}

/// What an entry destroyed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Effect {
    /// Named facts (`shred.fact`, or `expire` when the retention sweeper wrote it).
    Facts {
        /// The facts.
        fact_ids: Vec<Uuid>,
        /// Their objects. Replay shreds by these.
        object_ids: Vec<Id>,
        /// Whether this is an `expire` entry.
        expire: bool,
    },
    /// Every fact in a scope at the time.
    Scope {
        /// The scope's blind identifier.
        scope_hmac: [u8; 32],
        /// The blind-index key version that made it.
        bik_version: u32,
        /// The facts.
        fact_ids: Vec<Uuid>,
        /// Their objects. Replay shreds by these, not by looking the scope up: a fact re-bound to the scope
        /// after a backup was taken is filed under its old scope in that backup.
        object_ids: Vec<Id>,
    },
    /// A subject's keys, and so everything filed under them.
    Subject {
        /// The subject's blind identifier.
        subject_hmac: [u8; 32],
        /// The blind-index key version that made it.
        bik_version: u32,
        /// The key versions destroyed.
        subject_key_versions: Vec<u32>,
    },
    /// A whole domain.
    Domain,
}

impl Effect {
    fn type_name(&self) -> &'static str {
        match self {
            Effect::Facts { expire: true, .. } => "expire",
            Effect::Facts { .. } => "shred.fact",
            Effect::Scope { .. } => "shred.scope",
            Effect::Subject { .. } => "shred.subject",
            Effect::Domain => "shred.domain",
        }
    }
}

/// One entry of the ledger, without its signature.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Position, from 0 with no gaps.
    pub seq: u64,
    /// The previous entry's hash. All zeros for `seq` 0.
    pub prev: [u8; 32],
    /// When it was written, to the millisecond.
    pub time: OffsetDateTime,
    /// What it destroyed.
    pub effect: Effect,
    /// An id tying it to the request that caused it. Hex or a UUID, never free text.
    pub request_id: String,
    /// Why.
    pub reason: Reason,
}

/// `2026-11-14T12:00:00.000Z`.
pub fn format_time(t: OffsetDateTime) -> String {
    let t = t.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        t.year(),
        u8::from(t.month()),
        t.day(),
        t.hour(),
        t.minute(),
        t.second(),
        t.millisecond()
    )
}

fn parse_time(s: &str) -> Option<OffsetDateTime> {
    // Exactly the 24 characters `format_time` writes.
    let b = s.as_bytes();
    if b.len() != 24
        || b.get(4) != Some(&b'-')
        || b.get(7) != Some(&b'-')
        || b.get(10) != Some(&b'T')
        || b.get(13) != Some(&b':')
        || b.get(16) != Some(&b':')
        || b.get(19) != Some(&b'.')
        || b.get(23) != Some(&b'Z')
    {
        return None;
    }
    let num = |from: usize, to: usize| s.get(from..to)?.parse::<i32>().ok();
    let date = time::Date::from_calendar_date(
        num(0, 4)?,
        time::Month::try_from(u8::try_from(num(5, 7)?).ok()?).ok()?,
        u8::try_from(num(8, 10)?).ok()?,
    )
    .ok()?;
    let t = time::Time::from_hms_milli(
        u8::try_from(num(11, 13)?).ok()?,
        u8::try_from(num(14, 16)?).ok()?,
        u8::try_from(num(17, 19)?).ok()?,
        u16::try_from(num(20, 23)?).ok()?,
    )
    .ok()?;
    Some(OffsetDateTime::new_utc(date, t))
}

fn ids(v: &[Id]) -> Vec<Value> {
    v.iter().map(|i| Value::from(hex::encode(i))).collect()
}

fn uuids(v: &[Uuid]) -> Vec<Value> {
    v.iter().map(|u| Value::from(u.to_string())).collect()
}

/// Builds the JSON entry of FORMAT.md section 8 for a domain.
pub fn to_json(domain_id: &Id, e: &Entry) -> Value {
    let mut body = Map::new();
    body.insert("request_id".into(), e.request_id.clone().into());
    body.insert("reason".into(), e.reason.code().into());
    match &e.effect {
        Effect::Facts {
            fact_ids,
            object_ids,
            ..
        } => {
            body.insert("fact_ids".into(), uuids(fact_ids).into());
            body.insert("object_ids".into(), ids(object_ids).into());
        }
        Effect::Scope {
            scope_hmac,
            bik_version,
            fact_ids,
            object_ids,
        } => {
            body.insert("scope_hmac".into(), hex::encode(scope_hmac).into());
            body.insert("bik_version".into(), (*bik_version).into());
            body.insert("fact_ids".into(), uuids(fact_ids).into());
            body.insert("object_ids".into(), ids(object_ids).into());
        }
        Effect::Subject {
            subject_hmac,
            bik_version,
            subject_key_versions,
        } => {
            body.insert("subject_hmac".into(), hex::encode(subject_hmac).into());
            body.insert("bik_version".into(), (*bik_version).into());
            body.insert("subject_key_versions".into(), json!(subject_key_versions));
        }
        Effect::Domain => {}
    }
    log::entry(
        Log::Ledger,
        domain_id,
        e.seq,
        &hex::encode(e.prev),
        &format_time(e.time),
        e.effect.type_name(),
        Value::Object(body),
    )
}

fn hex_fixed<const N: usize>(v: &Value) -> Option<[u8; N]> {
    hex::decode(v.as_str()?).ok()?.try_into().ok()
}

fn id_list(v: &Value) -> Option<Vec<Id>> {
    v.as_array()?.iter().map(hex_fixed::<16>).collect()
}

fn uuid_list(v: &Value) -> Option<Vec<Uuid>> {
    v.as_array()?
        .iter()
        .map(|x| Uuid::parse_str(x.as_str()?).ok())
        .collect()
}

fn bad(what: &'static str) -> VaultError {
    VaultError::Invalid(what)
}

/// Reads an entry back. Everything is checked: the log name, the domain, the types, and that every list is
/// the right shape. A ledger line that parses here is one this code could have written.
pub fn from_json(domain_id: &Id, v: &Value) -> Result<Entry, VaultError> {
    if v.get("log").and_then(Value::as_str) != Some("ledger") {
        return Err(bad("not a ledger entry"));
    }
    if v.get("domain_id").and_then(Value::as_str) != Some(hex::encode(domain_id).as_str()) {
        return Err(bad("ledger entry is for another domain"));
    }
    let seq = v
        .get("seq")
        .and_then(Value::as_u64)
        .ok_or(bad("ledger seq"))?;
    let prev: [u8; 32] =
        hex_fixed(v.get("prev").ok_or(bad("ledger prev"))?).ok_or(bad("ledger prev"))?;
    let time = v
        .get("time")
        .and_then(Value::as_str)
        .and_then(parse_time)
        .ok_or(bad("ledger time"))?;
    let kind = v
        .get("type")
        .and_then(Value::as_str)
        .ok_or(bad("ledger type"))?;
    let body = v.get("body").ok_or(bad("ledger body"))?;
    let request_id = body
        .get("request_id")
        .and_then(Value::as_str)
        .ok_or(bad("ledger request id"))?
        .to_owned();
    let reason = body
        .get("reason")
        .and_then(Value::as_str)
        .and_then(Reason::from_code)
        .ok_or(bad("ledger reason"))?;
    let get = |k: &'static str| body.get(k).ok_or(bad("ledger body field"));
    let effect = match kind {
        "shred.fact" | "expire" => Effect::Facts {
            fact_ids: uuid_list(get("fact_ids")?).ok_or(bad("ledger fact ids"))?,
            object_ids: id_list(get("object_ids")?).ok_or(bad("ledger object ids"))?,
            expire: kind == "expire",
        },
        "shred.scope" => Effect::Scope {
            scope_hmac: hex_fixed(get("scope_hmac")?).ok_or(bad("ledger scope"))?,
            bik_version: u32::try_from(get("bik_version")?.as_u64().ok_or(bad("ledger bik"))?)
                .map_err(|_| bad("ledger bik"))?,
            fact_ids: uuid_list(get("fact_ids")?).ok_or(bad("ledger fact ids"))?,
            object_ids: id_list(get("object_ids")?).ok_or(bad("ledger object ids"))?,
        },
        "shred.subject" => Effect::Subject {
            subject_hmac: hex_fixed(get("subject_hmac")?).ok_or(bad("ledger subject"))?,
            bik_version: u32::try_from(get("bik_version")?.as_u64().ok_or(bad("ledger bik"))?)
                .map_err(|_| bad("ledger bik"))?,
            subject_key_versions: get("subject_key_versions")?
                .as_array()
                .ok_or(bad("ledger versions"))?
                .iter()
                .map(|x| x.as_u64().and_then(|n| u32::try_from(n).ok()))
                .collect::<Option<Vec<_>>>()
                .ok_or(bad("ledger versions"))?,
        },
        "shred.domain" => Effect::Domain,
        _ => return Err(bad("unknown ledger entry type")),
    };
    Ok(Entry {
        seq,
        prev,
        time,
        effect,
        request_id,
        reason,
    })
}

/// The hash of an entry, which the next entry's `prev` names.
pub fn hash_of(entry: &Value) -> Result<[u8; 32], VaultError> {
    Ok(log::entry_hash(entry)?)
}

/// `prev` for the first entry.
pub const GENESIS: [u8; 32] = [0; 32];

/// The ledger file name for a sequence number (FORMAT.md section 7).
pub fn path_for(domain_id: &Id, seq: u64) -> String {
    format!("ledger/{}/{seq:020}.json", hex::encode(domain_id))
}

/// The prefix that holds a domain's ledger.
pub fn prefix_for(domain_id: &Id) -> String {
    format!("ledger/{}/", hex::encode(domain_id))
}

/// The sequence number a ledger file name carries, if it is one.
pub fn seq_of(domain_id: &Id, path: &str) -> Option<u64> {
    let name = path.strip_prefix(prefix_for(domain_id).as_str())?;
    let digits = name.strip_suffix(".json")?;
    (digits.len() == 20 && digits.bytes().all(|b| b.is_ascii_digit()))
        .then(|| digits.parse().ok())
        .flatten()
}

/// Verifies a signed line from the bucket and reads its entry. Checks the signature, the canonical form, the
/// domain, and that the file name's sequence number matches the entry's.
pub fn verify_line(
    domain_id: &Id,
    public_key: &[u8; 32],
    line: &[u8],
) -> Result<(Entry, [u8; 32], Value), VaultError> {
    let value = log::ledger_verify(public_key, line)?;
    let entry = from_json(domain_id, &value)?;
    let hash = hash_of(&value)?;
    Ok((entry, hash, value))
}

/// Whether `prev` is the genesis value.
pub fn is_genesis(prev: &[u8; 32]) -> bool {
    hex::encode(prev) == ZERO_HASH
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

    fn when() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp_nanos(1_763_294_400_123_000_000).unwrap()
    }

    fn sample(effect: Effect) -> Entry {
        Entry {
            seq: 7,
            prev: [9; 32],
            time: when(),
            effect,
            request_id: "0123456789abcdef".into(),
            reason: Reason::SubjectRequest,
        }
    }

    #[test]
    fn every_effect_round_trips_through_json() {
        let domain = [1u8; 16];
        let u = Uuid::from_bytes([5; 16]);
        for effect in [
            Effect::Facts {
                fact_ids: vec![u],
                object_ids: vec![[2; 16]],
                expire: false,
            },
            Effect::Facts {
                fact_ids: vec![u],
                object_ids: vec![[2; 16]],
                expire: true,
            },
            Effect::Scope {
                scope_hmac: [3; 32],
                bik_version: 2,
                fact_ids: vec![u, Uuid::from_bytes([6; 16])],
                object_ids: vec![[2; 16], [4; 16]],
            },
            Effect::Subject {
                subject_hmac: [8; 32],
                bik_version: 1,
                subject_key_versions: vec![1, 2],
            },
            Effect::Domain,
        ] {
            let e = sample(effect);
            let json = to_json(&domain, &e);
            assert_eq!(from_json(&domain, &json).unwrap(), e);
        }
    }

    #[test]
    fn the_time_is_written_to_the_millisecond_and_read_back() {
        assert_eq!(format_time(when()), "2025-11-16T12:00:00.123Z");
        assert_eq!(parse_time("2025-11-16T12:00:00.123Z"), Some(when()));
        for bad in [
            "",
            "2025-11-16T12:00:00Z",
            "2025-11-16 12:00:00.123Z",
            "2025-13-16T12:00:00.123Z",
            "2025-11-16T12:00:00.123+00:00",
        ] {
            assert_eq!(parse_time(bad), None, "{bad}");
        }
    }

    #[test]
    fn an_entry_for_another_domain_or_log_is_refused() {
        let e = sample(Effect::Domain);
        let json = to_json(&[1; 16], &e);
        assert!(from_json(&[2; 16], &json).is_err());
        let mut wrong_log = json.clone();
        wrong_log["log"] = "audit".into();
        assert!(from_json(&[1; 16], &wrong_log).is_err());
    }

    #[test]
    fn a_free_text_reason_is_refused() {
        let mut json = to_json(&[1; 16], &sample(Effect::Domain));
        json["body"]["reason"] = "because alice@example.com asked".into();
        assert!(from_json(&[1; 16], &json).is_err());
    }

    #[test]
    fn paths_round_trip() {
        let d = [0xcd; 16];
        let p = path_for(&d, 42);
        assert_eq!(
            p,
            "ledger/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd/00000000000000000042.json"
        );
        assert_eq!(seq_of(&d, &p), Some(42));
        assert_eq!(seq_of(&[1; 16], &p), None);
        assert_eq!(
            seq_of(&d, "ledger/cdcdcdcdcdcdcdcdcdcdcdcdcdcdcdcd/42.json"),
            None
        );
    }
}
