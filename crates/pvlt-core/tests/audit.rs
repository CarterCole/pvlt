//! The audit log: what is written, that a read cannot happen without it, and that tampering and truncation
//! are caught.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::sync::Arc;

use common::{arena, id};
use pvlt_core::VaultError;
use pvlt_core::audit::NullAuditor;
use pvlt_core::audit_log::{self, Caller, Kind};
use pvlt_core::engine::{AuditStatus, CreateFact, Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::ledger::Reason;
use pvlt_core::memory::{MemKeyStore, MemObjectStore};
use pvlt_core::objects::ObjectStore;
use pvlt_core::seal::init_shamir;
use pvlt_core::store::{AuditAppend, AuditFilter, FactId, KeyStore};
use time::OffsetDateTime;
use uuid::Uuid;

const SECRET: &str = "Quentin-Q.-Nightingale-1987-03-09";
const WHO: &str = "tester";
const POLICY: [u8; 32] = [7; 32];

type TestEngine = Engine<MemKeyStore, MemObjectStore, NullAuditor>;

fn domain() -> [u8; 16] {
    id(7)
}

async fn engine() -> TestEngine {
    let a = arena();
    let init = init_shamir(&a, 2, 3).unwrap();
    let ring = Keyring::new(a);
    ring.unseal(init.root);
    let e = Engine::new(
        ring,
        MemKeyStore::new(),
        MemObjectStore::new(),
        NullAuditor,
        Limits::default(),
    );
    e.ensure_domain(&domain()).await.unwrap();
    e
}

fn fact<'a>(subject: &'a str, scope: &'a str, value: &'a str) -> CreateFact<'a> {
    CreateFact {
        fact_id: None,
        subject: Some(subject),
        scope,
        fact_type: "ascii",
        value: value.as_bytes(),
        expires_at: None,
    }
}

async fn create(e: &TestEngine, subject: &str, scope: &str, value: &str) -> FactId {
    e.create_fact(WHO, &domain(), &fact(subject, scope, value))
        .await
        .unwrap()
}

fn caller<'a>(roles: &'a [String]) -> Caller<'a> {
    Caller {
        principal: "backend/user:77",
        caller: Some("user:77"),
        roles,
        purpose: Some("kyc-review"),
        reason: Some("ticket 4411"),
        request_id: Some("req-42"),
        policy_hash: Some(POLICY),
    }
}

async fn all(e: &TestEngine) -> Vec<pvlt_core::store::AuditRecord> {
    e.store().audit_records(&domain(), 0, 10_000).await.unwrap()
}

#[tokio::test]
async fn a_read_is_written_down_with_who_why_and_which_policy_before_the_value_is_returned() {
    let e = engine().await;
    let f = create(&e, "user:1234", "kyc-doc:1", SECRET).await;
    let roles = vec!["verifier".to_owned()];
    let got = e.read_fact(caller(&roles), &domain(), &f).await.unwrap();
    assert_eq!(got.value.as_slice(), SECRET.as_bytes());

    let rows = all(&e).await;
    let grant = rows.iter().find(|r| r.kind == "read.grant").unwrap();
    assert_eq!(grant.principal, "backend/user:77");
    assert_eq!(grant.fact_id, Some(f));
    assert_eq!(
        grant.subject_hmac,
        Some(e.subject_hmac(&domain(), "user:1234").await.unwrap())
    );
    let line: serde_json::Value = serde_json::from_slice(&grant.line).unwrap();
    let body = &line["body"];
    assert_eq!(body["caller"], "user:77");
    assert_eq!(body["roles"], serde_json::json!(["verifier"]));
    assert_eq!(body["purpose"], "kyc-review");
    assert_eq!(body["reason"], "ticket 4411");
    assert_eq!(body["request_id"], "req-42");
    assert_eq!(body["policy_hash"], hex::encode(POLICY));
    assert_eq!(body["action"], "read");
}

#[tokio::test]
async fn a_read_that_cannot_be_written_down_does_not_happen() {
    let e = engine().await;
    let f = create(&e, "alice", "kyc", SECRET).await;
    let before = all(&e).await.len();
    e.store().set_audit_failure(true);
    let got = e.read_fact(WHO, &domain(), &f).await;
    assert!(matches!(got, Err(VaultError::Unavailable(_))), "{got:?}");
    // Not a single byte of the value is in the error.
    assert!(!format!("{got:?}").contains("Nightingale"));
    e.store().set_audit_failure(false);
    assert_eq!(
        all(&e).await.len(),
        before,
        "a failed read left an entry or none was needed"
    );
    // And it works again as soon as the log does.
    assert_eq!(
        e.read_fact(WHO, &domain(), &f)
            .await
            .unwrap()
            .value
            .as_slice(),
        SECRET.as_bytes()
    );
    assert!(all(&e).await.iter().any(|r| r.kind == "read.grant"));
}

#[tokio::test]
async fn a_read_that_fails_before_disclosing_writes_no_grant_and_one_that_fails_after_writes_a_fail()
 {
    let e = engine().await;
    let f = create(&e, "alice", "kyc", SECRET).await;
    // Not found, shredded and expired never reach the grant.
    assert!(
        e.read_fact(WHO, &domain(), &Uuid::from_bytes([1; 16]))
            .await
            .is_err()
    );
    assert!(all(&e).await.iter().all(|r| r.kind != "read.grant"));

    // The object is damaged after the grant is written: the grant stands, and a fail entry follows.
    let meta = e.store().fact_for_read(&domain(), &f).await.unwrap();
    let key = pvlt_core::objects::ObjectKey {
        domain_id: domain(),
        object_id: meta.fact.fact.object_id,
    };
    let mut sealed = e.objects().get(&key).await.unwrap().unwrap();
    let last = sealed.len() - 1;
    sealed[last] ^= 1;
    e.objects().put(&key, sealed).await.unwrap();
    assert_eq!(
        e.read_fact(WHO, &domain(), &f).await.map(|_| ()),
        Err(VaultError::OpenFailed)
    );
    let kinds: Vec<String> = all(&e).await.into_iter().map(|r| r.kind).collect();
    let g = kinds.iter().position(|k| k == "read.grant").unwrap();
    assert_eq!(kinds.get(g + 1).map(String::as_str), Some("read.fail"));
}

#[tokio::test]
async fn every_kind_of_operation_leaves_an_entry_and_none_holds_a_value_or_a_plaintext_name() {
    let e = engine().await;
    let a = create(&e, "alice@example.com", "scope-of-alice", SECRET).await;
    let b = create(&e, "bob", "draft", "b").await;
    e.read_fact(WHO, &domain(), &a).await.unwrap();
    e.rebind_scope(WHO, &domain(), &b, "approved")
        .await
        .unwrap();
    e.set_legal_hold(WHO, &domain(), &b, true).await.unwrap();
    e.set_legal_hold(WHO, &domain(), &b, false).await.unwrap();
    e.shred_fact(WHO, &domain(), &b, Reason::Admin)
        .await
        .unwrap();
    e.shred_subject(WHO, &domain(), "alice@example.com", Reason::SubjectRequest)
        .await
        .unwrap();
    let c = create(&e, "carol", "scope-of-carol", "c").await;
    e.shred_scope(WHO, &domain(), "scope-of-carol", Reason::Legal)
        .await
        .unwrap();
    let past = OffsetDateTime::now_utc() - time::Duration::seconds(5);
    e.create_fact(
        WHO,
        &domain(),
        &CreateFact {
            expires_at: Some(past),
            ..fact("dave", "s", "d")
        },
    )
    .await
    .unwrap();
    e.sweep_expired(WHO, &domain(), 10).await.unwrap();
    let _ = c;

    let rows = all(&e).await;
    let kinds: Vec<(&str, String)> = rows
        .iter()
        .map(|r| {
            let v: serde_json::Value = serde_json::from_slice(&r.line).unwrap();
            (
                r.kind.as_str(),
                v["body"]["action"].as_str().unwrap().to_owned(),
            )
        })
        .collect();
    for want in [
        ("create", "create"),
        ("read.grant", "read"),
        ("rebind", "rebind"),
        ("admin", "legal_hold.set"),
        ("admin", "legal_hold.clear"),
        ("shred", "shred.fact"),
        ("shred", "shred.subject"),
        ("shred", "shred.scope"),
        ("shred", "expire"),
    ] {
        assert!(
            kinds.iter().any(|(k, a)| (*k, a.as_str()) == want),
            "missing {want:?} in {kinds:?}"
        );
    }
    let text: Vec<u8> = rows.iter().flat_map(|r| r.line.clone()).collect();
    for needle in [
        SECRET,
        "Nightingale",
        "alice@example.com",
        "scope-of-alice",
        "scope-of-carol",
    ] {
        assert!(
            !text.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "the audit log holds {needle}"
        );
    }
    // A subject shred names the subject by its blind identifier.
    let alice = e
        .subject_hmac(&domain(), "alice@example.com")
        .await
        .unwrap();
    assert!(
        rows.iter()
            .any(|r| r.kind == "shred" && r.subject_hmac == Some(alice))
    );
}

#[tokio::test]
async fn the_chain_verifies_and_every_kind_of_damage_is_caught() {
    let e = engine().await;
    for n in 0..6 {
        let f = create(&e, "alice", "kyc", &format!("v{n}")).await;
        e.read_fact(WHO, &domain(), &f).await.unwrap();
    }
    let v = e.verify_audit(&domain()).await.unwrap();
    assert_eq!(v.status, AuditStatus::Ok);
    assert_eq!(v.entries, 12);

    let rows = all(&e).await;
    let original = rows[5].line.clone();
    // A line edited in place (a flipped bit).
    let mut bad = original.clone();
    bad[original.len() / 2] ^= 1;
    e.store().replace_audit_line(&domain(), 5, bad);
    assert!(matches!(
        e.verify_audit(&domain()).await.unwrap().status,
        AuditStatus::Tampered(_)
    ));
    // The same line with spaces: same JSON, not the bytes that were hashed.
    let spaced = String::from_utf8(original.clone())
        .unwrap()
        .replacen(":", ": ", 1);
    e.store()
        .replace_audit_line(&domain(), 5, spaced.into_bytes());
    assert!(matches!(
        e.verify_audit(&domain()).await.unwrap().status,
        AuditStatus::Tampered(_)
    ));
    // A different but valid entry in its place: the hash column no longer matches the line.
    let other = audit_log::build(
        &domain(),
        5,
        &rows[4].hash,
        OffsetDateTime::now_utc(),
        &audit_log::Item::new(
            Kind::Deny,
            &Caller::from("x"),
            "read",
            None,
            None,
            Some("y"),
            "r",
        ),
    )
    .unwrap();
    e.store().replace_audit_line(&domain(), 5, other.line);
    assert!(matches!(
        e.verify_audit(&domain()).await.unwrap().status,
        AuditStatus::Tampered(_)
    ));
    e.store().replace_audit_line(&domain(), 5, original);
    assert_eq!(
        e.verify_audit(&domain()).await.unwrap().status,
        AuditStatus::Ok
    );
}

#[tokio::test]
async fn a_checkpoint_pins_the_history_so_rewriting_the_last_entries_is_caught() {
    let e = engine().await;
    let f = create(&e, "alice", "kyc", SECRET).await;
    e.read_fact(WHO, &domain(), &f).await.unwrap();
    assert!(e.write_checkpoints(&POLICY).await.unwrap() >= 1);
    let files = e.objects().list_prefix("checkpoints/audit/").await.unwrap();
    assert_eq!(files.len(), 1);
    assert_eq!(e.verify_audit(&domain()).await.unwrap().checkpoints, 1);

    // Someone who can write the table rewrites the read.grant as something innocent, with a valid hash. The
    // chain alone cannot tell, because nothing follows it. The signed checkpoint can.
    let rows = all(&e).await;
    let last = rows.last().unwrap();
    let forged = audit_log::build(
        &domain(),
        last.seq,
        &last.prev,
        OffsetDateTime::now_utc(),
        &audit_log::Item::new(
            Kind::Create,
            &Caller::from("backend"),
            "create",
            None,
            None,
            None,
            "r",
        ),
    )
    .unwrap();
    e.store().replace_audit_entry(
        &domain(),
        last.seq,
        AuditAppend {
            seq: last.seq,
            prev: last.prev,
            hash: forged.hash,
            line: forged.line,
            kind: "create".into(),
            principal: "backend".into(),
            fact_id: None,
            subject_hmac: None,
            at: OffsetDateTime::now_utc(),
        },
    );
    let v = e.verify_audit(&domain()).await.unwrap();
    assert_eq!(
        v.status,
        AuditStatus::Tampered("a checkpoint disagrees with the audit chain")
    );
    assert!(matches!(
        e.check_audit().await,
        Err(VaultError::Integrity(_))
    ));
}

#[tokio::test]
async fn a_damaged_or_forged_checkpoint_is_refused() {
    let e = engine().await;
    create(&e, "alice", "kyc", "v").await;
    e.write_checkpoints(&POLICY).await.unwrap();
    let path = e
        .objects()
        .list_prefix("checkpoints/audit/")
        .await
        .unwrap()
        .remove(0)
        .0;
    let bytes = e.objects().get_path(&path).await.unwrap().unwrap();
    let mut bad = bytes.clone();
    bad[bytes.len() / 2] ^= 1;
    e.objects().put_path(&path, bad).await.unwrap();
    assert!(matches!(
        e.verify_audit(&domain()).await.unwrap().status,
        AuditStatus::Tampered(_)
    ));

    // A checkpoint signed by another vault's key for the same domain id.
    let other = engine().await;
    create(&other, "alice", "kyc", "v").await;
    other.write_checkpoints(&POLICY).await.unwrap();
    let opath = other
        .objects()
        .list_prefix("checkpoints/audit/")
        .await
        .unwrap()
        .remove(0)
        .0;
    let forged = other.objects().get_path(&opath).await.unwrap().unwrap();
    e.objects().put_path(&path, forged).await.unwrap();
    assert!(matches!(
        e.verify_audit(&domain()).await.unwrap().status,
        AuditStatus::Tampered(_)
    ));
}

#[tokio::test]
async fn a_truncated_log_is_detected_blocks_reads_and_is_cleared_only_by_a_signed_acknowledgement()
{
    let e = engine().await;
    let f = create(&e, "alice", "kyc", SECRET).await;
    for _ in 0..4 {
        e.read_fact(WHO, &domain(), &f).await.unwrap();
    }
    e.write_checkpoints(&POLICY).await.unwrap();
    let full = all(&e).await.len();
    assert_eq!(full, 5);

    // Entries disappear: a restore from an older backup, or someone covering their tracks.
    e.store().truncate_audit(&domain(), 2);
    let v = e.verify_audit(&domain()).await.unwrap();
    assert_eq!(
        v.status,
        AuditStatus::Truncated {
            checkpoint_seq: 4,
            entries: 2
        }
    );

    // At start the server notices, and reads stop (fail closed) until someone takes responsibility.
    let checked = e.check_audit().await.unwrap();
    assert!(matches!(checked[0].1.status, AuditStatus::Truncated { .. }));
    assert!(e.audit_blocked());
    assert!(matches!(
        e.read_fact(WHO, &domain(), &f).await,
        Err(VaultError::Unavailable(_))
    ));
    // Writing is not the problem; only disclosure waits.
    create(&e, "bob", "kyc", "still-works").await;

    let (from, through) = e
        .acknowledge_audit_rollback(&Caller::from("admin"), &domain(), &POLICY)
        .await
        .unwrap();
    // One entry (bob's create) was written after the truncation, so the log has 3 entries when it is acknowledged.
    assert_eq!((from, through), (3, 4));
    assert!(!e.audit_blocked());
    assert_eq!(
        e.read_fact(WHO, &domain(), &f)
            .await
            .unwrap()
            .value
            .as_slice(),
        SECRET.as_bytes()
    );
    assert_eq!(
        e.verify_audit(&domain()).await.unwrap().status,
        AuditStatus::Ok
    );
    // The acknowledgement is itself in the log, by name.
    assert!(all(&e).await.iter().any(|r| {
        let v: serde_json::Value = serde_json::from_slice(&r.line).unwrap();
        v["body"]["action"] == "audit.rollback_acknowledged"
    }));
    // There is nothing left to acknowledge.
    assert!(matches!(
        e.acknowledge_audit_rollback(&Caller::from("admin"), &domain(), &POLICY)
            .await,
        Err(VaultError::Conflict(_))
    ));
}

#[tokio::test]
async fn an_acknowledgement_does_not_excuse_anything_beyond_the_range_it_names() {
    let mut e = engine().await;
    // Every new entry earns a checkpoint, so the history after the acknowledgement is pinned too.
    e = e.with_checkpoint_policy(1, std::time::Duration::ZERO);
    let f = create(&e, "alice", "kyc", "v").await;
    for _ in 0..4 {
        e.read_fact(WHO, &domain(), &f).await.unwrap();
    }
    e.write_checkpoints(&POLICY).await.unwrap();
    e.store().truncate_audit(&domain(), 2);
    e.check_audit().await.unwrap();
    e.acknowledge_audit_rollback(&Caller::from("admin"), &domain(), &POLICY)
        .await
        .unwrap();
    // New history grows back to the very sequence number of a lost checkpoint, gets its own checkpoint there,
    // and then the new tail is rewritten: still caught, because the acknowledgement excused only the old one.
    for _ in 0..2 {
        e.read_fact(WHO, &domain(), &f).await.unwrap();
    }
    e.write_checkpoints(&POLICY).await.unwrap();
    let rows = all(&e).await;
    let last = rows.last().unwrap();
    let forged = audit_log::build(
        &domain(),
        last.seq,
        &last.prev,
        OffsetDateTime::now_utc(),
        &audit_log::Item::new(
            Kind::Create,
            &Caller::from("x"),
            "create",
            None,
            None,
            None,
            "r",
        ),
    )
    .unwrap();
    e.store().replace_audit_entry(
        &domain(),
        last.seq,
        AuditAppend {
            seq: last.seq,
            prev: last.prev,
            hash: forged.hash,
            line: forged.line,
            kind: "create".into(),
            principal: "x".into(),
            fact_id: None,
            subject_hmac: None,
            at: OffsetDateTime::now_utc(),
        },
    );
    assert!(matches!(
        e.verify_audit(&domain()).await.unwrap().status,
        AuditStatus::Tampered(_)
    ));
}

#[tokio::test]
async fn checkpoints_are_written_for_the_audit_log_and_the_ledger_and_only_when_there_is_news() {
    let e = engine().await;
    assert_eq!(
        e.write_checkpoints(&POLICY).await.unwrap(),
        0,
        "nothing to checkpoint yet"
    );
    let f = create(&e, "alice", "kyc", "v").await;
    assert_eq!(
        e.write_checkpoints(&POLICY).await.unwrap(),
        1,
        "the audit log has an entry"
    );
    assert_eq!(
        e.write_checkpoints(&POLICY).await.unwrap(),
        0,
        "and no new one since"
    );
    e.shred_fact(WHO, &domain(), &f, Reason::Admin)
        .await
        .unwrap();
    // The shred added a ledger entry and an audit entry, but a new checkpoint waits for the interval or for
    // enough entries, so a burst does not write a file per operation.
    assert_eq!(
        e.write_checkpoints(&POLICY).await.unwrap(),
        1,
        "the ledger has its first entry"
    );
    assert!(
        !e.objects()
            .list_prefix("checkpoints/ledger/")
            .await
            .unwrap()
            .is_empty()
    );
    let (path, _) = e
        .objects()
        .list_prefix("checkpoints/ledger/")
        .await
        .unwrap()
        .remove(0);
    let bytes = e.objects().get_path(&path).await.unwrap().unwrap();
    let key = e
        .store()
        .sign_key(&domain(), pvlt_format::wrap::SignPurpose::Checkpoint)
        .await
        .unwrap()
        .unwrap();
    let cp = audit_log::verify_checkpoint_file(&key.public_key, &bytes).unwrap();
    assert_eq!(cp["log"], "ledger");
    assert_eq!(cp["seq"], 0);
    assert_eq!(cp["policy_hash"], hex::encode(POLICY));
    // The ledger key cannot sign a checkpoint and the checkpoint key cannot sign the ledger.
    let ledger_key = e
        .store()
        .sign_key(&domain(), pvlt_format::wrap::SignPurpose::Ledger)
        .await
        .unwrap()
        .unwrap();
    assert_ne!(ledger_key.public_key, key.public_key);
    assert!(audit_log::verify_checkpoint_file(&ledger_key.public_key, &bytes).is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
async fn many_concurrent_reads_all_get_an_entry_and_the_chain_stays_whole() {
    let e = Arc::new(engine().await);
    let f = create(&e, "alice", "kyc", SECRET).await;
    let mut tasks = Vec::new();
    for _ in 0..64 {
        let e = Arc::clone(&e);
        tasks.push(tokio::spawn(async move {
            e.read_fact(WHO, &domain(), &f).await.unwrap()
        }));
    }
    for t in tasks {
        assert_eq!(t.await.unwrap().value.as_slice(), SECRET.as_bytes());
    }
    let rows = all(&e).await;
    assert_eq!(rows.iter().filter(|r| r.kind == "read.grant").count(), 64);
    assert_eq!(
        e.verify_audit(&domain()).await.unwrap().status,
        AuditStatus::Ok
    );
    assert!(
        e.store().audit_append_calls() <= rows.len(),
        "more transactions than entries"
    );
    // The writer is not stuck: another entry goes straight through.
    e.read_fact(WHO, &domain(), &f).await.unwrap();
}

#[tokio::test]
async fn the_log_can_be_queried_by_subject_principal_fact_kind_and_time_and_paged() {
    let e = engine().await;
    let a = create(&e, "alice", "kyc", "a").await;
    let b = create(&e, "bob", "kyc", "b").await;
    let roles = vec!["verifier".to_owned()];
    e.read_fact(caller(&roles), &domain(), &a).await.unwrap();
    e.read_fact(caller(&roles), &domain(), &a).await.unwrap();
    e.read_fact("another/service", &domain(), &b).await.unwrap();
    let q = |mut f: AuditFilter| {
        if f.limit == 0 {
            f.limit = 100;
        }
        let e = &e;
        async move { e.audit_query(&domain(), &f).await.unwrap() }
    };
    let alice = e.subject_hmac(&domain(), "alice").await.unwrap();
    assert_eq!(
        q(AuditFilter {
            subject_hmac: Some(alice),
            ..AuditFilter::default()
        })
        .await
        .len(),
        3,
        "a create and two reads"
    );
    assert_eq!(
        q(AuditFilter {
            subject_hmac: Some(alice),
            kind: Some("read.grant".into()),
            ..AuditFilter::default()
        })
        .await
        .len(),
        2
    );
    assert_eq!(
        q(AuditFilter {
            principal: Some("another/service".into()),
            ..AuditFilter::default()
        })
        .await
        .len(),
        1
    );
    assert_eq!(
        q(AuditFilter {
            fact_id: Some(b),
            ..AuditFilter::default()
        })
        .await
        .len(),
        2
    );
    assert_eq!(
        q(AuditFilter {
            subject_hmac: Some([9; 32]),
            ..AuditFilter::default()
        })
        .await
        .len(),
        0
    );
    let now = OffsetDateTime::now_utc();
    assert_eq!(
        q(AuditFilter {
            from: Some(now + time::Duration::hours(1)),
            ..AuditFilter::default()
        })
        .await
        .len(),
        0
    );
    assert_eq!(
        q(AuditFilter {
            to: Some(now + time::Duration::hours(1)),
            ..AuditFilter::default()
        })
        .await
        .len(),
        5
    );
    // Paging.
    let first = q(AuditFilter {
        limit: 3,
        ..AuditFilter::default()
    })
    .await;
    assert_eq!(first.len(), 3);
    let rest = q(AuditFilter {
        after_seq: Some(first[2].seq),
        ..AuditFilter::default()
    })
    .await;
    assert_eq!(rest.len(), 2);
    assert_eq!(rest[0].seq, first[2].seq + 1);
}

#[tokio::test]
async fn a_denial_written_by_the_server_is_an_entry_like_any_other() {
    let e = engine().await;
    let roles = vec!["verifier".to_owned()];
    e.audit_event(
        &domain(),
        Kind::Deny,
        &caller(&roles),
        "read",
        None,
        None,
        Some("purpose"),
    )
    .await
    .unwrap();
    let rows = all(&e).await;
    assert_eq!(rows.len(), 1);
    let v: serde_json::Value = serde_json::from_slice(&rows[0].line).unwrap();
    assert_eq!(
        (v["type"].as_str(), v["body"]["denial"].as_str()),
        (Some("deny"), Some("purpose"))
    );
    assert_eq!(
        e.verify_audit(&domain()).await.unwrap().status,
        AuditStatus::Ok
    );
}
