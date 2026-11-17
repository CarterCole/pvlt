//! The engine over in-memory stores: what it stores, what it refuses, and what a shred does.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::sync::{Arc, Mutex};
use std::time::Duration;

use common::{arena, id};
use pvlt_core::VaultError;
use pvlt_core::audit::{Action, AuditEvent, Auditor, NullAuditor};
use pvlt_core::engine::{CreateFact, Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::ledger::Reason;
use pvlt_core::memory::{MemKeyStore, MemObjectStore};
use pvlt_core::objects::{ObjectKey, ObjectStore};
use pvlt_core::seal::init_shamir;
use pvlt_core::store::{FactId, KeyStore, ShredFact, ShredSubject};
use time::OffsetDateTime;

const SECRET: &str = "Quentin-Q.-Nightingale-1987-03-09";
const WHO: &str = "tester";

type TestEngine<A = NullAuditor> = Engine<MemKeyStore, MemObjectStore, A>;

fn domain() -> [u8; 16] {
    id(7)
}

async fn engine_with<A: Auditor>(auditor: A, limits: Limits) -> TestEngine<A> {
    let a = arena();
    let init = init_shamir(&a, 2, 3).unwrap();
    let ring = Keyring::new(a);
    ring.unseal(init.root);
    let engine = Engine::new(
        ring,
        MemKeyStore::new(),
        MemObjectStore::new(),
        auditor,
        limits,
    );
    engine.ensure_domain(&domain()).await.unwrap();
    engine
}

async fn engine() -> TestEngine {
    engine_with(NullAuditor, Limits::default()).await
}

fn fact<'a>(subject: Option<&'a str>, scope: &'a str, value: &'a str) -> CreateFact<'a> {
    CreateFact {
        fact_id: None,
        subject,
        scope,
        fact_type: "ascii",
        value: value.as_bytes(),
        expires_at: None,
    }
}

async fn create<A: Auditor>(
    e: &TestEngine<A>,
    subject: Option<&str>,
    scope: &str,
    value: &str,
) -> FactId {
    e.create_fact(WHO, &domain(), &fact(subject, scope, value))
        .await
        .unwrap()
}

async fn read<A: Auditor>(e: &TestEngine<A>, fact_id: &FactId) -> Result<String, VaultError> {
    e.read_fact(WHO, &domain(), fact_id)
        .await
        .map(|f| String::from_utf8(f.value.to_vec()).unwrap())
}

async fn object_key(e: &TestEngine, fact_id: &FactId) -> ObjectKey {
    let bundle = e.store().fact_for_read(&domain(), fact_id).await.unwrap();
    ObjectKey {
        domain_id: domain(),
        object_id: bundle.fact.fact.object_id,
    }
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    haystack
        .windows(needle.len())
        .any(|w| w == needle.as_bytes())
}

#[tokio::test]
async fn a_fact_reads_back_whatever_its_size() {
    let e = engine().await;
    for len in [0, 1, 254, 255, 256, 1023, 1024, 100_000, 1_048_575] {
        let value = "x".repeat(len);
        let fact_id = create(&e, Some("alice"), "kyc", &value).await;
        assert_eq!(read(&e, &fact_id).await.unwrap(), value, "len {len}");
    }
}

#[tokio::test]
async fn the_type_comes_back_and_a_supplied_id_is_used() {
    let e = engine().await;
    let wanted = uuid::Uuid::from_bytes([9; 16]);
    let got = e
        .create_fact(
            WHO,
            &domain(),
            &CreateFact {
                fact_id: Some(wanted),
                fact_type: "json",
                ..fact(Some("alice"), "s", "{}")
            },
        )
        .await
        .unwrap();
    assert_eq!(got, wanted);
    let read = e.read_fact(WHO, &domain(), &wanted).await.unwrap();
    assert_eq!(read.fact_type, "json");
    assert_eq!(read.value.as_slice(), b"{}");
}

#[tokio::test]
async fn neither_store_holds_the_value_subject_or_scope() {
    let e = engine().await;
    let fact_id = create(&e, Some("alice@example.com"), "scope-of-alice", SECRET).await;
    create(&e, None, "another-scope", SECRET).await;
    assert_eq!(read(&e, &fact_id).await.unwrap(), SECRET);

    for (name, bytes) in [
        ("key store", e.store().dump()),
        ("bucket", e.objects().dump()),
    ] {
        assert!(!bytes.is_empty(), "{name} is empty, so the scan is vacuous");
        for needle in [
            SECRET,
            "Nightingale",
            "alice@example.com",
            "scope-of-alice",
            "another-scope",
        ] {
            assert!(!contains(&bytes, needle), "{name} holds {needle}");
        }
    }
}

#[tokio::test]
async fn a_shredded_fact_is_gone_for_good_and_says_so() {
    let e = engine().await;
    let fact_id = create(&e, Some("alice"), "kyc", SECRET).await;
    let other = create(&e, Some("alice"), "kyc", "second").await;
    assert_eq!(e.objects().object_count(), 2);

    let first = e
        .shred_fact(WHO, &domain(), &fact_id, Reason::Admin)
        .await
        .unwrap();
    assert!(matches!(first, ShredFact::Shredded { .. }));
    assert_eq!(read(&e, &fact_id).await, Err(VaultError::Shredded));
    assert_eq!(
        e.shred_fact(WHO, &domain(), &fact_id, Reason::Admin)
            .await
            .unwrap(),
        ShredFact::AlreadyShredded
    );
    // Its object was deleted, and the neighbour is untouched.
    assert_eq!(e.objects().object_count(), 1);
    assert_eq!(read(&e, &other).await.unwrap(), "second");
}

#[tokio::test]
async fn shredding_a_fact_that_never_existed_is_a_success_and_reading_one_is_not_found() {
    let e = engine().await;
    let nobody = uuid::Uuid::from_bytes([1; 16]);
    assert_eq!(
        e.shred_fact(WHO, &domain(), &nobody, Reason::Admin)
            .await
            .unwrap(),
        ShredFact::NotFound
    );
    assert_eq!(read(&e, &nobody).await, Err(VaultError::NotFound));
}

#[tokio::test]
async fn a_shred_cannot_be_undone_by_reading_the_object_back() {
    // Keep a copy of the sealed object from before the shred, put it back afterwards, and show that the fact
    // still cannot be opened: the key, not the bucket, is what was destroyed.
    let e = engine().await;
    let fact_id = create(&e, Some("alice"), "kyc", SECRET).await;
    let bundle = e.store().fact_for_read(&domain(), &fact_id).await.unwrap();
    let key = ObjectKey {
        domain_id: domain(),
        object_id: bundle.fact.fact.object_id,
    };
    let sealed = e.objects().get(&key).await.unwrap().unwrap();

    e.shred_fact(WHO, &domain(), &fact_id, Reason::Admin)
        .await
        .unwrap();
    e.objects().put(&key, sealed).await.unwrap();
    assert_eq!(read(&e, &fact_id).await, Err(VaultError::Shredded));
}

#[tokio::test]
async fn shredding_a_subject_destroys_all_its_facts_and_blocks_new_ones() {
    let e = engine().await;
    let a1 = create(&e, Some("alice"), "kyc", "a1").await;
    let a2 = create(&e, Some("alice"), "other", "a2").await;
    let b1 = create(&e, Some("bob"), "kyc", "b1").await;

    assert_eq!(
        e.shred_subject(WHO, &domain(), "alice", Reason::Admin)
            .await
            .unwrap(),
        ShredSubject::Shredded
    );
    assert_eq!(read(&e, &a1).await, Err(VaultError::Shredded));
    assert_eq!(read(&e, &a2).await, Err(VaultError::Shredded));
    assert_eq!(read(&e, &b1).await.unwrap(), "b1");

    let again = e
        .create_fact(WHO, &domain(), &fact(Some("alice"), "kyc", "new"))
        .await;
    assert_eq!(again, Err(VaultError::Shredded));
    assert_eq!(
        e.shred_subject(WHO, &domain(), "alice", Reason::Admin)
            .await
            .unwrap(),
        ShredSubject::AlreadyShredded
    );
    assert_eq!(
        e.shred_subject(WHO, &domain(), "nobody", Reason::Admin)
            .await
            .unwrap(),
        ShredSubject::NotFound
    );
}

#[tokio::test]
async fn a_subject_is_matched_after_unicode_normalisation() {
    let e = engine().await;
    let composed = "caf\u{e9}";
    let decomposed = "cafe\u{301}";
    let f = create(&e, Some(composed), "s", "v").await;
    e.shred_subject(WHO, &domain(), decomposed, Reason::Admin)
        .await
        .unwrap();
    assert_eq!(read(&e, &f).await, Err(VaultError::Shredded));
}

#[tokio::test]
async fn a_fact_without_a_subject_is_not_covered_by_a_subject_shred() {
    // REQUIREMENTS C4: no subject means no subject shred. Naming the scope as a subject must not reach it.
    let e = engine().await;
    let f = create(&e, None, "kyc-doc:1", "v").await;
    assert_eq!(
        e.shred_subject(WHO, &domain(), "kyc-doc:1", Reason::Admin)
            .await
            .unwrap(),
        ShredSubject::NotFound
    );
    assert_eq!(read(&e, &f).await.unwrap(), "v");
}

#[tokio::test]
async fn facts_without_a_subject_in_different_scopes_do_not_share_a_key() {
    let e = engine().await;
    let a = create(&e, None, "scope-a", "a").await;
    let b = create(&e, None, "scope-b", "b").await;
    let bundle_a = e.store().fact_for_read(&domain(), &a).await.unwrap();
    let bundle_b = e.store().fact_for_read(&domain(), &b).await.unwrap();
    assert_ne!(
        bundle_a.fact.fact.subject_hmac,
        bundle_b.fact.fact.subject_hmac
    );
    assert_ne!(bundle_a.subject_key.key, bundle_b.subject_key.key);
}

#[tokio::test]
async fn a_sealed_vault_neither_stores_nor_reads_and_unsealing_restores_it() {
    let a = arena();
    let init = init_shamir(&a, 2, 3).unwrap();
    let config = init.config.clone();
    let shares = init.shares;
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
    let f = create(&e, Some("alice"), "kyc", SECRET).await;

    assert!(e.keyring().seal());
    assert_eq!(read(&e, &f).await, Err(VaultError::Sealed));
    assert_eq!(
        e.create_fact(WHO, &domain(), &fact(Some("alice"), "kyc", "v"))
            .await,
        Err(VaultError::Sealed)
    );
    assert_eq!(
        e.shred_subject(WHO, &domain(), "alice", Reason::Admin)
            .await,
        Err(VaultError::Sealed)
    );
    // Signing a ledger entry needs the root key, so a shred waits for an unseal.
    assert_eq!(
        e.shred_fact(WHO, &domain(), &f, Reason::Admin)
            .await
            .map(|_| ()),
        Err(VaultError::Sealed)
    );

    let again = pvlt_core::seal::unseal_with_shares(&arena(), &config, &shares[..2]).unwrap();
    e.keyring().unseal(again);
    assert_eq!(read(&e, &f).await.unwrap(), SECRET);
    e.shred_fact(WHO, &domain(), &f, Reason::Admin)
        .await
        .unwrap();
    assert_eq!(read(&e, &f).await, Err(VaultError::Shredded));
    let g = create(&e, Some("alice"), "kyc", "after").await;
    assert_eq!(read(&e, &g).await.unwrap(), "after");
}

#[tokio::test]
async fn an_object_moved_to_another_facts_row_does_not_open() {
    let e = engine().await;
    let a = create(&e, Some("alice"), "kyc", "value-a").await;
    let b = create(&e, Some("alice"), "kyc", "value-b").await;
    let (ka, kb) = (object_key(&e, &a).await, object_key(&e, &b).await);
    let sealed_a = e.objects().get(&ka).await.unwrap().unwrap();
    e.objects().put(&kb, sealed_a).await.unwrap();
    assert_eq!(read(&e, &b).await, Err(VaultError::OpenFailed));
}

#[tokio::test]
async fn a_flipped_bit_in_the_object_does_not_open() {
    let e = engine().await;
    let f = create(&e, Some("alice"), "kyc", SECRET).await;
    let bundle = e.store().fact_for_read(&domain(), &f).await.unwrap();
    let key = ObjectKey {
        domain_id: domain(),
        object_id: bundle.fact.fact.object_id,
    };
    let sealed = e.objects().get(&key).await.unwrap().unwrap();
    for at in [0, 40, 103, 104, sealed.len() - 1] {
        let mut bad = sealed.clone();
        bad[at] ^= 1;
        e.objects().put(&key, bad).await.unwrap();
        let got = read(&e, &f).await;
        assert!(got.is_err(), "bit flip at {at} was accepted");
    }
}

#[tokio::test]
async fn a_missing_object_is_unavailable_not_not_found() {
    let e = engine().await;
    let f = create(&e, Some("alice"), "kyc", SECRET).await;
    let bundle = e.store().fact_for_read(&domain(), &f).await.unwrap();
    e.objects()
        .delete(&ObjectKey {
            domain_id: domain(),
            object_id: bundle.fact.fact.object_id,
        })
        .await
        .unwrap();
    assert!(matches!(
        read(&e, &f).await,
        Err(VaultError::Unavailable(_))
    ));
}

#[tokio::test]
async fn a_fact_is_not_readable_in_another_domain() {
    let e = engine().await;
    let f = create(&e, Some("alice"), "kyc", SECRET).await;
    let other = id(8);
    e.ensure_domain(&other).await.unwrap();
    assert_eq!(
        e.read_fact(WHO, &other, &f).await.map(|_| ()),
        Err(VaultError::NotFound)
    );
}

#[tokio::test]
async fn an_expired_fact_is_not_found() {
    let e = engine().await;
    let past = OffsetDateTime::now_utc() - time::Duration::seconds(5);
    let future = OffsetDateTime::now_utc() + time::Duration::hours(1);
    let old = e
        .create_fact(
            WHO,
            &domain(),
            &CreateFact {
                expires_at: Some(past),
                ..fact(Some("a"), "s", "v")
            },
        )
        .await
        .unwrap();
    let live = e
        .create_fact(
            WHO,
            &domain(),
            &CreateFact {
                expires_at: Some(future),
                ..fact(Some("a"), "s", "v")
            },
        )
        .await
        .unwrap();
    assert_eq!(read(&e, &old).await, Err(VaultError::NotFound));
    assert_eq!(read(&e, &live).await.unwrap(), "v");
}

#[tokio::test]
async fn a_fact_under_legal_hold_cannot_be_shredded() {
    let e = engine().await;
    let f = create(&e, Some("alice"), "kyc", SECRET).await;
    e.store().set_legal_hold(&domain(), &f, true).await.unwrap();
    assert!(matches!(
        e.shred_fact(WHO, &domain(), &f, Reason::Admin).await,
        Err(VaultError::Conflict(_))
    ));
    assert_eq!(read(&e, &f).await.unwrap(), SECRET);
    e.store()
        .set_legal_hold(&domain(), &f, false)
        .await
        .unwrap();
    e.shred_fact(WHO, &domain(), &f, Reason::Admin)
        .await
        .unwrap();
}

#[tokio::test]
async fn bad_requests_are_refused_before_anything_is_written() {
    let e = engine_with(NullAuditor, Limits { max_value_len: 10 }).await;
    let cases = [
        ("empty scope", fact(Some("a"), "", "v")),
        ("empty subject", fact(Some(""), "s", "v")),
        ("too long", fact(Some("a"), "s", "01234567890")),
        (
            "no type",
            CreateFact {
                fact_type: "",
                ..fact(Some("a"), "s", "v")
            },
        ),
    ];
    for (name, request) in cases {
        let got = e.create_fact(WHO, &domain(), &request).await;
        assert!(
            matches!(got, Err(VaultError::Invalid(_))),
            "{name}: {got:?}"
        );
    }
    let long_type = "t".repeat(65);
    let got = e
        .create_fact(
            WHO,
            &domain(),
            &CreateFact {
                fact_type: &long_type,
                ..fact(Some("a"), "s", "v")
            },
        )
        .await;
    assert!(matches!(got, Err(VaultError::Invalid(_))));
    assert!(e.objects().is_empty());
}

#[tokio::test]
async fn a_duplicate_fact_id_is_refused_and_leaves_no_object_behind() {
    let e = engine().await;
    let same = uuid::Uuid::from_bytes([5; 16]);
    let request = CreateFact {
        fact_id: Some(same),
        ..fact(Some("a"), "s", "first")
    };
    e.create_fact(WHO, &domain(), &request).await.unwrap();
    let second = e
        .create_fact(
            WHO,
            &domain(),
            &CreateFact {
                value: b"second",
                ..request
            },
        )
        .await;
    assert!(matches!(second, Err(VaultError::Conflict(_))), "{second:?}");
    assert_eq!(e.objects().object_count(), 1);
    assert_eq!(read(&e, &same).await.unwrap(), "first");
}

#[tokio::test]
async fn many_creates_for_one_new_subject_all_succeed_and_share_one_key() {
    let e = Arc::new(engine().await);
    let mut tasks = Vec::new();
    for n in 0..16 {
        let e = Arc::clone(&e);
        tasks.push(tokio::spawn(async move {
            let value = format!("value-{n}");
            let f = e
                .create_fact(WHO, &domain(), &fact(Some("same-subject"), "s", &value))
                .await
                .unwrap();
            (f, value)
        }));
    }
    let mut keys = Vec::new();
    for t in tasks {
        let (f, value) = t.await.unwrap();
        assert_eq!(read(&e, &f).await.unwrap(), value);
        let bundle = e.store().fact_for_read(&domain(), &f).await.unwrap();
        keys.push(bundle.subject_key.key.wrapped);
    }
    keys.dedup();
    assert_eq!(keys.len(), 1, "the subject got more than one key");
}

#[tokio::test]
async fn the_sweeper_removes_only_objects_nobody_can_read() {
    let e = engine().await;
    let live = create(&e, Some("alice"), "kyc", "live").await;
    let shredded_subject = create(&e, Some("bob"), "kyc", "gone").await;
    e.shred_subject(WHO, &domain(), "bob", Reason::Admin)
        .await
        .unwrap();
    // A shred deletes the objects it destroys at once, so only unkeyed leftovers are the sweeper's.
    let orphan = ObjectKey {
        domain_id: domain(),
        object_id: id(99),
    };
    e.objects().put(&orphan, vec![1, 2, 3]).await.unwrap();
    let young = ObjectKey {
        domain_id: domain(),
        object_id: id(98),
    };
    e.objects().put(&young, vec![1, 2, 3]).await.unwrap();
    assert_eq!(e.objects().object_count(), 3);

    // With a real grace period nothing is old enough, so nothing is touched.
    let hour = Duration::from_secs(3600);
    let none = e.sweep_orphans(WHO, &domain(), hour).await.unwrap();
    assert_eq!((none.listed, none.too_young, none.deleted), (3, 3, 0));

    // Age everything but `young` by two hours.
    let long_ago = OffsetDateTime::now_utc() - time::Duration::hours(2);
    for meta in e.objects().list(&domain()).await.unwrap() {
        if meta.key != young {
            e.objects().backdate(&meta.key, long_ago);
        }
    }
    let report = e.sweep_orphans(WHO, &domain(), hour).await.unwrap();
    assert_eq!(report.listed, 3);
    assert_eq!(report.too_young, 1);
    assert_eq!(report.live, 1);
    assert_eq!(report.deleted, 1);
    assert_eq!(report.failed, 0);
    assert!(e.objects().contains(&young));
    assert!(!e.objects().contains(&orphan));
    assert_eq!(read(&e, &live).await.unwrap(), "live");
    assert_eq!(read(&e, &shredded_subject).await, Err(VaultError::Shredded));
}

type Recorded = (String, Action, Option<FactId>, &'static str);

#[derive(Default, Clone)]
struct Recorder(Arc<Mutex<Vec<Recorded>>>);

impl Auditor for Recorder {
    fn record(&self, e: &AuditEvent<'_>) {
        self.0
            .lock()
            .unwrap()
            .push((e.principal.to_owned(), e.action, e.fact_id, e.outcome));
    }
}

#[tokio::test]
async fn every_operation_is_reported_with_its_outcome_and_nothing_secret() {
    let recorder = Recorder::default();
    let e = engine_with(recorder.clone(), Limits::default()).await;
    let f = create(&e, Some("alice@example.com"), "scope-of-alice", SECRET).await;
    read(&e, &f).await.unwrap();
    e.shred_fact("shredder", &domain(), &f, Reason::Admin)
        .await
        .unwrap();
    let _ = read(&e, &f).await;
    let _ = e
        .create_fact(WHO, &domain(), &fact(Some("a"), "", "v"))
        .await;

    let events = recorder.0.lock().unwrap().clone();
    let summary: Vec<_> = events
        .iter()
        .map(|(p, a, _, o)| (p.as_str(), *a, *o))
        .collect();
    assert_eq!(
        summary,
        [
            (WHO, Action::Create, "ok"),
            (WHO, Action::Read, "ok"),
            ("shredder", Action::ShredFact, "ok"),
            (WHO, Action::Read, "shredded"),
            (WHO, Action::Create, "invalid"),
        ]
    );
    assert_eq!(events[0].2, Some(f));
    let text = format!("{events:?}");
    for needle in [SECRET, "alice@example.com", "scope-of-alice"] {
        assert!(!text.contains(needle));
    }
}

#[tokio::test]
async fn a_batch_is_stored_whole_and_in_order() {
    let e = engine().await;
    let batch = [
        fact(Some("alice"), "kyc-doc:1", "the-key"),
        CreateFact {
            fact_type: "base64",
            ..fact(Some("alice"), "kyc-doc:1", "the-path")
        },
        fact(Some("bob"), "other", "third"),
    ];
    let ids = e.create_facts(WHO, &domain(), &batch).await.unwrap();
    assert_eq!(ids.len(), 3);
    for (id, want) in ids.iter().zip(["the-key", "the-path", "third"]) {
        assert_eq!(read(&e, id).await.unwrap(), want);
    }
    assert_eq!(e.objects().object_count(), 3);
}

#[tokio::test]
async fn a_batch_with_one_bad_fact_stores_nothing() {
    let e = engine().await;
    let (a, b) = (
        uuid::Uuid::from_bytes([1; 16]),
        uuid::Uuid::from_bytes([2; 16]),
    );
    // The second fact has an empty scope, so the batch is refused before anything is written.
    let got = e
        .create_facts(
            WHO,
            &domain(),
            &[
                CreateFact {
                    fact_id: Some(a),
                    ..fact(Some("alice"), "s", "one")
                },
                CreateFact {
                    fact_id: Some(b),
                    ..fact(Some("alice"), "", "two")
                },
            ],
        )
        .await;
    assert!(matches!(got, Err(VaultError::Invalid(_))), "{got:?}");
    assert_eq!(e.objects().object_count(), 0);
    assert_eq!(read(&e, &a).await, Err(VaultError::NotFound));

    // A duplicate id inside the batch is caught by the key store after the objects were written: they go too.
    let dup = e
        .create_facts(
            WHO,
            &domain(),
            &[
                CreateFact {
                    fact_id: Some(a),
                    ..fact(Some("alice"), "s", "one")
                },
                CreateFact {
                    fact_id: Some(a),
                    ..fact(Some("alice"), "s", "two")
                },
            ],
        )
        .await;
    assert!(matches!(dup, Err(VaultError::Conflict(_))), "{dup:?}");
    assert_eq!(e.objects().object_count(), 0);
    assert_eq!(read(&e, &a).await, Err(VaultError::NotFound));
}

#[tokio::test]
async fn a_batch_that_touches_a_shredded_subject_stores_nothing() {
    let e = engine().await;
    create(&e, Some("gone"), "s", "v").await;
    e.shred_subject(WHO, &domain(), "gone", Reason::Admin)
        .await
        .unwrap();
    let a = uuid::Uuid::from_bytes([1; 16]);
    let got = e
        .create_facts(
            WHO,
            &domain(),
            &[
                CreateFact {
                    fact_id: Some(a),
                    ..fact(Some("fine"), "s", "one")
                },
                fact(Some("gone"), "s", "two"),
            ],
        )
        .await;
    assert_eq!(got, Err(VaultError::Shredded));
    assert_eq!(e.objects().object_count(), 0);
    assert_eq!(read(&e, &a).await, Err(VaultError::NotFound));
}

#[tokio::test]
async fn a_batch_must_have_between_one_and_the_maximum_number_of_facts() {
    let e = engine().await;
    assert!(matches!(
        e.create_facts(WHO, &domain(), &[]).await,
        Err(VaultError::Invalid(_))
    ));
    let too_many: Vec<_> = (0..17).map(|_| fact(Some("a"), "s", "v")).collect();
    assert!(matches!(
        e.create_facts(WHO, &domain(), &too_many).await,
        Err(VaultError::Invalid(_))
    ));
    let max: Vec<_> = (0..16).map(|_| fact(Some("a"), "s", "v")).collect();
    assert_eq!(
        e.create_facts(WHO, &domain(), &max).await.unwrap().len(),
        16
    );
}

#[tokio::test]
async fn fact_meta_describes_a_fact_without_opening_it_and_says_when_it_is_gone() {
    use pvlt_core::store::State;
    let e = engine().await;
    let f = create(&e, Some("alice"), "kyc", SECRET).await;
    let meta = e.fact_meta(&domain(), &f).await.unwrap();
    assert_eq!(meta.fact_type, "ascii");
    assert_eq!(meta.state, State::Active);
    assert_eq!(
        meta.subject_hmac,
        e.subject_hmac(&domain(), "alice").await.unwrap()
    );
    assert_eq!(
        meta.scope_hmac,
        e.scope_hmac(&domain(), "kyc").await.unwrap()
    );
    assert_ne!(
        meta.subject_hmac,
        e.subject_hmac(&domain(), "bob").await.unwrap()
    );
    // A subject shred makes the fact shredded in its meta too.
    e.shred_subject(WHO, &domain(), "alice", Reason::Admin)
        .await
        .unwrap();
    assert_eq!(
        e.fact_meta(&domain(), &f).await.unwrap().state,
        State::Shredded
    );
    assert_eq!(
        e.fact_meta(&domain(), &uuid::Uuid::from_bytes([9; 16]))
            .await,
        Err(VaultError::NotFound)
    );
}
