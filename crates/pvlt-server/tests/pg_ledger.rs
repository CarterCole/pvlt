//! The shred ledger on PostgreSQL: atomic with the shred, append-only, serialised under concurrency, and
//! restored from a real database copy.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::sync::Arc;

use common::{TestDb, World, fact, fact_id, person, refused_with};
use pvlt_core::VaultError;
use pvlt_core::audit::NullAuditor;
use pvlt_core::engine::{CreateFact, Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::ledger::{self, Reason};
use pvlt_core::memory::MemObjectStore;
use pvlt_core::objects::ObjectStore;
use pvlt_core::seal::{SealConfig, UnsealShare, init_shamir, unseal_with_shares};
use pvlt_core::store::{FactId, KeyStore, LedgerAppend, ShredFact, ShredPlan, State, StoreError};
use pvlt_mem::{Arena, LockPolicy};
use pvlt_server::pg::PgStore;

const SECRET: &str = "Quentin-Q.-Nightingale-1987-03-09";
const WHO: &str = "tester";

fn append(seq: u64, prev: [u8; 32], tag: u8) -> LedgerAppend {
    LedgerAppend {
        seq,
        prev,
        hash: [tag; 32],
        line: vec![tag; 8],
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn the_database_keeps_the_ledger_append_only() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let (f, _) = fact(&seed, &alice, 1);
    w.store().insert_fact(&f).await.unwrap();
    let plan = ShredPlan::Facts {
        fact_ids: vec![f.fact_id],
    };
    w.store()
        .apply_shred(&seed.domain_id, &plan, &append(0, [0; 32], 1))
        .await
        .unwrap();

    let key = w
        .root
        .new_signing_key(
            &w.arena,
            &seed.domain_id,
            pvlt_format::wrap::SignPurpose::Ledger,
        )
        .unwrap();
    w.store()
        .get_or_insert_sign_key(&seed.domain_id, &key)
        .await
        .unwrap();
    let hex_id = common::hex(&seed.domain_id);
    for (what, sql) in [
        (
            "delete",
            format!("DELETE FROM ledger WHERE domain_id = decode('{hex_id}', 'hex')"),
        ),
        (
            "change the line",
            format!(
                "UPDATE ledger SET line = '\\x00'::bytea WHERE domain_id = decode('{hex_id}', 'hex')"
            ),
        ),
        (
            "change the hash",
            format!(
                "UPDATE ledger SET entry_hash = decode(repeat('ff', 32), 'hex') WHERE domain_id = decode('{hex_id}', 'hex')"
            ),
        ),
        (
            "change the seq",
            format!("UPDATE ledger SET seq = 9 WHERE domain_id = decode('{hex_id}', 'hex')"),
        ),
        (
            "a signing key delete",
            format!("DELETE FROM sign_keys WHERE domain_id = decode('{hex_id}', 'hex')"),
        ),
    ] {
        // `refused_with` wants a static string; leak the few test strings.
        let sql: &'static str = Box::leak(sql.into_boxed_str());
        let (code, _) = refused_with(w.db.pool(), sql).await;
        // 23000 is integrity_constraint_violation, the code the triggers raise. A syntax error or a missing
        // column would be a different code.
        assert_eq!(code, "23000", "{what}");
    }
    // The only allowed change: published false to true, and never back.
    w.store()
        .ledger_mark_published(&seed.domain_id, 0)
        .await
        .unwrap();
    let back: &'static str = Box::leak(
        format!("UPDATE ledger SET published = false WHERE domain_id = decode('{hex_id}', 'hex')")
            .into_boxed_str(),
    );
    assert_eq!(refused_with(w.db.pool(), back).await.0, "23000");
    let rec = w.store().ledger_records(&seed.domain_id, 0).await.unwrap();
    assert_eq!(rec.len(), 1);
    assert!(rec[0].published);
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_refused_shred_leaves_no_ledger_row_and_destroys_nothing() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let (held, _) = fact(&seed, &alice, 1);
    let (plain, _) = fact(&seed, &alice, 2);
    w.store().insert_fact(&held).await.unwrap();
    w.store().insert_fact(&plain).await.unwrap();
    w.store()
        .set_legal_hold(&seed.domain_id, &held.fact_id, true)
        .await
        .unwrap();

    // One fact in the plan is held, so the whole thing is refused, including the fact that was not.
    let plan = ShredPlan::Facts {
        fact_ids: vec![plain.fact_id, held.fact_id],
    };
    let got = w
        .store()
        .apply_shred(&seed.domain_id, &plan, &append(0, [0; 32], 1))
        .await;
    assert_eq!(got, Err(StoreError::LegalHold));
    assert!(
        w.store()
            .ledger_head(&seed.domain_id)
            .await
            .unwrap()
            .is_none()
    );
    let bundle = w
        .store()
        .fact_for_read(&seed.domain_id, &plain.fact_id)
        .await
        .unwrap();
    assert_eq!(bundle.fact.state, State::Active);
    assert_ne!(bundle.fact.fact.dek.wrapped, vec![0u8; 107]);
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_plan_that_went_stale_is_refused_whole() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let (a, _) = fact(&seed, &alice, 1);
    w.store().insert_fact(&a).await.unwrap();
    let scope = a.scope_hmac;
    let plan = ShredPlan::Scope {
        scope_hmac: scope,
        fact_ids: vec![a.fact_id],
    };

    // A second fact lands in the scope after the plan was made.
    let mut b = fact(&seed, &alice, 2).0;
    b.scope_hmac = scope;
    w.store().insert_fact(&b).await.unwrap();
    let got = w
        .store()
        .apply_shred(&seed.domain_id, &plan, &append(0, [0; 32], 1))
        .await;
    assert!(matches!(got, Err(StoreError::Conflict(_))), "{got:?}");
    assert!(
        w.store()
            .ledger_head(&seed.domain_id)
            .await
            .unwrap()
            .is_none()
    );
    for f in [&a, &b] {
        let got = w
            .store()
            .fact_for_read(&seed.domain_id, &f.fact_id)
            .await
            .unwrap();
        assert_eq!(got.fact.state, State::Active);
    }
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn of_many_concurrent_appends_to_one_sequence_number_exactly_one_wins() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let mut facts = Vec::new();
    for n in 0..16 {
        let (f, _) = fact(&seed, &alice, n);
        w.store().insert_fact(&f).await.unwrap();
        facts.push(f.fact_id);
    }
    let store = Arc::new(w.store().clone());
    let mut tasks = Vec::new();
    for (i, id) in facts.iter().enumerate() {
        let (store, domain, id) = (Arc::clone(&store), seed.domain_id, *id);
        tasks.push(tokio::spawn(async move {
            let plan = ShredPlan::Facts { fact_ids: vec![id] };
            store
                .apply_shred(
                    &domain,
                    &plan,
                    &append(0, [0; 32], u8::try_from(i + 1).unwrap()),
                )
                .await
        }));
    }
    let mut wins = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(_) => wins += 1,
            Err(StoreError::Conflict(_)) => {}
            Err(e) => panic!("{e:?}"),
        }
    }
    assert_eq!(wins, 1);
    // Exactly one fact was destroyed, and it is the one whose entry is in the ledger.
    let mut shredded = 0;
    for id in &facts {
        let b = w.store().fact_for_read(&seed.domain_id, id).await.unwrap();
        if b.fact.state == State::Shredded {
            shredded += 1;
        }
    }
    assert_eq!(shredded, 1);
    assert_eq!(
        w.store()
            .ledger_records(&seed.domain_id, 0)
            .await
            .unwrap()
            .len(),
        1
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn an_append_must_follow_the_head() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let mut ids = Vec::new();
    for n in 0..3 {
        let (f, _) = fact(&seed, &alice, n);
        w.store().insert_fact(&f).await.unwrap();
        ids.push(f.fact_id);
    }
    let one = |id: FactId| ShredPlan::Facts { fact_ids: vec![id] };
    let d = seed.domain_id;
    w.store()
        .apply_shred(&d, &one(ids[0]), &append(0, [0; 32], 1))
        .await
        .unwrap();
    // Wrong seq, wrong prev, and a repeat of seq 0.
    for bad in [
        append(2, [1; 32], 2),
        append(1, [9; 32], 2),
        append(0, [0; 32], 2),
    ] {
        let got = w.store().apply_shred(&d, &one(ids[1]), &bad).await;
        assert!(
            matches!(got, Err(StoreError::Conflict(_))),
            "{bad:?} {got:?}"
        );
    }
    w.store()
        .apply_shred(&d, &one(ids[1]), &append(1, [1; 32], 2))
        .await
        .unwrap();
    let head = w.store().ledger_head(&d).await.unwrap().unwrap();
    assert_eq!((head.seq, head.hash), (1, [2; 32]));
    w.finish().await;
}

// --- The engine over Postgres: restore from a real database copy -------------------------------------------

type PgEngine = Engine<PgStore, MemObjectStore, NullAuditor>;

struct Rig {
    db: TestDb,
    engine: PgEngine,
    config: SealConfig,
    shares: Vec<UnsealShare>,
}

const DOMAIN: [u8; 16] = [7; 16];

async fn pg_engine(
    store: PgStore,
    objects: MemObjectStore,
    config: &SealConfig,
    shares: &[UnsealShare],
) -> PgEngine {
    let ring = Keyring::new(Arena::new(256, LockPolicy::BestEffort).unwrap());
    let root = unseal_with_shares(ring.arena(), config, &shares[..2]).unwrap();
    ring.unseal(root);
    Engine::new(ring, store, objects, NullAuditor, Limits::default())
}

async fn rig() -> Rig {
    let db = TestDb::new().await;
    let init = init_shamir(&Arena::new(256, LockPolicy::BestEffort).unwrap(), 2, 3).unwrap();
    let engine = pg_engine(
        db.store.clone(),
        MemObjectStore::new(),
        &init.config,
        &init.shares,
    )
    .await;
    engine.ensure_domain(&DOMAIN).await.unwrap();
    Rig {
        db,
        engine,
        config: init.config,
        shares: init.shares,
    }
}

async fn create(e: &PgEngine, subject: &str, scope: &str, value: &str) -> FactId {
    e.create_fact(
        WHO,
        &DOMAIN,
        &CreateFact {
            fact_id: None,
            subject: Some(subject),
            scope,
            fact_type: "ascii",
            value: value.as_bytes(),
            expires_at: None,
        },
    )
    .await
    .unwrap()
}

async fn read(e: &PgEngine, f: &FactId) -> Result<String, VaultError> {
    e.read_fact(WHO, &DOMAIN, f)
        .await
        .map(|v| String::from_utf8(v.value.to_vec()).unwrap())
}

impl Rig {
    /// A server over a copy of the database taken now and the data bucket as it is now, pointed at the
    /// **current** ledger bucket, which is never rolled back.
    async fn backup(&self) -> (TestDb, MemObjectStore) {
        (self.db.snapshot().await, self.engine.objects().snapshot())
    }

    async fn restored(&self, backup: &(TestDb, MemObjectStore)) -> PgEngine {
        let data = backup.1.snapshot();
        for (path, _) in self.engine.objects().list_prefix("ledger/").await.unwrap() {
            let bytes = self
                .engine
                .objects()
                .get_path(&path)
                .await
                .unwrap()
                .unwrap();
            data.put_path(&path, bytes).await.unwrap();
        }
        pg_engine(backup.0.store.clone(), data, &self.config, &self.shares).await
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_database_restored_from_a_backup_is_re_shredded_before_anything_reads_it() {
    let r = rig().await;
    let alice1 = create(&r.engine, "alice", "kyc", SECRET).await;
    let alice2 = create(&r.engine, "alice", "other", "a2").await;
    let bob = create(&r.engine, "bob", "tax", "b1").await;
    let carol = create(&r.engine, "carol", "tax", "c1").await;
    let dave = create(&r.engine, "dave", "misc", "d1").await;
    let single = create(&r.engine, "erin", "misc", "e1").await;
    let backup = r.backup().await;

    r.engine
        .shred_subject(WHO, &DOMAIN, "alice", Reason::SubjectRequest)
        .await
        .unwrap();
    assert_eq!(
        r.engine
            .shred_scope(WHO, &DOMAIN, "tax", Reason::Legal)
            .await
            .unwrap(),
        2
    );
    assert!(matches!(
        r.engine
            .shred_fact(WHO, &DOMAIN, &single, Reason::Admin)
            .await
            .unwrap(),
        ShredFact::Shredded { .. }
    ));
    for f in [&alice1, &alice2, &bob, &carol, &single] {
        assert_eq!(read(&r.engine, f).await, Err(VaultError::Shredded));
    }

    let restored = r.restored(&backup).await;
    for f in [&alice1, &alice2, &bob, &carol, &single, &dave] {
        assert!(
            read(&restored, f).await.is_ok(),
            "the control must show the problem"
        );
    }
    let report = restored.reconcile().await.unwrap();
    assert_eq!((report.replayed, report.republished), (3, 0));
    for f in [&alice1, &alice2, &bob, &carol, &single] {
        assert_eq!(read(&restored, f).await, Err(VaultError::Shredded));
    }
    assert_eq!(read(&restored, &dave).await.unwrap(), "d1");
    // The restored database now holds the same ledger, published, and is in step with the bucket.
    assert!(restored.ledger_in_sync().await.unwrap());
    assert_eq!(restored.reconcile().await.unwrap().replayed, 0);
    // A subject shredded in the ledger cannot be written to again.
    let again = restored
        .create_fact(
            WHO,
            &DOMAIN,
            &CreateFact {
                fact_id: None,
                subject: Some("alice"),
                scope: "kyc",
                fact_type: "ascii",
                value: b"x",
                expires_at: None,
            },
        )
        .await;
    assert_eq!(again, Err(VaultError::Shredded));

    backup.0.finish().await;
    r.db.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_subject_shredded_after_the_backup_gets_a_tombstone_in_the_restored_database() {
    let r = rig().await;
    create(&r.engine, "zed", "kyc", "z").await;
    let backup = r.backup().await;
    let later = create(&r.engine, "newcomer", "kyc", "n").await;
    r.engine
        .shred_subject(WHO, &DOMAIN, "newcomer", Reason::SubjectRequest)
        .await
        .unwrap();
    assert_eq!(read(&r.engine, &later).await, Err(VaultError::Shredded));

    let restored = r.restored(&backup).await;
    restored.reconcile().await.unwrap();
    let again = restored
        .create_fact(
            WHO,
            &DOMAIN,
            &CreateFact {
                fact_id: None,
                subject: Some("newcomer"),
                scope: "kyc",
                fact_type: "ascii",
                value: b"x",
                expires_at: None,
            },
        )
        .await;
    assert_eq!(again, Err(VaultError::Shredded));
    backup.0.finish().await;
    r.db.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_restored_database_with_a_published_entry_missing_from_the_bucket_is_refused() {
    let r = rig().await;
    let f = create(&r.engine, "alice", "kyc", "v").await;
    r.engine
        .shred_fact(WHO, &DOMAIN, &f, Reason::Admin)
        .await
        .unwrap();
    r.engine
        .objects()
        .delete_path(&ledger::path_for(&DOMAIN, 0))
        .await
        .unwrap();
    assert!(matches!(
        r.engine.reconcile().await,
        Err(VaultError::Integrity(_))
    ));
    r.db.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn concurrent_shreds_through_the_engine_leave_one_verified_chain() {
    let r = Arc::new(rig().await);
    let mut facts = Vec::new();
    for n in 0..20 {
        facts.push(create(&r.engine, &format!("user-{n}"), "kyc", "v").await);
    }
    let mut tasks = Vec::new();
    for f in facts {
        let r = Arc::clone(&r);
        tasks.push(tokio::spawn(async move {
            r.engine
                .shred_fact(WHO, &DOMAIN, &f, Reason::Admin)
                .await
                .unwrap()
        }));
    }
    for t in tasks {
        assert!(matches!(t.await.unwrap(), ShredFact::Shredded { .. }));
    }
    assert!(r.engine.ledger_in_sync().await.unwrap());
    assert_eq!(r.engine.reconcile().await.unwrap().replayed, 0);
    let head = r
        .engine
        .store()
        .ledger_head(&DOMAIN)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.seq, 19);
    let r = Arc::try_unwrap(r).ok().unwrap();
    r.db.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn expiry_hold_and_rebind_work_in_the_database() {
    let r = rig().await;
    let past = time::OffsetDateTime::now_utc() - time::Duration::seconds(5);
    let held = r
        .engine
        .create_fact(
            WHO,
            &DOMAIN,
            &CreateFact {
                fact_id: None,
                subject: Some("a"),
                scope: "s",
                fact_type: "ascii",
                value: b"held",
                expires_at: Some(past),
            },
        )
        .await
        .unwrap();
    let due = r
        .engine
        .create_fact(
            WHO,
            &DOMAIN,
            &CreateFact {
                fact_id: None,
                subject: Some("b"),
                scope: "s",
                fact_type: "ascii",
                value: b"due",
                expires_at: Some(past),
            },
        )
        .await
        .unwrap();
    let moved = create(&r.engine, "c", "draft", "moved").await;
    r.engine
        .set_legal_hold(WHO, &DOMAIN, &held, true)
        .await
        .unwrap();
    assert_eq!(r.engine.sweep_expired(WHO, &DOMAIN, 10).await.unwrap(), 1);
    assert_eq!(read(&r.engine, &due).await, Err(VaultError::Shredded));
    assert_eq!(
        read(&r.engine, &held).await,
        Err(VaultError::NotFound),
        "held but expired: unreadable, not erased"
    );
    assert!(matches!(
        r.engine
            .shred_fact(WHO, &DOMAIN, &held, Reason::Admin)
            .await,
        Err(VaultError::Conflict(_))
    ));

    r.engine
        .rebind_scope(WHO, &DOMAIN, &moved, "approved")
        .await
        .unwrap();
    assert_eq!(
        r.engine
            .shred_scope(WHO, &DOMAIN, "draft", Reason::Admin)
            .await
            .unwrap(),
        0
    );
    assert_eq!(read(&r.engine, &moved).await.unwrap(), "moved");
    assert_eq!(
        r.engine
            .shred_scope(WHO, &DOMAIN, "approved", Reason::Admin)
            .await
            .unwrap(),
        1
    );
    assert_eq!(
        r.engine
            .set_legal_hold(WHO, &DOMAIN, &fact_id(99), true)
            .await,
        Err(VaultError::NotFound)
    );
    assert!(matches!(
        r.engine.set_legal_hold(WHO, &DOMAIN, &moved, true).await,
        Err(VaultError::Conflict(_))
    ));
    let _ = person;
    r.db.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn an_export_loads_into_an_empty_key_store_unchanged_and_never_into_a_used_one() {
    let r = rig().await;
    let a = create(&r.engine, "alice", "kyc", SECRET).await;
    let b = create(&r.engine, "bob", "kyc", "b").await;
    r.engine
        .shred_fact(WHO, &DOMAIN, &a, Reason::Admin)
        .await
        .unwrap();
    r.engine
        .shred_subject(WHO, &DOMAIN, "bob", Reason::SubjectRequest)
        .await
        .unwrap();
    r.engine
        .store()
        .create_issuer("backend", &[7; 32], &["verifier".to_owned()])
        .await
        .unwrap();
    r.engine
        .store()
        .put_policy(b"{\"version\":1}", &[3; 32], "admin")
        .await
        .unwrap();
    let init = r.engine.store().seal_config().await.unwrap();
    assert!(
        init.is_none(),
        "this rig never wrote a seal config; the export must cope with an empty table"
    );

    let dump = r.db.store.export_all().await.unwrap();
    assert!(dump.iter().all(|t| !t.table.is_empty()));
    let counts: Vec<(String, usize)> = dump
        .iter()
        .map(|t| (t.table.clone(), t.rows.len()))
        .collect();
    assert_eq!(
        counts,
        [
            ("seal_config".to_owned(), 0),
            ("domains".to_owned(), 1),
            ("subject_keys".to_owned(), 2),
            ("facts".to_owned(), 2),
            ("sign_keys".to_owned(), 2),
            ("ledger".to_owned(), 2),
            ("audit".to_owned(), 4),
            ("issuers".to_owned(), 1),
            ("policies".to_owned(), 1),
            ("approvals".to_owned(), 0),
        ]
    );
    // Nothing in a dump is a value, a subject or a scope.
    let text = serde_json::to_string(&dump.iter().map(|t| &t.rows).collect::<Vec<_>>()).unwrap();
    for needle in ["Nightingale", "alice", "bob", "kyc"] {
        assert!(!text.contains(needle), "the export holds {needle}");
    }

    let fresh = TestDb::new().await;
    fresh.store.import_all(&dump).await.unwrap();
    assert_eq!(
        fresh.store.export_all().await.unwrap(),
        dump,
        "an import must reproduce the export exactly"
    );
    // The restored key store is a working one: the ledger is intact and the shreds are still shredded.
    // Identity sequences continue after the restored ids, so the next issuer does not collide.
    let next = fresh
        .store
        .create_issuer("second", &[8; 32], &[])
        .await
        .unwrap();
    assert_eq!(next.key_id, 2);
    let next_policy = fresh
        .store
        .put_policy(b"{\"version\":1,\"roles\":{}}", &[4; 32], "admin")
        .await
        .unwrap();
    assert_eq!(next_policy.version, 2);
    let again = fresh.store.import_all(&dump).await;
    assert!(matches!(again, Err(StoreError::Conflict(_))), "{again:?}");
    let head = fresh.store.ledger_head(&DOMAIN).await.unwrap().unwrap();
    assert_eq!(head.seq, 1);
    assert_eq!(
        fresh
            .store
            .fact_for_read(&DOMAIN, &b)
            .await
            .unwrap()
            .subject_key
            .state,
        State::Shredded
    );
    // A dump with a table missing is refused before anything is written.
    let short = &dump[..3];
    assert!(matches!(
        TestDb::new().await.store.import_all(short).await,
        Err(StoreError::Conflict(_))
    ));
    fresh.finish().await;
    r.db.finish().await;
}
