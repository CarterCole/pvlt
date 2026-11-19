//! The audit log on PostgreSQL: append-only, chained across writers, verified against checkpoints, and
//! restored from a real database copy.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::sync::Arc;

use common::{TestDb, World, refused_with};
use pvlt_core::VaultError;
use pvlt_core::audit::NullAuditor;
use pvlt_core::engine::{AuditStatus, CreateFact, Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::memory::MemObjectStore;
use pvlt_core::objects::ObjectStore;
use pvlt_core::seal::{SealConfig, UnsealShare, init_shamir, unseal_with_shares};
use pvlt_core::store::{AuditAppend, AuditFilter, FactId, KeyStore, StoreError};
use pvlt_mem::{Arena, LockPolicy};
use pvlt_server::pg::PgStore;
use time::OffsetDateTime;

const DOMAIN: [u8; 16] = [7; 16];
const WHO: &str = "tester";
const POLICY: [u8; 32] = [4; 32];

fn entry(seq: u64, prev: [u8; 32], tag: u8) -> AuditAppend {
    AuditAppend {
        seq,
        prev,
        hash: [tag; 32],
        line: vec![tag; 4],
        kind: "read.grant".into(),
        principal: "p".into(),
        fact_id: None,
        subject_hmac: None,
        at: OffsetDateTime::now_utc(),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn the_database_keeps_the_audit_log_append_only_and_chained() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let d = seed.domain_id;
    w.store()
        .append_audit(&d, &[entry(0, [0; 32], 1), entry(1, [1; 32], 2)])
        .await
        .unwrap();
    let head = w.store().audit_head(&d).await.unwrap().unwrap();
    assert_eq!((head.seq, head.hash), (1, [2; 32]));

    // Wrong sequence number, wrong previous hash, a repeat, and a batch that is not a chain.
    for (bad, what) in [
        (vec![entry(3, [2; 32], 9)], "a gap"),
        (vec![entry(2, [7; 32], 9)], "a wrong prev"),
        (vec![entry(1, [1; 32], 9)], "a repeat"),
        (
            vec![entry(2, [2; 32], 3), entry(3, [9; 32], 4)],
            "a broken batch",
        ),
    ] {
        let got = w.store().append_audit(&d, &bad).await;
        assert!(
            matches!(got, Err(StoreError::Conflict(_))),
            "{what}: {got:?}"
        );
    }
    // A failed batch stored none of its entries, including the good first one.
    assert_eq!(w.store().audit_head(&d).await.unwrap().unwrap().seq, 1);

    let hex_id = common::hex(&d);
    for sql in [
        format!("DELETE FROM audit WHERE domain_id = decode('{hex_id}', 'hex')"),
        format!(
            "UPDATE audit SET principal = 'mallory' WHERE domain_id = decode('{hex_id}', 'hex')"
        ),
        format!(
            "UPDATE audit SET line = '\\x00'::bytea WHERE domain_id = decode('{hex_id}', 'hex')"
        ),
    ] {
        let sql: &'static str = Box::leak(sql.into_boxed_str());
        assert_eq!(refused_with(w.db.pool(), sql).await.0, "23000", "{sql}");
    }
    // An entry for a domain that does not exist is refused.
    assert!(matches!(
        w.store()
            .append_audit(&[9; 16], &[entry(0, [0; 32], 1)])
            .await,
        Err(StoreError::Conflict(_))
    ));
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn of_many_writers_extending_one_head_exactly_one_wins_each_round() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let store = Arc::new(w.store().clone());
    let mut tasks = Vec::new();
    for i in 0..16u8 {
        let (store, d) = (Arc::clone(&store), seed.domain_id);
        tasks.push(tokio::spawn(async move {
            store.append_audit(&d, &[entry(0, [0; 32], i + 1)]).await
        }));
    }
    let mut wins = 0;
    for t in tasks {
        match t.await.unwrap() {
            Ok(()) => wins += 1,
            Err(StoreError::Conflict(_)) => {}
            Err(e) => panic!("{e:?}"),
        }
    }
    assert_eq!(wins, 1);
    assert_eq!(
        w.store()
            .audit_records(&seed.domain_id, 0, 100)
            .await
            .unwrap()
            .len(),
        1
    );
    w.finish().await;
}

// --- The engine over Postgres ------------------------------------------------------------------------------

/// A bucket two engines can share.
#[derive(Clone, Default)]
struct Shared(Arc<MemObjectStore>);

impl ObjectStore for Shared {
    async fn ping(&self) -> Result<(), pvlt_core::objects::ObjectError> {
        self.0.ping().await
    }
    async fn put_path(&self, p: &str, b: Vec<u8>) -> Result<(), pvlt_core::objects::ObjectError> {
        self.0.put_path(p, b).await
    }
    async fn get_path(&self, p: &str) -> Result<Option<Vec<u8>>, pvlt_core::objects::ObjectError> {
        self.0.get_path(p).await
    }
    async fn delete_path(&self, p: &str) -> Result<(), pvlt_core::objects::ObjectError> {
        self.0.delete_path(p).await
    }
    async fn list_prefix(
        &self,
        p: &str,
    ) -> Result<Vec<(String, pvlt_core::objects::ObjectInfo)>, pvlt_core::objects::ObjectError>
    {
        self.0.list_prefix(p).await
    }
}

type PgEngine = Engine<PgStore, Shared, NullAuditor>;

struct Rig {
    db: TestDb,
    engine: PgEngine,
    config: SealConfig,
    shares: Vec<UnsealShare>,
}

fn engine_over(
    store: PgStore,
    objects: Shared,
    config: &SealConfig,
    shares: &[UnsealShare],
) -> PgEngine {
    let ring = Keyring::new(Arena::new(256, LockPolicy::BestEffort).unwrap());
    ring.unseal(unseal_with_shares(ring.arena(), config, &shares[..2]).unwrap());
    Engine::new(ring, store, objects, NullAuditor, Limits::default())
        .with_checkpoint_policy(1, std::time::Duration::ZERO)
}

async fn rig() -> Rig {
    let db = TestDb::new().await;
    let init = init_shamir(&Arena::new(256, LockPolicy::BestEffort).unwrap(), 2, 3).unwrap();
    let engine = engine_over(
        db.store.clone(),
        Shared::default(),
        &init.config,
        &init.shares,
    );
    engine.ensure_domain(&DOMAIN).await.unwrap();
    Rig {
        db,
        engine,
        config: init.config,
        shares: init.shares,
    }
}

async fn create(e: &PgEngine, subject: &str, value: &str) -> FactId {
    e.create_fact(
        WHO,
        &DOMAIN,
        &CreateFact {
            fact_id: None,
            subject: Some(subject),
            scope: "s",
            fact_type: "ascii",
            value: value.as_bytes(),
            expires_at: None,
        },
    )
    .await
    .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn two_servers_writing_one_log_leave_one_verified_chain() {
    let r = rig().await;
    // A second engine on the same database is a second replica: its writer races the first's for the head.
    let second = Arc::new(engine_over(
        r.db.store.clone(),
        r.engine.objects().clone(),
        &r.config,
        &r.shares,
    ));
    let first = Arc::new(r.engine);
    let f = create(&first, "alice", "v").await;
    let mut tasks = Vec::new();
    for i in 0..60 {
        let e = if i % 2 == 0 {
            Arc::clone(&first)
        } else {
            Arc::clone(&second)
        };
        tasks.push(tokio::spawn(async move {
            e.read_fact(WHO, &DOMAIN, &f).await.map(|_| ())
        }));
    }
    for t in tasks {
        t.await.unwrap().unwrap();
    }
    let rows = first.store().audit_records(&DOMAIN, 0, 1000).await.unwrap();
    assert_eq!(rows.iter().filter(|r| r.kind == "read.grant").count(), 60);
    let v = first.verify_audit(&DOMAIN).await.unwrap();
    assert_eq!(v.status, AuditStatus::Ok);
    assert_eq!(v.entries, 61);
    r.db.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_restored_database_is_caught_by_the_checkpoints_and_reads_wait_for_an_acknowledgement() {
    let r = rig().await;
    let f = create(&r.engine, "alice", "v").await;
    r.engine.read_fact(WHO, &DOMAIN, &f).await.unwrap();
    // A backup of the database, then more history, with a checkpoint pinning it.
    let backup = r.db.snapshot().await;
    for _ in 0..3 {
        r.engine.read_fact(WHO, &DOMAIN, &f).await.unwrap();
    }
    r.engine.write_checkpoints(&POLICY).await.unwrap();
    assert_eq!(
        r.engine.verify_audit(&DOMAIN).await.unwrap().status,
        AuditStatus::Ok
    );

    // The restored server: the older database and the bucket that was never rolled back.
    let restored = engine_over(
        backup.store.clone(),
        r.engine.objects().clone(),
        &r.config,
        &r.shares,
    );
    let v = restored.verify_audit(&DOMAIN).await.unwrap();
    assert!(
        matches!(v.status, AuditStatus::Truncated { .. }),
        "{:?}",
        v.status
    );
    restored.check_audit().await.unwrap();
    assert!(matches!(
        restored.read_fact(WHO, &DOMAIN, &f).await,
        Err(VaultError::Unavailable(_))
    ));

    restored
        .acknowledge_audit_rollback(
            &pvlt_core::audit_log::Caller::from("admin"),
            &DOMAIN,
            &POLICY,
        )
        .await
        .unwrap();
    assert!(restored.read_fact(WHO, &DOMAIN, &f).await.is_ok());
    assert_eq!(
        restored.verify_audit(&DOMAIN).await.unwrap().status,
        AuditStatus::Ok
    );
    backup.finish().await;
    r.db.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn queries_use_the_indexes_the_columns_describe_and_agree_with_the_entries() {
    let r = rig().await;
    let a = create(&r.engine, "alice", "a").await;
    let b = create(&r.engine, "bob", "b").await;
    r.engine.read_fact("svc/one", &DOMAIN, &a).await.unwrap();
    r.engine.read_fact("svc/two", &DOMAIN, &a).await.unwrap();
    r.engine.read_fact("svc/two", &DOMAIN, &b).await.unwrap();
    let alice = r.engine.subject_hmac(&DOMAIN, "alice").await.unwrap();
    let q = |mut f: AuditFilter| {
        if f.limit == 0 {
            f.limit = 100;
        }
        let e = &r.engine;
        async move { e.audit_query(&DOMAIN, &f).await.unwrap() }
    };
    assert_eq!(
        q(AuditFilter {
            subject_hmac: Some(alice),
            ..AuditFilter::default()
        })
        .await
        .len(),
        3
    );
    assert_eq!(
        q(AuditFilter {
            principal: Some("svc/two".into()),
            ..AuditFilter::default()
        })
        .await
        .len(),
        2
    );
    assert_eq!(
        q(AuditFilter {
            fact_id: Some(b),
            kind: Some("read.grant".into()),
            ..AuditFilter::default()
        })
        .await
        .len(),
        1
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
    let page = q(AuditFilter {
        limit: 2,
        ..AuditFilter::default()
    })
    .await;
    let rest = q(AuditFilter {
        after_seq: Some(page[1].seq),
        ..AuditFilter::default()
    })
    .await;
    assert_eq!((page.len(), rest.len()), (2, 3));
    r.db.finish().await;
}
