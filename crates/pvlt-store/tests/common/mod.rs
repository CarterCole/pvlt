//! Shared setup for the Postgres tests: a fresh database per test, and fixtures built with the real key
//! hierarchy so every stored blob is a genuine wrapped key.

#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::future::Future;
use std::str::FromStr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

use pvlt_core::keys::{Dek, DomainKeys, KeyMaterial, RootKey, SubjectKey, WrappedDomainKeys};
use pvlt_core::store::{FactId, KeyStore, NewFact, NewSubjectKey};
use pvlt_format::Id;
use pvlt_mem::{Arena, LockPolicy};
use pvlt_store::PgStore;
use sqlx::PgPool;
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};
use uuid::Uuid;

static COUNTER: AtomicU32 = AtomicU32::new(0);

pub fn arena() -> Arena {
    Arena::new(256, LockPolicy::BestEffort).unwrap()
}

/// Fails a test that hangs, which for these tests would mean a deadlock.
pub async fn within<T>(fut: impl Future<Output = T>) -> T {
    tokio::time::timeout(Duration::from_secs(120), fut)
        .await
        .expect("timed out: deadlock?")
}

/// Runs a statement that must fail with a database error and returns its SQLSTATE and constraint name. A syntax
/// error or a wrong column would make the statement fail for the wrong reason, so callers check the code.
pub async fn refused_with(pool: &PgPool, sql: &'static str) -> (String, Option<String>) {
    match sqlx::query(sql).execute(pool).await {
        Err(sqlx::Error::Database(db)) => (
            db.code().map(|c| c.to_string()).unwrap_or_default(),
            db.constraint().map(str::to_owned),
        ),
        other => panic!("expected a database error for `{sql}`, got {other:?}"),
    }
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// A database made for one test and dropped by `finish`.
pub struct TestDb {
    pub store: PgStore,
    admin: PgPool,
    name: String,
}

impl TestDb {
    pub async fn new() -> TestDb {
        let url = std::env::var("PVLT_TEST_DATABASE_URL")
            .expect("set PVLT_TEST_DATABASE_URL (scripts/test-db.sh)");
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let name = format!(
            "pvlt_t_{}_{}_{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
            .execute(&admin)
            .await
            .unwrap();
        let options = PgConnectOptions::from_str(&url).unwrap().database(&name);
        let pool = PgPoolOptions::new()
            .max_connections(24)
            .connect_with(options)
            .await
            .unwrap();
        let store = PgStore::from_pool(pool);
        store.migrate().await.unwrap();
        TestDb { store, admin, name }
    }

    pub fn pool(&self) -> &PgPool {
        self.store.pool()
    }

    /// A copy of this database as it is now, standing in for a restored backup. Other connections to the
    /// source are closed first, because Postgres cannot copy a database that is in use; the source's pool
    /// opens new ones on its next query.
    pub async fn snapshot(&self) -> TestDb {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let name = format!(
            "pvlt_t_{}_{}_{nanos}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "SELECT pg_terminate_backend(pid) FROM pg_stat_activity \
             WHERE datname = '{}' AND pid <> pg_backend_pid()",
            self.name
        )))
        .execute(&self.admin)
        .await
        .unwrap();
        // A pooled connection may be mid-reconnect; retry until the copy goes through.
        let mut tries = 0;
        loop {
            let made = sqlx::query(sqlx::AssertSqlSafe(format!(
                "CREATE DATABASE \"{name}\" TEMPLATE \"{}\"",
                self.name
            )))
            .execute(&self.admin)
            .await;
            match made {
                Ok(_) => break,
                Err(e) if tries < 20 => {
                    tries += 1;
                    let _ = e;
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(e) => panic!("cannot snapshot: {e}"),
            }
        }
        let url = std::env::var("PVLT_TEST_DATABASE_URL").unwrap();
        let options = PgConnectOptions::from_str(&url).unwrap().database(&name);
        let pool = PgPoolOptions::new()
            .max_connections(24)
            .connect_with(options)
            .await
            .unwrap();
        TestDb {
            store: PgStore::from_pool(pool),
            admin: self.admin.clone(),
            name,
        }
    }

    pub async fn finish(self) {
        self.store.pool().close().await;
        sqlx::query(sqlx::AssertSqlSafe(format!(
            "DROP DATABASE IF EXISTS \"{}\" WITH (FORCE)",
            self.name
        )))
        .execute(&self.admin)
        .await
        .ok();
    }

    /// Every row of every table as text, for searching.
    pub async fn dump(&self) -> String {
        let tables: Vec<String> = sqlx::query_scalar(
            "SELECT table_name::text FROM information_schema.tables \
             WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1",
        )
        .fetch_all(self.pool())
        .await
        .unwrap();
        let mut out = String::new();
        for t in tables {
            let rows: Vec<String> = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
                "SELECT x::text FROM \"{t}\" x"
            )))
            .fetch_all(self.pool())
            .await
            .unwrap();
            out.push_str(&format!("-- {t}\n{}\n", rows.join("\n")));
        }
        out
    }
}

/// A root key and arena, for building real wrapped keys.
pub struct World {
    pub db: TestDb,
    pub arena: Arena,
    pub root: RootKey,
}

pub struct Seed {
    pub domain_id: Id,
    pub domain: DomainKeys,
    pub wrapped: WrappedDomainKeys,
}

pub struct Person {
    pub hmac: [u8; 32],
    pub key: SubjectKey,
    pub record: NewSubjectKey,
}

impl World {
    pub async fn new() -> World {
        let arena = arena();
        let root = RootKey::generate(&arena).unwrap();
        World {
            db: TestDb::new().await,
            arena,
            root,
        }
    }

    pub fn store(&self) -> &PgStore {
        &self.db.store
    }

    /// Makes a domain with real keys and stores it.
    pub async fn domain(&self, n: u8) -> Seed {
        let domain_id = [n; 16];
        let (domain, wrapped) = DomainKeys::create(&self.arena, &self.root, &domain_id).unwrap();
        self.store()
            .create_domain(&domain_id, &wrapped)
            .await
            .unwrap();
        Seed {
            domain_id,
            domain,
            wrapped,
        }
    }

    /// Makes a subject key and stores it.
    pub async fn person(&self, seed: &Seed, name: &str) -> Person {
        let p = person(seed, name);
        let stored = self
            .store()
            .get_or_insert_subject_key(&p.record)
            .await
            .unwrap();
        assert_eq!(
            stored.key, p.record.key,
            "a brand new subject must get the key just made"
        );
        p
    }

    pub async fn finish(self) {
        self.db.finish().await;
    }
}

/// A subject and key, not yet stored.
pub fn person(seed: &Seed, name: &str) -> Person {
    let hmac = seed.domain.subject_hmac(name).unwrap();
    let (key, wrapped) = seed.domain.new_subject_key(&hmac, 1).unwrap();
    let record = NewSubjectKey {
        domain_id: seed.domain_id,
        subject_hmac: hmac,
        bik_version: seed.domain.bik_version(),
        key: wrapped,
    };
    Person { hmac, key, record }
}

/// A fact for `person`, numbered `n`. Its fact id and object id both come from `n`.
pub fn fact(seed: &Seed, p: &Person, n: u32) -> (NewFact, Dek) {
    let mut object_id = [0u8; 16];
    object_id[..4].copy_from_slice(&n.to_be_bytes());
    object_id[15] = 0xEE;
    let (dek, wrapped) = p.key.new_dek(&object_id, 0).unwrap();
    let fact = NewFact {
        domain_id: seed.domain_id,
        fact_id: fact_id(n),
        subject_hmac: p.hmac,
        bik_version: seed.domain.bik_version(),
        scope_hmac: seed.domain.scope_hmac(&format!("scope:{n}")).unwrap(),
        fact_type: "ascii".to_owned(),
        object_id,
        size_class: 256,
        dek: wrapped,
        expires_at: None,
        legal_hold: false,
    };
    (fact, dek)
}

pub fn fact_id(n: u32) -> FactId {
    Uuid::from_u128(u128::from(n) + 1)
}

pub fn root_hex(w: &World) -> String {
    hex(w.root.expose())
}
