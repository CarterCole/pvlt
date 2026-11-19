//! `pvlt backup`, `restore` and `scrub-backup` against real databases.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::path::PathBuf;
use std::str::FromStr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use pvlt_core::VaultError;
use pvlt_core::audit::NullAuditor;
use pvlt_core::engine::{CreateFact, Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::ledger::Reason;
use pvlt_core::memory::MemObjectStore;
use pvlt_core::objects::{ObjectError, ObjectInfo, ObjectStore};
use pvlt_core::seal::{SealConfig, UnsealShare, init_shamir, unseal_with_shares};
use pvlt_core::store::{FactId, KeyStore, State};
use pvlt_mem::{Arena, LockPolicy};
use pvlt_server::pg::PgStore;
use pvlt_server::{backup, tools};
use sqlx::postgres::{PgConnectOptions, PgPoolOptions};

const SECRET: &str = "Quentin-Q.-Nightingale-1987-03-09";
const DOMAIN: [u8; 16] = [7; 16];
const WHO: &str = "tester";
static COUNTER: AtomicU32 = AtomicU32::new(0);

/// A bucket two engines can share, standing in for the ledger bucket that is never rolled back.
#[derive(Clone, Default)]
struct Shared(Arc<MemObjectStore>);

impl ObjectStore for Shared {
    async fn ping(&self) -> Result<(), ObjectError> {
        self.0.ping().await
    }
    async fn put_path(&self, p: &str, b: Vec<u8>) -> Result<(), ObjectError> {
        self.0.put_path(p, b).await
    }
    async fn get_path(&self, p: &str) -> Result<Option<Vec<u8>>, ObjectError> {
        self.0.get_path(p).await
    }
    async fn delete_path(&self, p: &str) -> Result<(), ObjectError> {
        self.0.delete_path(p).await
    }
    async fn list_prefix(&self, p: &str) -> Result<Vec<(String, ObjectInfo)>, ObjectError> {
        self.0.list_prefix(p).await
    }
}

struct Dbs {
    admin: sqlx::PgPool,
    url: String,
    made: Vec<String>,
}

impl Dbs {
    async fn new() -> Self {
        let url = std::env::var("PVLT_TEST_DATABASE_URL").expect("set PVLT_TEST_DATABASE_URL");
        let admin = PgPoolOptions::new()
            .max_connections(2)
            .connect(&url)
            .await
            .unwrap();
        Self {
            admin,
            url,
            made: Vec::new(),
        }
    }

    async fn fresh(&mut self) -> PgStore {
        let name = format!(
            "pvlt_b_{}_{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        );
        sqlx::query(sqlx::AssertSqlSafe(format!("CREATE DATABASE \"{name}\"")))
            .execute(&self.admin)
            .await
            .unwrap();
        self.made.push(name.clone());
        let opts = PgConnectOptions::from_str(&self.url)
            .unwrap()
            .database(&name);
        let store = PgStore::from_pool(
            PgPoolOptions::new()
                .max_connections(8)
                .connect_with(opts)
                .await
                .unwrap(),
        );
        store.migrate().await.unwrap();
        store
    }

    async fn finish(self) {
        for name in &self.made {
            let _ = sqlx::query(sqlx::AssertSqlSafe(format!(
                "DROP DATABASE IF EXISTS \"{name}\" WITH (FORCE)"
            )))
            .execute(&self.admin)
            .await;
        }
    }
}

type PgEngine = Engine<PgStore, Shared, NullAuditor>;

struct Vault {
    store: PgStore,
    engine: PgEngine,
    config: SealConfig,
    shares: Vec<UnsealShare>,
}

fn engine_over(
    store: PgStore,
    bucket: Shared,
    config: &SealConfig,
    shares: &[UnsealShare],
) -> PgEngine {
    let ring = Keyring::new(Arena::new(256, LockPolicy::BestEffort).unwrap());
    ring.unseal(unseal_with_shares(ring.arena(), config, &shares[..2]).unwrap());
    Engine::new(ring, store, bucket, NullAuditor, Limits::default())
}

async fn vault(dbs: &mut Dbs) -> Vault {
    let store = dbs.fresh().await;
    let init = init_shamir(&Arena::new(256, LockPolicy::BestEffort).unwrap(), 2, 3).unwrap();
    store.init_seal_config(&init.config).await.unwrap();
    let engine = engine_over(store.clone(), Shared::default(), &init.config, &init.shares);
    engine.ensure_domain(&DOMAIN).await.unwrap();
    Vault {
        store,
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

struct Files(PathBuf);

impl Files {
    fn new() -> Self {
        let dir = std::env::temp_dir().join(format!(
            "pvlt-backup-test-{}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::SeqCst)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn identity(files: &Files, name: &str) -> (PathBuf, String) {
    let (secret, recipient) = backup::generate_identity();
    let path = files.path(name);
    std::fs::write(&path, secret.as_str()).unwrap();
    (path, recipient)
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_backup_file_is_encrypted_private_and_never_overwritten() {
    let mut dbs = Dbs::new().await;
    let v = vault(&mut dbs).await;
    create(&v.engine, "alice", "kyc", SECRET).await;
    let files = Files::new();
    let (_, recipient) = identity(&files, "id");
    let out = files.path("backup.age");

    let rows = tools::backup_to_file(&v.store, &out, std::slice::from_ref(&recipient))
        .await
        .unwrap();
    assert!(rows > 0);
    let bytes = std::fs::read(&out).unwrap();
    for needle in ["pvlt-backup", "domains", "ledger", "alice", "Nightingale"] {
        assert!(
            !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "{needle} is visible"
        );
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&out).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // It will not overwrite a file that is there.
    assert!(
        tools::backup_to_file(&v.store, &out, &[recipient])
            .await
            .is_err()
    );
    // And it will not write one without a recipient the server can read.
    assert!(
        tools::backup_to_file(&v.store, &files.path("none.age"), &[])
            .await
            .is_err()
    );
    assert!(!files.path("none.age").exists());
    dbs.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn restoring_a_backup_replays_every_shred_made_since_before_anything_can_read_it() {
    let mut dbs = Dbs::new().await;
    let v = vault(&mut dbs).await;
    let alice = create(&v.engine, "alice", "kyc", SECRET).await;
    let bob = create(&v.engine, "bob", "tax", "bob-value").await;
    let carol = create(&v.engine, "carol", "misc", "carol-value").await;
    let files = Files::new();
    let (identity_file, recipient) = identity(&files, "id");
    let out = files.path("backup.age");
    tools::backup_to_file(&v.store, &out, &[recipient])
        .await
        .unwrap();

    v.engine
        .shred_subject(WHO, &DOMAIN, "alice", Reason::SubjectRequest)
        .await
        .unwrap();
    v.engine
        .shred_scope(WHO, &DOMAIN, "tax", Reason::Legal)
        .await
        .unwrap();
    assert_eq!(read(&v.engine, &alice).await, Err(VaultError::Shredded));

    // A new key store, and the same ledger bucket (the data bucket has the objects too: nothing was rolled back
    // there, which is the worst case for this test: the sealed values are all still present).
    let fresh = dbs.fresh().await;
    tools::must_be_empty(&fresh).await.unwrap();
    let bucket = v.engine.objects().clone();
    let restored = engine_over(
        fresh.clone(),
        Shared(Arc::clone(&bucket.0)),
        &v.config,
        &v.shares,
    );
    // The control: importing without the ledger brings the erased data back.
    let dump = backup::decode(
        &backup::decrypt(
            &std::fs::read(&out).unwrap(),
            &std::fs::read_to_string(&identity_file).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    fresh.import_all(&dump).await.unwrap();
    // (alice's and bob's sealed objects were deleted at shred time, so put the control copies back by reading
    // the key state instead: the wrapped keys are live again.)
    for f in [&alice, &bob] {
        let b = fresh.fact_for_read(&DOMAIN, f).await.unwrap();
        assert_eq!(
            b.fact.state,
            State::Active,
            "the control must show the problem"
        );
    }

    let other = dbs.fresh().await;
    let restored2 = engine_over(
        other.clone(),
        Shared(Arc::clone(&bucket.0)),
        &v.config,
        &v.shares,
    );
    let report = tools::restore_from_file(&other, &restored2, &out, &identity_file)
        .await
        .unwrap();
    assert_eq!(report.replayed, 2);
    for f in [&alice, &bob] {
        let b = other.fact_for_read(&DOMAIN, f).await.unwrap();
        assert_eq!(b.fact.state, State::Shredded);
        assert_eq!(read(&restored2, f).await, Err(VaultError::Shredded));
    }
    let _ = (restored, carol);
    // Restoring into a key store that has data is refused.
    assert!(tools::must_be_empty(&other).await.is_err());
    assert!(other.import_all(&dump).await.is_err());
    dbs.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_scrubbed_backup_already_has_the_later_shreds_applied() {
    let mut dbs = Dbs::new().await;
    let v = vault(&mut dbs).await;
    let alice = create(&v.engine, "alice", "kyc", SECRET).await;
    let keep = create(&v.engine, "carol", "misc", "carol-value").await;
    let files = Files::new();
    let (identity_file, recipient) = identity(&files, "id");
    let old = files.path("old.age");
    tools::backup_to_file(&v.store, &old, std::slice::from_ref(&recipient))
        .await
        .unwrap();
    v.engine
        .shred_subject(WHO, &DOMAIN, "alice", Reason::SubjectRequest)
        .await
        .unwrap();

    let scratch = dbs.fresh().await;
    let scratch_engine = engine_over(
        scratch.clone(),
        Shared(Arc::clone(&v.engine.objects().0)),
        &v.config,
        &v.shares,
    );
    let scrubbed = files.path("scrubbed.age");
    let report = tools::scrub_backup(
        &scratch,
        &scratch_engine,
        &old,
        &identity_file,
        &scrubbed,
        &[recipient],
    )
    .await
    .unwrap();
    assert_eq!(report.replayed, 1);

    // Load the scrubbed file with no ledger replay at all: alice is already gone, carol is not.
    let plain = backup::decode(
        &backup::decrypt(
            &std::fs::read(&scrubbed).unwrap(),
            &std::fs::read_to_string(&identity_file).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let target = dbs.fresh().await;
    target.import_all(&plain).await.unwrap();
    assert_eq!(
        target
            .fact_for_read(&DOMAIN, &alice)
            .await
            .unwrap()
            .fact
            .state,
        State::Shredded
    );
    assert_eq!(
        target
            .fact_for_read(&DOMAIN, &alice)
            .await
            .unwrap()
            .subject_key
            .state,
        State::Shredded
    );
    assert_eq!(
        target
            .fact_for_read(&DOMAIN, &keep)
            .await
            .unwrap()
            .fact
            .state,
        State::Active
    );
    // The old backup, by contrast, still has alice's key.
    let old_plain = backup::decode(
        &backup::decrypt(
            &std::fs::read(&old).unwrap(),
            &std::fs::read_to_string(&identity_file).unwrap(),
        )
        .unwrap(),
    )
    .unwrap();
    let old_target = dbs.fresh().await;
    old_target.import_all(&old_plain).await.unwrap();
    assert_eq!(
        old_target
            .fact_for_read(&DOMAIN, &alice)
            .await
            .unwrap()
            .fact
            .state,
        State::Active
    );
    dbs.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_wrong_identity_or_a_damaged_file_restores_nothing() {
    let mut dbs = Dbs::new().await;
    let v = vault(&mut dbs).await;
    create(&v.engine, "alice", "kyc", "v").await;
    let files = Files::new();
    let (good, recipient) = identity(&files, "good");
    let (wrong, _) = identity(&files, "wrong");
    let out = files.path("b.age");
    tools::backup_to_file(&v.store, &out, &[recipient])
        .await
        .unwrap();

    let target = dbs.fresh().await;
    let engine = engine_over(target.clone(), Shared::default(), &v.config, &v.shares);
    assert!(
        tools::restore_from_file(&target, &engine, &out, &wrong)
            .await
            .is_err()
    );
    let mut bytes = std::fs::read(&out).unwrap();
    let n = bytes.len();
    bytes[n / 2] ^= 1;
    let damaged = files.path("damaged.age");
    std::fs::write(&damaged, &bytes).unwrap();
    assert!(
        tools::restore_from_file(&target, &engine, &damaged, &good)
            .await
            .is_err()
    );
    // Nothing was loaded by either attempt.
    assert!(tools::must_be_empty(&target).await.is_ok());
    assert!(target.list_domains().await.unwrap().is_empty());
    dbs.finish().await;
}
