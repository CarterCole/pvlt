//! The shred ledger: a shred is signed, chained, published, and survives restoring an older key store.
//!
//! Each restore test first shows that, without replay, a restored backup brings the erased value back. That is
//! the failure the ledger exists to prevent, and it keeps these tests from passing vacuously.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::{arena, id};
use pvlt_core::VaultError;
use pvlt_core::audit::NullAuditor;
use pvlt_core::engine::{CreateFact, Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::ledger::{self, Reason};
use pvlt_core::memory::{MemKeyStore, MemObjectStore};
use pvlt_core::objects::{ObjectError, ObjectInfo, ObjectKey, ObjectStore};
use pvlt_core::seal::{SealConfig, UnsealShare, init_shamir, unseal_with_shares};
use pvlt_core::store::{FactId, KeyStore, ShredFact, ShredSubject};
use time::OffsetDateTime;

const SECRET: &str = "Quentin-Q.-Nightingale-1987-03-09";
const WHO: &str = "tester";

/// A bucket whose ledger writes can be made to fail.
struct Flaky {
    inner: MemObjectStore,
    fail_ledger: AtomicBool,
}

impl Flaky {
    fn new(inner: MemObjectStore) -> Self {
        Self {
            inner,
            fail_ledger: AtomicBool::new(false),
        }
    }
}

impl ObjectStore for Flaky {
    async fn ping(&self) -> Result<(), ObjectError> {
        self.inner.ping().await
    }
    async fn put_path(&self, path: &str, bytes: Vec<u8>) -> Result<(), ObjectError> {
        if path.starts_with("ledger/") && self.fail_ledger.load(Ordering::SeqCst) {
            return Err(ObjectError("the ledger bucket is down".into()));
        }
        self.inner.put_path(path, bytes).await
    }
    async fn get_path(&self, path: &str) -> Result<Option<Vec<u8>>, ObjectError> {
        self.inner.get_path(path).await
    }
    async fn delete_path(&self, path: &str) -> Result<(), ObjectError> {
        self.inner.delete_path(path).await
    }
    async fn list_prefix(&self, prefix: &str) -> Result<Vec<(String, ObjectInfo)>, ObjectError> {
        self.inner.list_prefix(prefix).await
    }
}

type TestEngine = Engine<MemKeyStore, Flaky, NullAuditor>;

struct Rig {
    engine: TestEngine,
    config: SealConfig,
    shares: Vec<UnsealShare>,
}

fn domain() -> [u8; 16] {
    id(7)
}

fn build(
    keys: MemKeyStore,
    objects: MemObjectStore,
    config: &SealConfig,
    shares: &[UnsealShare],
    unsealed: bool,
) -> TestEngine {
    let a = arena();
    let ring = Keyring::new(a);
    if unsealed {
        let root = unseal_with_shares(ring.arena(), config, &shares[..2]).unwrap();
        ring.unseal(root);
    }
    Engine::new(
        ring,
        keys,
        Flaky::new(objects),
        NullAuditor,
        Limits::default(),
    )
}

async fn rig() -> Rig {
    let a = arena();
    let init = init_shamir(&a, 2, 3).unwrap();
    let engine = build(
        MemKeyStore::new(),
        MemObjectStore::new(),
        &init.config,
        &init.shares,
        false,
    );
    // The init root is already unsealed: hand it to this engine.
    engine.keyring().unseal(init.root);
    engine.ensure_domain(&domain()).await.unwrap();
    Rig {
        engine,
        config: init.config,
        shares: init.shares,
    }
}

impl Rig {
    /// What a backup of the key store and the data bucket looks like right now.
    fn backup(&self) -> (MemKeyStore, MemObjectStore) {
        (
            self.engine.store().snapshot(),
            self.engine.objects().inner.snapshot(),
        )
    }

    /// A server restored from `backup` but pointed at the **current** ledger bucket, which is never rolled back.
    async fn restored(&self, backup: (MemKeyStore, MemObjectStore), unsealed: bool) -> TestEngine {
        let (keys, data) = backup;
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
        build(keys, data, &self.config, &self.shares, unsealed)
    }
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

async fn create(e: &TestEngine, subject: Option<&str>, scope: &str, value: &str) -> FactId {
    e.create_fact(WHO, &domain(), &fact(subject, scope, value))
        .await
        .unwrap()
}

async fn read(e: &TestEngine, f: &FactId) -> Result<String, VaultError> {
    e.read_fact(WHO, &domain(), f)
        .await
        .map(|v| String::from_utf8(v.value.to_vec()).unwrap())
}

async fn ledger_files(e: &TestEngine) -> Vec<String> {
    let mut v: Vec<String> = e
        .objects()
        .list_prefix(&ledger::prefix_for(&domain()))
        .await
        .unwrap()
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    v.sort();
    v
}

#[tokio::test]
async fn a_shred_writes_one_signed_entry_to_the_bucket_and_one_to_the_key_store() {
    let r = rig().await;
    let f = create(&r.engine, Some("alice"), "kyc", SECRET).await;
    assert!(ledger_files(&r.engine).await.is_empty());

    r.engine
        .shred_fact(WHO, &domain(), &f, Reason::SubjectRequest)
        .await
        .unwrap();
    let files = ledger_files(&r.engine).await;
    assert_eq!(files, [ledger::path_for(&domain(), 0)]);

    let public = r
        .engine
        .store()
        .sign_key(&domain(), pvlt_format::wrap::SignPurpose::Ledger)
        .await
        .unwrap()
        .unwrap()
        .public_key;
    let line = r
        .engine
        .objects()
        .get_path(&files[0])
        .await
        .unwrap()
        .unwrap();
    let (entry, hash, _) = ledger::verify_line(&domain(), &public, &line).unwrap();
    assert_eq!(entry.seq, 0);
    assert_eq!(entry.prev, ledger::GENESIS);
    assert_eq!(entry.reason, Reason::SubjectRequest);
    let head = r
        .engine
        .store()
        .ledger_head(&domain())
        .await
        .unwrap()
        .unwrap();
    assert_eq!((head.seq, head.hash), (0, hash));
    let rec = r.engine.store().ledger_records(&domain(), 0).await.unwrap();
    assert!(rec[0].published);
    assert_eq!(rec[0].line, line);

    // A second shred of the same fact writes nothing.
    assert_eq!(
        r.engine
            .shred_fact(WHO, &domain(), &f, Reason::Admin)
            .await
            .unwrap(),
        ShredFact::AlreadyShredded
    );
    assert_eq!(ledger_files(&r.engine).await.len(), 1);
    // Nor does shredding one that never existed.
    let nobody = uuid::Uuid::from_bytes([1; 16]);
    assert_eq!(
        r.engine
            .shred_fact(WHO, &domain(), &nobody, Reason::Admin)
            .await
            .unwrap(),
        ShredFact::NotFound
    );
    assert_eq!(ledger_files(&r.engine).await.len(), 1);
}

#[tokio::test]
async fn the_ledger_holds_no_value_subject_scope_or_free_text() {
    let r = rig().await;
    let f = create(
        &r.engine,
        Some("alice@example.com"),
        "scope-of-alice",
        SECRET,
    )
    .await;
    create(
        &r.engine,
        Some("alice@example.com"),
        "scope-of-alice",
        "second",
    )
    .await;
    r.engine
        .shred_fact(WHO, &domain(), &f, Reason::SubjectRequest)
        .await
        .unwrap();
    r.engine
        .shred_scope(WHO, &domain(), "scope-of-alice", Reason::Legal)
        .await
        .unwrap();
    r.engine
        .shred_subject(WHO, &domain(), "alice@example.com", Reason::Admin)
        .await
        .unwrap();
    let mut all = Vec::new();
    for path in ledger_files(&r.engine).await {
        all.extend(r.engine.objects().get_path(&path).await.unwrap().unwrap());
    }
    assert!(!all.is_empty());
    for needle in [
        SECRET,
        "Nightingale",
        "alice",
        "example.com",
        "scope-of-alice",
    ] {
        assert!(
            !all.windows(needle.len()).any(|w| w == needle.as_bytes()),
            "the ledger holds {needle}"
        );
    }
}

#[tokio::test]
async fn without_replay_a_restored_backup_brings_a_shredded_fact_back_and_with_replay_it_does_not()
{
    let r = rig().await;
    let f = create(&r.engine, Some("alice"), "kyc", SECRET).await;
    let backup = r.backup();
    r.engine
        .shred_fact(WHO, &domain(), &f, Reason::SubjectRequest)
        .await
        .unwrap();
    assert_eq!(read(&r.engine, &f).await, Err(VaultError::Shredded));

    let restored = r.restored(backup, true).await;
    // The control: the restored system, before replay, still reads the erased value.
    assert_eq!(
        read(&restored, &f).await.unwrap(),
        SECRET,
        "the control must show the problem"
    );

    let report = restored.reconcile().await.unwrap();
    assert_eq!((report.replayed, report.republished), (1, 0));
    assert_eq!(read(&restored, &f).await, Err(VaultError::Shredded));
    // Replaying again is a no-op.
    assert_eq!(restored.reconcile().await.unwrap().replayed, 0);
}

#[tokio::test]
async fn replay_works_while_the_vault_is_sealed() {
    let r = rig().await;
    let f = create(&r.engine, Some("alice"), "kyc", SECRET).await;
    let backup = r.backup();
    r.engine
        .shred_fact(WHO, &domain(), &f, Reason::Admin)
        .await
        .unwrap();
    let restored = r.restored(backup, false).await;
    assert_eq!(restored.reconcile().await.unwrap().replayed, 1);
    restored
        .keyring()
        .unseal(unseal_with_shares(restored.keyring().arena(), &r.config, &r.shares[1..]).unwrap());
    assert_eq!(read(&restored, &f).await, Err(VaultError::Shredded));
}

#[tokio::test]
async fn a_restored_backup_is_re_shredded_for_a_subject_a_scope_and_an_expiry() {
    let r = rig().await;
    let alice1 = create(&r.engine, Some("alice"), "kyc", "a1").await;
    let alice2 = create(&r.engine, Some("alice"), "other", "a2").await;
    let bob = create(&r.engine, Some("bob"), "tax", "b1").await;
    let carol = create(&r.engine, Some("carol"), "tax", "c1").await;
    let dave = create(&r.engine, Some("dave"), "misc", "d1").await;
    let expiring = r
        .engine
        .create_fact(
            WHO,
            &domain(),
            &CreateFact {
                expires_at: Some(OffsetDateTime::now_utc() + time::Duration::milliseconds(50)),
                ..fact(Some("erin"), "misc", "e1")
            },
        )
        .await
        .unwrap();
    let backup = r.backup();

    assert_eq!(
        r.engine
            .shred_subject(WHO, &domain(), "alice", Reason::SubjectRequest)
            .await
            .unwrap(),
        ShredSubject::Shredded
    );
    assert_eq!(
        r.engine
            .shred_scope(WHO, &domain(), "tax", Reason::Legal)
            .await
            .unwrap(),
        2
    );
    tokio::time::sleep(std::time::Duration::from_millis(80)).await;
    assert_eq!(
        r.engine.sweep_expired(WHO, &domain(), 100).await.unwrap(),
        1
    );
    assert_eq!(read(&r.engine, &dave).await.unwrap(), "d1");

    let restored = r.restored(backup, true).await;
    for f in [&alice1, &alice2, &bob, &carol] {
        assert!(
            read(&restored, f).await.is_ok(),
            "the control must show the problem"
        );
    }
    // The expiring fact is past its time in the restored copy too, so a read already refuses it.
    assert_eq!(read(&restored, &expiring).await, Err(VaultError::NotFound));

    assert_eq!(restored.reconcile().await.unwrap().replayed, 3);
    assert_eq!(read(&restored, &alice1).await, Err(VaultError::Shredded));
    assert_eq!(read(&restored, &alice2).await, Err(VaultError::Shredded));
    assert_eq!(read(&restored, &bob).await, Err(VaultError::Shredded));
    assert_eq!(read(&restored, &carol).await, Err(VaultError::Shredded));
    assert_eq!(read(&restored, &expiring).await, Err(VaultError::Shredded));
    // What was never shredded is untouched.
    assert_eq!(read(&restored, &dave).await.unwrap(), "d1");
}

#[tokio::test]
async fn a_scope_shred_after_a_rebind_still_destroys_a_fact_filed_elsewhere_in_the_backup() {
    let r = rig().await;
    let f = create(&r.engine, Some("alice"), "draft", SECRET).await;
    let backup = r.backup(); // here the fact is in scope "draft"
    r.engine
        .rebind_scope(WHO, &domain(), &f, "approved")
        .await
        .unwrap();
    assert_eq!(
        r.engine
            .shred_scope(WHO, &domain(), "draft", Reason::Admin)
            .await
            .unwrap(),
        0
    );
    assert_eq!(
        read(&r.engine, &f).await.unwrap(),
        SECRET,
        "the old scope no longer holds it"
    );
    assert_eq!(
        r.engine
            .shred_scope(WHO, &domain(), "approved", Reason::Admin)
            .await
            .unwrap(),
        1
    );

    // The entry names the object, so the backup's old filing does not matter.
    let restored = r.restored(backup, true).await;
    restored.reconcile().await.unwrap();
    assert_eq!(read(&restored, &f).await, Err(VaultError::Shredded));
}

#[tokio::test]
async fn a_subject_shredded_after_the_backup_cannot_be_reopened_in_the_restored_system() {
    let r = rig().await;
    create(&r.engine, Some("zed"), "kyc", "z1").await;
    let backup = r.backup();
    // Created after the backup, so the restored key store has never heard of this subject.
    let later = create(&r.engine, Some("newcomer"), "kyc", "n1").await;
    r.engine
        .shred_subject(WHO, &domain(), "newcomer", Reason::SubjectRequest)
        .await
        .unwrap();
    assert_eq!(read(&r.engine, &later).await, Err(VaultError::Shredded));

    let restored = r.restored(backup, true).await;
    restored.reconcile().await.unwrap();
    let again = restored
        .create_fact(WHO, &domain(), &fact(Some("newcomer"), "kyc", "again"))
        .await;
    assert_eq!(
        again,
        Err(VaultError::Shredded),
        "a tombstone must stop a later write"
    );
}

#[tokio::test]
async fn a_shredded_domain_stays_shredded_after_a_restore() {
    let r = rig().await;
    let f = create(&r.engine, Some("alice"), "kyc", SECRET).await;
    let backup = r.backup();
    assert!(
        r.engine
            .shred_domain(WHO, &domain(), Reason::Admin)
            .await
            .unwrap()
    );
    assert_eq!(read(&r.engine, &f).await, Err(VaultError::Shredded));
    assert!(
        !r.engine
            .shred_domain(WHO, &domain(), Reason::Admin)
            .await
            .unwrap()
    );

    let restored = r.restored(backup, true).await;
    assert_eq!(
        read(&restored, &f).await.unwrap(),
        SECRET,
        "the control must show the problem"
    );
    restored.reconcile().await.unwrap();
    assert_eq!(read(&restored, &f).await, Err(VaultError::Shredded));
    assert_eq!(
        restored
            .create_fact(WHO, &domain(), &fact(Some("x"), "s", "v"))
            .await,
        Err(VaultError::Shredded)
    );
}

#[tokio::test]
async fn a_shred_whose_bucket_write_failed_is_applied_reported_and_published_later() {
    let r = rig().await;
    let f = create(&r.engine, Some("alice"), "kyc", SECRET).await;
    r.engine.objects().fail_ledger.store(true, Ordering::SeqCst);

    let got = r.engine.shred_fact(WHO, &domain(), &f, Reason::Admin).await;
    assert!(matches!(got, Err(VaultError::Unavailable(_))), "{got:?}");
    // The shred itself is durable in the key store...
    assert_eq!(read(&r.engine, &f).await, Err(VaultError::Shredded));
    let rec = r.engine.store().ledger_records(&domain(), 0).await.unwrap();
    assert_eq!(rec.len(), 1);
    assert!(!rec[0].published);
    // ...and the bucket does not have it yet, so readiness says the ledger is out of step.
    assert!(ledger_files(&r.engine).await.is_empty());
    assert!(!r.engine.ledger_in_sync().await.unwrap());

    r.engine
        .objects()
        .fail_ledger
        .store(false, Ordering::SeqCst);
    let report = r.engine.reconcile().await.unwrap();
    assert_eq!(report.republished, 1);
    assert_eq!(ledger_files(&r.engine).await.len(), 1);
    assert!(r.engine.ledger_in_sync().await.unwrap());
}

#[tokio::test]
async fn an_earlier_unpublished_entry_goes_out_before_the_next_shred() {
    let r = rig().await;
    let a = create(&r.engine, Some("alice"), "kyc", "a").await;
    let b = create(&r.engine, Some("bob"), "kyc", "b").await;
    r.engine.objects().fail_ledger.store(true, Ordering::SeqCst);
    assert!(
        r.engine
            .shred_fact(WHO, &domain(), &a, Reason::Admin)
            .await
            .is_err()
    );
    r.engine
        .objects()
        .fail_ledger
        .store(false, Ordering::SeqCst);

    r.engine
        .shred_fact(WHO, &domain(), &b, Reason::Admin)
        .await
        .unwrap();
    assert_eq!(
        ledger_files(&r.engine).await.len(),
        2,
        "the bucket must stay a prefix of the ledger"
    );
    assert!(r.engine.ledger_in_sync().await.unwrap());
}

#[tokio::test]
async fn a_tampered_ledger_in_the_bucket_stops_startup() {
    let r = rig().await;
    for n in 0..3 {
        let f = create(&r.engine, Some("alice"), "kyc", &format!("v{n}")).await;
        r.engine
            .shred_fact(WHO, &domain(), &f, Reason::Admin)
            .await
            .unwrap();
    }
    assert_eq!(r.engine.reconcile().await.unwrap().replayed, 0);
    let files = ledger_files(&r.engine).await;
    assert_eq!(files.len(), 3);

    // A flipped byte.
    let line = r
        .engine
        .objects()
        .get_path(&files[1])
        .await
        .unwrap()
        .unwrap();
    for at in [5, line.len() / 2, line.len() - 3] {
        let mut bad = line.clone();
        bad[at] ^= 1;
        r.engine.objects().put_path(&files[1], bad).await.unwrap();
        assert!(
            matches!(r.engine.reconcile().await, Err(VaultError::Integrity(_))),
            "a bit flip at {at} was accepted"
        );
    }
    r.engine
        .objects()
        .put_path(&files[1], line.clone())
        .await
        .unwrap();
    assert!(r.engine.reconcile().await.is_ok());

    // A missing middle entry.
    r.engine.objects().delete_path(&files[1]).await.unwrap();
    assert!(matches!(
        r.engine.reconcile().await,
        Err(VaultError::Integrity(_))
    ));
    r.engine
        .objects()
        .put_path(&files[1], line.clone())
        .await
        .unwrap();

    // Entries swapped between sequence numbers.
    let other = r
        .engine
        .objects()
        .get_path(&files[2])
        .await
        .unwrap()
        .unwrap();
    r.engine
        .objects()
        .put_path(&files[1], other.clone())
        .await
        .unwrap();
    r.engine
        .objects()
        .put_path(&files[2], line.clone())
        .await
        .unwrap();
    assert!(matches!(
        r.engine.reconcile().await,
        Err(VaultError::Integrity(_))
    ));
}

#[tokio::test]
async fn a_published_entry_that_vanishes_from_the_bucket_stops_startup() {
    let r = rig().await;
    let f = create(&r.engine, Some("alice"), "kyc", "v").await;
    r.engine
        .shred_fact(WHO, &domain(), &f, Reason::Admin)
        .await
        .unwrap();
    r.engine
        .objects()
        .delete_path(&ledger::path_for(&domain(), 0))
        .await
        .unwrap();
    assert!(matches!(
        r.engine.reconcile().await,
        Err(VaultError::Integrity(_))
    ));
    assert!(!r.engine.ledger_in_sync().await.unwrap());
}

#[tokio::test]
async fn a_forked_ledger_stops_startup() {
    // Two histories from one backup: the key store follows one, the bucket the other.
    let r = rig().await;
    let a = create(&r.engine, Some("alice"), "kyc", "a").await;
    let b = create(&r.engine, Some("bob"), "kyc", "b").await;
    let (keys_a, data_a) = r.backup();
    let (keys_b, data_b) = r.backup();

    let fork_a = r.restored((keys_a, data_a), true).await;
    fork_a
        .shred_fact(WHO, &domain(), &a, Reason::Admin)
        .await
        .unwrap();
    let fork_b = r.restored((keys_b, data_b), true).await;
    fork_b
        .shred_fact(WHO, &domain(), &b, Reason::Admin)
        .await
        .unwrap();

    // Key store from history A, ledger bucket from history B.
    let mixed = build(
        fork_a.store().snapshot(),
        fork_b.objects().inner.snapshot(),
        &r.config,
        &r.shares,
        true,
    );
    assert!(matches!(
        mixed.reconcile().await,
        Err(VaultError::Integrity(_))
    ));
}

#[tokio::test]
async fn a_ledger_line_signed_by_another_key_is_refused() {
    let r = rig().await;
    let f = create(&r.engine, Some("alice"), "kyc", "v").await;
    let backup = r.backup();
    r.engine
        .shred_fact(WHO, &domain(), &f, Reason::Admin)
        .await
        .unwrap();

    // Another vault's ledger for the same domain id, with the same shape but its own signing key.
    let other = rig().await;
    let g = create(&other.engine, Some("alice"), "kyc", "v").await;
    other
        .engine
        .shred_fact(WHO, &domain(), &g, Reason::Admin)
        .await
        .unwrap();
    let forged = other
        .engine
        .objects()
        .get_path(&ledger::path_for(&domain(), 0))
        .await
        .unwrap()
        .unwrap();

    let restored = r.restored(backup, true).await;
    restored
        .objects()
        .put_path(&ledger::path_for(&domain(), 0), forged)
        .await
        .unwrap();
    assert!(matches!(
        restored.reconcile().await,
        Err(VaultError::Integrity(_))
    ));
}

#[tokio::test]
async fn concurrent_shreds_leave_one_gapless_verified_chain() {
    let r = Arc::new(rig().await);
    let mut facts = Vec::new();
    for n in 0..24 {
        facts.push(create(&r.engine, Some(&format!("user-{n}")), "kyc", "v").await);
    }
    let mut tasks = Vec::new();
    for f in facts {
        let r = Arc::clone(&r);
        tasks.push(tokio::spawn(async move {
            r.engine
                .shred_fact(WHO, &domain(), &f, Reason::Admin)
                .await
                .unwrap()
        }));
    }
    for t in tasks {
        assert!(matches!(t.await.unwrap(), ShredFact::Shredded { .. }));
    }
    assert_eq!(ledger_files(&r.engine).await.len(), 24);
    assert!(r.engine.ledger_in_sync().await.unwrap());
    // reconcile verifies every signature and every link.
    assert_eq!(r.engine.reconcile().await.unwrap().replayed, 0);
    let head = r
        .engine
        .store()
        .ledger_head(&domain())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(head.seq, 23);
}

#[tokio::test]
async fn a_legal_hold_stops_a_shred_and_an_expiry_and_writes_nothing() {
    let r = rig().await;
    let past = OffsetDateTime::now_utc() - time::Duration::seconds(5);
    let held = r
        .engine
        .create_fact(
            WHO,
            &domain(),
            &CreateFact {
                expires_at: Some(past),
                ..fact(Some("alice"), "kyc", "held")
            },
        )
        .await
        .unwrap();
    r.engine
        .set_legal_hold(WHO, &domain(), &held, true)
        .await
        .unwrap();

    assert!(matches!(
        r.engine
            .shred_fact(WHO, &domain(), &held, Reason::Admin)
            .await,
        Err(VaultError::Conflict(_))
    ));
    assert!(matches!(
        r.engine
            .shred_subject(WHO, &domain(), "alice", Reason::Admin)
            .await,
        Err(VaultError::Conflict(_))
    ));
    assert!(matches!(
        r.engine
            .shred_scope(WHO, &domain(), "kyc", Reason::Admin)
            .await,
        Err(VaultError::Conflict(_))
    ));
    assert!(matches!(
        r.engine.shred_domain(WHO, &domain(), Reason::Admin).await,
        Err(VaultError::Conflict(_))
    ));
    assert_eq!(
        r.engine.sweep_expired(WHO, &domain(), 10).await.unwrap(),
        0,
        "a held fact is never due"
    );
    assert!(
        ledger_files(&r.engine).await.is_empty(),
        "a refused shred must not be in the ledger"
    );
    assert!(
        r.engine
            .store()
            .ledger_head(&domain())
            .await
            .unwrap()
            .is_none()
    );

    r.engine
        .set_legal_hold(WHO, &domain(), &held, false)
        .await
        .unwrap();
    assert_eq!(r.engine.sweep_expired(WHO, &domain(), 10).await.unwrap(), 1);
    assert_eq!(ledger_files(&r.engine).await.len(), 1);
}

#[tokio::test]
async fn the_expiry_sweeper_writes_an_expire_entry_in_batches() {
    let r = rig().await;
    let past = OffsetDateTime::now_utc() - time::Duration::seconds(5);
    for n in 0..5 {
        r.engine
            .create_fact(
                WHO,
                &domain(),
                &CreateFact {
                    expires_at: Some(past),
                    ..fact(Some(&format!("u{n}")), "s", "v")
                },
            )
            .await
            .unwrap();
    }
    let kept = create(&r.engine, Some("keeper"), "s", "keep").await;
    assert_eq!(r.engine.sweep_expired(WHO, &domain(), 3).await.unwrap(), 3);
    assert_eq!(r.engine.sweep_expired(WHO, &domain(), 3).await.unwrap(), 2);
    assert_eq!(r.engine.sweep_expired(WHO, &domain(), 3).await.unwrap(), 0);
    assert_eq!(read(&r.engine, &kept).await.unwrap(), "keep");
    let public = r
        .engine
        .store()
        .sign_key(&domain(), pvlt_format::wrap::SignPurpose::Ledger)
        .await
        .unwrap()
        .unwrap()
        .public_key;
    for path in ledger_files(&r.engine).await {
        let line = r.engine.objects().get_path(&path).await.unwrap().unwrap();
        let (entry, ..) = ledger::verify_line(&domain(), &public, &line).unwrap();
        assert_eq!(entry.reason, Reason::Retention);
        assert!(matches!(
            entry.effect,
            ledger::Effect::Facts { expire: true, .. }
        ));
    }
}

#[tokio::test]
async fn a_rebound_fact_is_found_under_its_new_scope_and_not_its_old_one() {
    let r = rig().await;
    let f = create(&r.engine, Some("alice"), "draft", "v").await;
    let g = create(&r.engine, Some("alice"), "draft", "w").await;
    r.engine
        .rebind_scope(WHO, &domain(), &f, "approved")
        .await
        .unwrap();
    assert_eq!(
        r.engine
            .shred_scope(WHO, &domain(), "draft", Reason::Admin)
            .await
            .unwrap(),
        1
    );
    assert_eq!(read(&r.engine, &g).await, Err(VaultError::Shredded));
    assert_eq!(read(&r.engine, &f).await.unwrap(), "v");
    assert_eq!(
        r.engine.rebind_scope(WHO, &domain(), &g, "x").await,
        Err(VaultError::Conflict("fact is shredded"))
    );
    assert_eq!(
        r.engine
            .rebind_scope(WHO, &domain(), &uuid::Uuid::from_bytes([3; 16]), "x")
            .await,
        Err(VaultError::NotFound)
    );
}

#[tokio::test]
async fn a_shred_deletes_the_objects_it_destroyed() {
    let r = rig().await;
    create(&r.engine, Some("alice"), "a", "1").await;
    create(&r.engine, Some("alice"), "b", "2").await;
    create(&r.engine, Some("bob"), "c", "3").await;
    assert_eq!(r.engine.objects().inner.object_count(), 3);
    r.engine
        .shred_subject(WHO, &domain(), "alice", Reason::Admin)
        .await
        .unwrap();
    assert_eq!(r.engine.objects().inner.object_count(), 1);
    r.engine
        .shred_scope(WHO, &domain(), "c", Reason::Admin)
        .await
        .unwrap();
    assert_eq!(r.engine.objects().inner.object_count(), 0);
    let _ = ObjectKey {
        domain_id: domain(),
        object_id: id(0),
    };
}
