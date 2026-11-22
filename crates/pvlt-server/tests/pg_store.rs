//! The Postgres key store against a real database.
//!
//! These need a server and are `#[ignore]`d so a plain `cargo test` stays green on a machine without one:
//!
//! ```text
//! scripts/test-db.sh start
//! PVLT_TEST_DATABASE_URL=$(scripts/test-db.sh url) cargo test -p pvlt-server -- --include-ignored
//! ```

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use common::{TestDb, World, arena, fact, fact_id, hex, person, refused_with, root_hex, within};
use pvlt_core::VaultError;
use pvlt_core::keyring::Keyring;
use pvlt_core::keys::{KeyMaterial, WrappedSubjectKey};
use pvlt_core::seal::{UnsealShare, init_shamir, unseal_with_shares};
use pvlt_core::store::{
    KeyStore, NewFact, NewSubjectKey, ShredFact, ShredSubject, State, StoreError,
};
use pvlt_format::{Suite, fact as format_fact};
use time::OffsetDateTime;

fn zeros() -> Vec<u8> {
    vec![0; 107]
}

fn near_now(t: OffsetDateTime) -> bool {
    (OffsetDateTime::now_utc() - t).whole_seconds().abs() < 600
}

// --- Setup, seal configuration, domains ------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn migrations_are_repeatable_and_make_the_tables() {
    let db = TestDb::new().await;
    db.store.migrate().await.unwrap();
    db.store.migrate().await.unwrap();
    db.store.ping().await.unwrap();
    let tables: Vec<String> = sqlx::query_scalar(
        "SELECT table_name::text FROM information_schema.tables \
         WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1",
    )
    .fetch_all(db.pool())
    .await
    .unwrap();
    assert_eq!(
        tables,
        [
            "_sqlx_migrations",
            "admin_changes",
            "approvals",
            "audit",
            "domains",
            "facts",
            "issuers",
            "ledger",
            "policies",
            "seal_config",
            "seal_kms",
            "sign_keys",
            "subject_keys"
        ]
    );
    db.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn the_kms_seal_is_stored_replaced_and_removed_and_a_backup_leaves_it_out() {
    use pvlt_server::pg::{BACKUP_TABLES, KmsSeal};
    let db = TestDb::new().await;
    assert_eq!(db.store.kms_seal().await.unwrap(), None);
    let one = KmsSeal {
        root_key_id: [7; 16],
        provider: "aws-kms".into(),
        key_id: "alias/pvlt-unseal".into(),
        wrapped: vec![1, 2, 3],
    };
    db.store.set_kms_seal(&one).await.unwrap();
    assert_eq!(db.store.kms_seal().await.unwrap(), Some(one.clone()));
    // Enrolling again (another KMS key) replaces the one record; there is never more than one.
    let two = KmsSeal {
        key_id: "alias/other".into(),
        wrapped: vec![9; 40],
        ..one
    };
    db.store.set_kms_seal(&two).await.unwrap();
    assert_eq!(db.store.kms_seal().await.unwrap(), Some(two));
    let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM seal_kms")
        .fetch_one(db.pool())
        .await
        .unwrap();
    assert_eq!(rows, 1);
    // The database refuses a provider this build does not know and an empty ciphertext.
    for bad in [
        "INSERT INTO seal_kms (singleton, root_key_id, provider, key_id, wrapped) VALUES (false, '\\x00112233445566778899aabbccddeeff', 'aws-kms', 'k', '\\x01')",
        "UPDATE seal_kms SET provider = 'mystery'",
        "UPDATE seal_kms SET wrapped = ''::bytea",
    ] {
        refused_with(db.pool(), bad).await;
    }
    assert!(!BACKUP_TABLES.contains(&"seal_kms"));
    assert!(db.store.clear_kms_seal().await.unwrap());
    assert!(!db.store.clear_kms_seal().await.unwrap());
    assert_eq!(db.store.kms_seal().await.unwrap(), None);
    db.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn seal_config_is_written_once_and_read_back_exactly() {
    let db = TestDb::new().await;
    assert_eq!(db.store.seal_config().await.unwrap(), None);
    let a = arena();
    let first = init_shamir(&a, 3, 5).unwrap().config;
    db.store.init_seal_config(&first).await.unwrap();
    assert_eq!(db.store.seal_config().await.unwrap(), Some(first.clone()));

    let second = init_shamir(&a, 2, 4).unwrap().config;
    assert_eq!(
        db.store.init_seal_config(&second).await.unwrap_err(),
        StoreError::AlreadyExists
    );
    assert_eq!(
        db.store.seal_config().await.unwrap(),
        Some(first),
        "the original is untouched"
    );
    db.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn only_one_of_many_concurrent_initialisations_wins() {
    within(async {
        let db = TestDb::new().await;
        let a = arena();
        let configs: Vec<_> = (0..8)
            .map(|_| init_shamir(&a, 2, 3).unwrap().config)
            .collect();
        let handles: Vec<_> = configs
            .iter()
            .cloned()
            .map(|c| {
                let store = db.store.clone();
                tokio::spawn(async move { store.init_seal_config(&c).await })
            })
            .collect();
        let mut winners = Vec::new();
        for (i, h) in handles.into_iter().enumerate() {
            match h.await.unwrap() {
                Ok(()) => winners.push(i),
                Err(e) => assert_eq!(e, StoreError::AlreadyExists),
            }
        }
        assert_eq!(winners.len(), 1, "exactly one initialisation may succeed");
        assert_eq!(
            db.store.seal_config().await.unwrap().as_ref(),
            Some(&configs[winners[0]])
        );
        db.finish().await;
    })
    .await;
}

#[cfg(feature = "dev-insecure")]
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_passphrase_seal_config_round_trips() {
    use pvlt_core::seal::{PassphraseParams, init_passphrase};
    let db = TestDb::new().await;
    let params = PassphraseParams {
        m_kib: 8,
        t_cost: 1,
        p_cost: 1,
        salt: [5; 16],
    };
    let config = init_passphrase(&arena(), b"correct horse battery", params)
        .unwrap()
        .config;
    db.store.init_seal_config(&config).await.unwrap();
    assert_eq!(db.store.seal_config().await.unwrap(), Some(config));
    db.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn domains_round_trip_and_are_unique() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let got = w.store().domain(&seed.domain_id).await.unwrap();
    assert_eq!(
        (got.domain_id, got.keys.clone(), got.state),
        (seed.domain_id, seed.wrapped.clone(), State::Active)
    );
    assert!(near_now(got.created_at));

    assert_eq!(
        w.store()
            .create_domain(&seed.domain_id, &seed.wrapped)
            .await
            .unwrap_err(),
        StoreError::AlreadyExists
    );
    assert_eq!(
        w.store().domain(&[9; 16]).await.unwrap_err(),
        StoreError::NotFound
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn wrapped_keys_of_the_wrong_length_are_refused_by_the_database() {
    let w = World::new().await;
    let (_, mut bad) = pvlt_core::keys::DomainKeys::create(&w.arena, &w.root, &[4; 16]).unwrap();
    bad.kek.pop();
    assert_eq!(
        w.store().create_domain(&[4; 16], &bad).await.unwrap_err(),
        StoreError::Conflict("record violates a constraint")
    );
    assert_eq!(
        w.store().domain(&[4; 16]).await.unwrap_err(),
        StoreError::NotFound,
        "nothing was stored"
    );
    w.finish().await;
}

// --- Subject keys ----------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn the_first_subject_key_wins_and_later_ones_are_discarded() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let first = person(&seed, "user:1");
    assert_eq!(
        w.store()
            .subject_key(&seed.domain_id, &first.hmac)
            .await
            .unwrap(),
        None
    );
    let stored = w
        .store()
        .get_or_insert_subject_key(&first.record)
        .await
        .unwrap();
    assert_eq!(
        (stored.key.clone(), stored.state),
        (first.record.key.clone(), State::Active)
    );

    let second = person(&seed, "user:1");
    assert_ne!(first.record.key.wrapped, second.record.key.wrapped);
    let again = w
        .store()
        .get_or_insert_subject_key(&second.record)
        .await
        .unwrap();
    assert_eq!(
        again.key, first.record.key,
        "the existing key is returned, not the new one"
    );

    let other = NewSubjectKey {
        domain_id: [9; 16],
        ..first.record.clone()
    };
    assert_eq!(
        w.store()
            .get_or_insert_subject_key(&other)
            .await
            .unwrap_err(),
        StoreError::Conflict("domain does not exist")
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn concurrent_callers_for_one_subject_all_get_the_same_key() {
    within(async {
        let w = World::new().await;
        let seed = w.domain(1).await;
        let candidates: Vec<_> = (0..16).map(|_| person(&seed, "user:race").record).collect();
        let handles: Vec<_> = candidates
            .into_iter()
            .map(|c| {
                let store = w.store().clone();
                tokio::spawn(async move { store.get_or_insert_subject_key(&c).await.unwrap() })
            })
            .collect();
        let mut results = Vec::new();
        for h in handles {
            results.push(h.await.unwrap());
        }
        assert!(
            results.windows(2).all(|p| p[0].key == p[1].key),
            "everyone must see the winner's key"
        );
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM subject_keys")
            .fetch_one(w.db.pool())
            .await
            .unwrap();
        assert_eq!(rows, 1);
        w.finish().await;
    })
    .await;
}

// --- Facts -----------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_fact_reads_back_with_its_subject_key_and_domain() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let p = w.person(&seed, "user:ada").await;
    let (mut f, _) = fact(&seed, &p, 7);
    f.expires_at = Some(OffsetDateTime::from_unix_timestamp(1_900_000_000).unwrap());
    f.fact_type = "json".to_owned();
    f.size_class = 4096;
    w.store().insert_fact(&f).await.unwrap();

    let bundle = w
        .store()
        .fact_for_read(&seed.domain_id, &f.fact_id)
        .await
        .unwrap();
    assert_eq!(bundle.fact.fact, f);
    assert_eq!(
        (bundle.fact.state, bundle.fact.shredded_at),
        (State::Active, None)
    );
    assert!(near_now(bundle.fact.created_at));
    assert_eq!(bundle.subject_key.key, p.record.key);
    assert_eq!(
        (bundle.subject_key.state, bundle.subject_key.subject_hmac),
        (State::Active, p.hmac)
    );
    assert_eq!(bundle.domain.keys, seed.wrapped);
    assert_eq!(bundle.domain.state, State::Active);
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn the_largest_numbers_round_trip() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let p = w.person(&seed, "user:big").await;
    let (mut f, _) = fact(&seed, &p, 1);
    f.dek.generation = u32::MAX;
    f.size_class = 4_194_304;
    f.bik_version = u32::MAX;
    w.store().insert_fact(&f).await.unwrap();
    let got = w
        .store()
        .fact_for_read(&seed.domain_id, &f.fact_id)
        .await
        .unwrap();
    assert_eq!(got.fact.fact, f);
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn duplicate_ids_are_refused_by_kind() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let p = w.person(&seed, "user:1").await;
    let (f, _) = fact(&seed, &p, 1);
    w.store().insert_fact(&f).await.unwrap();

    assert_eq!(
        w.store().insert_fact(&f).await.unwrap_err(),
        StoreError::AlreadyExists,
        "same fact id"
    );
    let clash = NewFact {
        fact_id: fact_id(2),
        ..f.clone()
    };
    assert_eq!(
        w.store().insert_fact(&clash).await.unwrap_err(),
        StoreError::Conflict("object id already in use"),
        "same object id"
    );

    // The same fact id in another domain is a different fact.
    let other = w.domain(2).await;
    let q = w.person(&other, "user:1").await;
    let (g, _) = fact(&other, &q, 1);
    assert_eq!(g.fact_id, f.fact_id);
    w.store().insert_fact(&g).await.unwrap();
    assert_ne!(
        w.store()
            .fact_for_read(&seed.domain_id, &f.fact_id)
            .await
            .unwrap()
            .fact
            .fact
            .scope_hmac,
        w.store()
            .fact_for_read(&other.domain_id, &g.fact_id)
            .await
            .unwrap()
            .fact
            .fact
            .scope_hmac
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn of_many_concurrent_inserts_of_one_fact_exactly_one_wins() {
    within(async {
        let w = World::new().await;
        let seed = w.domain(1).await;
        let p = w.person(&seed, "user:1").await;
        let (f, _) = fact(&seed, &p, 1);
        let handles: Vec<_> = (0..12)
            .map(|_| {
                let (store, f) = (w.store().clone(), f.clone());
                tokio::spawn(async move { store.insert_fact(&f).await })
            })
            .collect();
        let (mut ok, mut dup) = (0, 0);
        for h in handles {
            match h.await.unwrap() {
                Ok(()) => ok += 1,
                Err(StoreError::AlreadyExists) => dup += 1,
                Err(e) => panic!("unexpected: {e}"),
            }
        }
        assert_eq!((ok, dup), (1, 11));
        w.finish().await;
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_fact_needs_an_existing_subject_key() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let p = person(&seed, "user:never-stored");
    let (f, _) = fact(&seed, &p, 1);
    assert_eq!(
        w.store().insert_fact(&f).await.unwrap_err(),
        StoreError::Conflict("subject key does not exist")
    );

    let stored = w.person(&seed, "user:1").await;
    let (mut g, _) = fact(&seed, &stored, 2);
    g.dek.subject_key_version = 2;
    assert_eq!(
        w.store().insert_fact(&g).await.unwrap_err(),
        StoreError::Conflict("subject key does not exist")
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn bad_fact_fields_are_refused_by_the_database() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let p = w.person(&seed, "user:1").await;
    let (good, _) = fact(&seed, &p, 1);
    for (name, f) in [
        (
            "size class",
            NewFact {
                size_class: 100,
                ..good.clone()
            },
        ),
        (
            "empty type",
            NewFact {
                fact_type: String::new(),
                ..good.clone()
            },
        ),
        (
            "long type",
            NewFact {
                fact_type: "x".repeat(65),
                ..good.clone()
            },
        ),
        ("short key", {
            let mut f = good.clone();
            f.dek.wrapped.pop();
            f
        }),
    ] {
        assert_eq!(
            w.store().insert_fact(&f).await.unwrap_err(),
            StoreError::Conflict("record violates a constraint"),
            "{name}"
        );
    }
    assert_eq!(
        w.store()
            .fact_for_read(&seed.domain_id, &good.fact_id)
            .await
            .unwrap_err(),
        StoreError::NotFound
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn unknown_facts_and_wrong_domains_are_not_found() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let p = w.person(&seed, "user:1").await;
    let (f, _) = fact(&seed, &p, 1);
    w.store().insert_fact(&f).await.unwrap();
    assert_eq!(
        w.store()
            .fact_for_read(&seed.domain_id, &fact_id(99))
            .await
            .unwrap_err(),
        StoreError::NotFound
    );
    assert_eq!(
        w.store()
            .fact_for_read(&[9; 16], &f.fact_id)
            .await
            .unwrap_err(),
        StoreError::NotFound
    );
    w.finish().await;
}

// --- Shredding -------------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn shredding_a_fact_zeroes_its_key_and_is_idempotent() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let p = w.person(&seed, "user:1").await;
    let (f, _) = fact(&seed, &p, 1);
    let (keep, _) = fact(&seed, &p, 2);
    w.store().insert_fact(&f).await.unwrap();
    w.store().insert_fact(&keep).await.unwrap();

    let out = w
        .store()
        .shred_fact(&seed.domain_id, &f.fact_id)
        .await
        .unwrap();
    assert_eq!(
        out,
        ShredFact::Shredded {
            object_id: f.object_id
        }
    );

    let gone = w
        .store()
        .fact_for_read(&seed.domain_id, &f.fact_id)
        .await
        .unwrap();
    assert_eq!(gone.fact.state, State::Shredded);
    assert_eq!(gone.fact.fact.dek.wrapped, zeros());
    assert!(gone.fact.shredded_at.is_some_and(near_now));
    assert_eq!(
        gone.subject_key.state,
        State::Active,
        "shredding a fact leaves its subject alone"
    );

    assert_eq!(
        w.store()
            .shred_fact(&seed.domain_id, &f.fact_id)
            .await
            .unwrap(),
        ShredFact::AlreadyShredded
    );
    assert_eq!(
        w.store()
            .shred_fact(&seed.domain_id, &fact_id(99))
            .await
            .unwrap(),
        ShredFact::NotFound
    );
    let kept = w
        .store()
        .fact_for_read(&seed.domain_id, &keep.fact_id)
        .await
        .unwrap();
    assert_eq!(
        (kept.fact.state, kept.fact.fact),
        (State::Active, keep),
        "other facts are untouched"
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_fact_under_legal_hold_cannot_be_shredded() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let p = w.person(&seed, "user:1").await;
    let (mut f, _) = fact(&seed, &p, 1);
    f.legal_hold = true;
    w.store().insert_fact(&f).await.unwrap();
    assert_eq!(
        w.store()
            .shred_fact(&seed.domain_id, &f.fact_id)
            .await
            .unwrap_err(),
        StoreError::LegalHold
    );
    let still = w
        .store()
        .fact_for_read(&seed.domain_id, &f.fact_id)
        .await
        .unwrap();
    assert_eq!(
        (still.fact.state, still.fact.fact.dek.wrapped.clone()),
        (State::Active, f.dek.wrapped.clone())
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn shredding_a_subject_makes_all_its_facts_unreadable_at_once() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "user:alice").await;
    let bob = w.person(&seed, "user:bob").await;
    let (a1, _) = fact(&seed, &alice, 1);
    let (a2, _) = fact(&seed, &alice, 2);
    let (b1, _) = fact(&seed, &bob, 3);
    for f in [&a1, &a2, &b1] {
        w.store().insert_fact(f).await.unwrap();
    }

    assert_eq!(
        w.store()
            .shred_subject_key(&seed.domain_id, &alice.hmac)
            .await
            .unwrap(),
        ShredSubject::Shredded
    );

    for f in [&a1, &a2] {
        let b = w
            .store()
            .fact_for_read(&seed.domain_id, &f.fact_id)
            .await
            .unwrap();
        assert_eq!(b.subject_key.state, State::Shredded);
        assert_eq!(b.subject_key.key.wrapped, zeros());
        let opened = seed
            .domain
            .unwrap_subject_key(&alice.hmac, &b.subject_key.key);
        assert!(
            matches!(opened, Err(VaultError::Shredded)),
            "the subject key must open as Shredded"
        );
    }
    let b = w
        .store()
        .fact_for_read(&seed.domain_id, &b1.fact_id)
        .await
        .unwrap();
    assert_eq!(
        b.subject_key.state,
        State::Active,
        "another subject is untouched"
    );
    assert!(
        seed.domain
            .unwrap_subject_key(&bob.hmac, &b.subject_key.key)
            .is_ok()
    );

    assert_eq!(
        w.store()
            .shred_subject_key(&seed.domain_id, &alice.hmac)
            .await
            .unwrap(),
        ShredSubject::AlreadyShredded
    );
    assert_eq!(
        w.store()
            .shred_subject_key(&seed.domain_id, &[1; 32])
            .await
            .unwrap(),
        ShredSubject::NotFound
    );

    // Nothing can be stored under a destroyed subject, and asking for a key hands back the shredded one.
    let (late, _) = fact(&seed, &alice, 4);
    assert_eq!(
        w.store().insert_fact(&late).await.unwrap_err(),
        StoreError::SubjectShredded
    );
    let renewed = person(&seed, "user:alice");
    let got = w
        .store()
        .get_or_insert_subject_key(&renewed.record)
        .await
        .unwrap();
    assert_eq!(
        (got.state, got.key.wrapped),
        (State::Shredded, zeros()),
        "a shredded subject is not silently reopened"
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn the_database_refuses_to_undo_a_shred() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let p = w.person(&seed, "user:1").await;
    let (f, _) = fact(&seed, &p, 1);
    w.store().insert_fact(&f).await.unwrap();
    w.store()
        .shred_fact(&seed.domain_id, &f.fact_id)
        .await
        .unwrap();
    w.store()
        .shred_subject_key(&seed.domain_id, &p.hmac)
        .await
        .unwrap();
    let pool = w.db.pool();

    // A shredded row cannot be changed in any way, even by hand. 23000 is the trigger's own error, so a typo in
    // one of these statements would show up as a different code.
    for sql in [
        "UPDATE facts SET legal_hold = true",
        "UPDATE facts SET state = 'active', shredded_at = NULL, wrapped_dek = decode(repeat('01', 107), 'hex')",
        "UPDATE subject_keys SET state = 'active', shredded_at = NULL, wrapped_key = decode(repeat('01', 107), 'hex')",
        "UPDATE subject_keys SET kek_version = 2",
    ] {
        let (code, _) = refused_with(pool, sql).await;
        assert_eq!(code, "23000", "wrong reason for refusing: {sql}");
    }

    // A live row cannot be marked shredded without destroying its key (23514 is a CHECK violation).
    let q = w.person(&seed, "user:2").await;
    let (g, _) = fact(&seed, &q, 2);
    w.store().insert_fact(&g).await.unwrap();
    let (code, constraint) = refused_with(
        pool,
        "UPDATE facts SET state = 'shredded', shredded_at = now() WHERE state = 'active'",
    )
    .await;
    assert_eq!(
        (code.as_str(), constraint.as_deref()),
        ("23514", Some("facts_shredded_key_is_zero"))
    );

    // A shredded row cannot be inserted with a live key either.
    let (code, constraint) = refused_with(
        pool,
        "INSERT INTO subject_keys (domain_id, subject_hmac, version, bik_version, kek_version, wrapped_key, state, shredded_at) \
         SELECT domain_id, decode(repeat('ab', 32), 'hex'), 1, 1, 1, decode(repeat('01', 107), 'hex'), 'shredded', now() \
         FROM domains LIMIT 1",
    )
    .await;
    assert_eq!(
        (code.as_str(), constraint.as_deref()),
        ("23514", Some("subject_keys_shredded_key_is_zero"))
    );
    w.finish().await;
}

// --- Races -----------------------------------------------------------------------------------------------

/// The ordering guarantee, proved deterministically: hold the subject key row the way a shred in progress would,
/// and an insert must wait for it and then be refused. Without `FOR SHARE` in `insert_fact` it would not wait,
/// would read the old state, and would report success for a fact whose key is already destroyed.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn an_insert_waits_for_a_shred_in_progress_and_is_then_refused() {
    within(async {
        let w = World::new().await;
        let seed = w.domain(1).await;
        let p = w.person(&seed, "user:1").await;
        let (f, _) = fact(&seed, &p, 1);

        let mut shredding = w.db.pool().begin().await.unwrap();
        sqlx::query("SELECT 1 FROM subject_keys WHERE subject_hmac = $1 FOR UPDATE")
            .bind(p.hmac.as_slice())
            .fetch_all(&mut *shredding)
            .await
            .unwrap();
        sqlx::query(
            "UPDATE subject_keys SET wrapped_key = decode(repeat('00', 107), 'hex'), state = 'shredded', \
             shredded_at = now() WHERE subject_hmac = $1",
        )
        .bind(p.hmac.as_slice())
        .execute(&mut *shredding)
        .await
        .unwrap();

        let store = w.store().clone();
        let insert = tokio::spawn(async move { store.insert_fact(&f).await });
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(!insert.is_finished(), "the insert must wait for the shred in progress, not read the old state");

        shredding.commit().await.unwrap();
        assert_eq!(insert.await.unwrap().unwrap_err(), StoreError::SubjectShredded);
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM facts").fetch_one(w.db.pool()).await.unwrap();
        assert_eq!(rows, 0, "the refused fact left nothing behind");
        w.finish().await;
    })
    .await;
}

/// The other side: a shred must wait for an insert that is in flight, so the fact that insert stores is covered
/// by the shred and not left behind it.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_shred_waits_for_an_insert_in_progress() {
    within(async {
        let w = World::new().await;
        let seed = w.domain(1).await;
        let p = w.person(&seed, "user:1").await;

        let mut inserting = w.db.pool().begin().await.unwrap();
        sqlx::query("SELECT 1 FROM subject_keys WHERE subject_hmac = $1 FOR SHARE")
            .bind(p.hmac.as_slice())
            .fetch_all(&mut *inserting)
            .await
            .unwrap();

        let (store, domain_id, hmac) = (w.store().clone(), seed.domain_id, p.hmac);
        let shred = tokio::spawn(async move { store.shred_subject_key(&domain_id, &hmac).await });
        tokio::time::sleep(std::time::Duration::from_millis(400)).await;
        assert!(
            !shred.is_finished(),
            "the shred must wait for the insert in progress"
        );

        inserting.commit().await.unwrap();
        assert_eq!(shred.await.unwrap().unwrap(), ShredSubject::Shredded);
        w.finish().await;
    })
    .await;
}

/// A fact insert and a shred of its subject at the same moment, 60 times over. This is a smoke test for errors
/// and for lost or phantom rows; it cannot prove the ordering, because both orders leave the same final state.
/// The two tests above prove the ordering by holding the locks.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn inserting_facts_races_with_shredding_their_subject() {
    within(async {
        let w = World::new().await;
        let seed = w.domain(1).await;
        let (mut stored_and_ok, mut refused) = (0u32, 0u32);
        for round in 0..60u32 {
            let p = w.person(&seed, &format!("racer-{round}")).await;
            let facts: Vec<NewFact> = (0..4).map(|i| fact(&seed, &p, round * 4 + i).0).collect();
            let inserts: Vec<_> = facts
                .iter()
                .cloned()
                .map(|f| {
                    let store = w.store().clone();
                    tokio::spawn(async move { store.insert_fact(&f).await })
                })
                .collect();
            let shred = {
                let (store, domain_id, hmac) = (w.store().clone(), seed.domain_id, p.hmac);
                tokio::spawn(async move { store.shred_subject_key(&domain_id, &hmac).await })
            };

            let mut ok = 0;
            for h in inserts {
                match h.await.unwrap() {
                    Ok(()) => ok += 1,
                    Err(StoreError::SubjectShredded) => refused += 1,
                    Err(e) => panic!("unexpected: {e}"),
                }
            }
            assert_eq!(shred.await.unwrap().unwrap(), ShredSubject::Shredded);
            stored_and_ok += ok;

            let rows: i64 =
                sqlx::query_scalar("SELECT count(*) FROM facts WHERE subject_hmac = $1")
                    .bind(p.hmac.as_slice())
                    .fetch_one(w.db.pool())
                    .await
                    .unwrap();
            assert_eq!(
                rows,
                i64::from(ok),
                "round {round}: every reported success is stored, nothing else is"
            );
            for f in &facts {
                match w.store().fact_for_read(&seed.domain_id, &f.fact_id).await {
                    Ok(b) => assert_eq!(
                        b.subject_key.state,
                        State::Shredded,
                        "round {round}: stored under a live key"
                    ),
                    Err(StoreError::NotFound) => {}
                    Err(e) => panic!("unexpected: {e}"),
                }
            }
        }
        eprintln!("insert-vs-shred: {stored_and_ok} inserts won, {refused} were refused");
        w.finish().await;
    })
    .await;
}

/// Readers never see a half-shredded fact: either the key is intact and it is active, or the key is zero and it is
/// shredded. And once a reader has seen it shredded, it stays shredded.
#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn reads_see_a_fact_either_whole_or_shredded_never_in_between() {
    within(async {
        let w = World::new().await;
        let seed = w.domain(1).await;
        let p = w.person(&seed, "user:1").await;
        let (f, _) = fact(&seed, &p, 1);
        w.store().insert_fact(&f).await.unwrap();
        let shredding = Arc::new(AtomicBool::new(false));

        let readers: Vec<_> = (0..6)
            .map(|_| {
                let (store, domain_id, id, f, flag) = (
                    w.store().clone(),
                    seed.domain_id,
                    f.fact_id,
                    f.clone(),
                    shredding.clone(),
                );
                tokio::spawn(async move {
                    let (mut seen_shredded, mut reads) = (false, 0u32);
                    loop {
                        let b = store.fact_for_read(&domain_id, &id).await.unwrap();
                        reads += 1;
                        match b.fact.state {
                            State::Active => {
                                assert!(!seen_shredded, "a shredded fact came back to life");
                                assert_eq!(b.fact.fact.dek, f.dek);
                                assert!(b.fact.shredded_at.is_none());
                            }
                            State::Shredded => {
                                seen_shredded = true;
                                assert_eq!(b.fact.fact.dek.wrapped, zeros());
                                assert!(b.fact.shredded_at.is_some());
                            }
                        }
                        if seen_shredded {
                            return reads;
                        }
                        if flag.load(Ordering::SeqCst) {
                            tokio::task::yield_now().await;
                        }
                    }
                })
            })
            .collect();

        tokio::time::sleep(std::time::Duration::from_millis(30)).await;
        shredding.store(true, Ordering::SeqCst);
        assert_eq!(
            w.store()
                .shred_fact(&seed.domain_id, &f.fact_id)
                .await
                .unwrap(),
            ShredFact::Shredded {
                object_id: f.object_id
            }
        );
        let mut total = 0;
        for r in readers {
            total += r.await.unwrap();
        }
        eprintln!("read-vs-shred: {total} reads across 6 readers");
        w.finish().await;
    })
    .await;
}

// --- What is at rest -------------------------------------------------------------------------------------

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn no_plaintext_subject_scope_or_key_is_in_any_table() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let subject = "alice@example.com";
    let p = w.person(&seed, subject).await;
    let (mut f, dek) = fact(&seed, &p, 1);
    let scope = "kyc-doc:alice-passport";
    f.scope_hmac = seed.domain.scope_hmac(scope).unwrap();
    w.store().insert_fact(&f).await.unwrap();

    let dump = w.db.dump().await.to_lowercase();
    // The dump is real: the wrapped keys and hashes are in it.
    for present in [
        hex(&f.dek.wrapped),
        hex(&p.hmac),
        hex(&f.scope_hmac),
        hex(&p.record.key.wrapped),
        hex(&seed.wrapped.kek),
    ] {
        assert!(
            dump.contains(&present),
            "the scan cannot see the stored data, so it proves nothing"
        );
    }
    // And none of what must never be at rest is.
    let forbidden = [
        ("subject", subject.to_lowercase()),
        ("subject local part", "alice".to_owned()),
        ("scope", scope.to_owned()),
        ("root key", root_hex(&w)),
        ("subject key", hex(p.key.expose())),
        ("data key", hex(dek.expose())),
    ];
    for (what, needle) in forbidden {
        assert!(!dump.contains(&needle), "{what} found in the database");
    }
    w.finish().await;
}

// --- The whole path --------------------------------------------------------------------------------------

/// Seal, store, restart from the stored state with Shamir shares, read the value back, shred it, and see the
/// read fail as shredded. The object store is a variable.
#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_fact_survives_a_restart_and_then_a_shred() {
    let db = TestDb::new().await;
    let store = &db.store;
    let secret = b"Ada Example, born 1815-12-10";
    let (domain_id, object_id, fid) = ([1u8; 16], [9u8; 16], fact_id(77));

    // First start: initialise, make a domain, store a fact.
    let arena1 = arena();
    let init = init_shamir(&arena1, 3, 5).unwrap();
    store.init_seal_config(&init.config).await.unwrap();
    let share_text: Vec<String> = init
        .shares
        .iter()
        .map(|s| s.to_text().to_string())
        .collect();
    let ring = Keyring::new(arena1);
    ring.unseal(init.root);
    let wrapped_domain = ring.create_domain(&domain_id).unwrap();
    store
        .create_domain(&domain_id, &wrapped_domain)
        .await
        .unwrap();

    let (hmac, scope_hmac, wrapped_sk, wrapped_dek, bik_version, bucket) = ring
        .with_domain(&domain_id, &wrapped_domain, |d| {
            let hmac = d.subject_hmac("user:ada")?;
            let scope_hmac = d.scope_hmac("kyc:ada")?;
            let (sk, wrapped_sk) = d.new_subject_key(&hmac, 1)?;
            let (dek, wrapped_dek) = sk.new_dek(&object_id, 0)?;
            let object = format_fact::seal(
                dek.expose(),
                Suite::XChaCha20Poly1305,
                d.domain_id(),
                &object_id,
                0,
                &[3; 24],
                secret,
            )?;
            Ok((
                hmac,
                scope_hmac,
                wrapped_sk,
                wrapped_dek,
                d.bik_version(),
                object,
            ))
        })
        .unwrap();
    let kept = store
        .get_or_insert_subject_key(&NewSubjectKey {
            domain_id,
            subject_hmac: hmac,
            bik_version,
            key: wrapped_sk,
        })
        .await
        .unwrap();
    assert_eq!(kept.state, State::Active);
    store
        .insert_fact(&NewFact {
            domain_id,
            fact_id: fid,
            subject_hmac: hmac,
            bik_version,
            scope_hmac,
            fact_type: "ascii".to_owned(),
            object_id,
            size_class: 256,
            dek: wrapped_dek,
            expires_at: None,
            legal_hold: false,
        })
        .await
        .unwrap();
    assert!(ring.seal());
    drop(ring);

    // Restart: a new process has only the database, the bucket and three shares.
    let arena2 = arena();
    let config = store.seal_config().await.unwrap().unwrap();
    assert_eq!(config, init.config);
    let shares: Vec<UnsealShare> = [4, 1, 2]
        .iter()
        .map(|i| UnsealShare::from_text(&share_text[*i]).unwrap())
        .collect();
    let ring2 = Keyring::new(arena2.clone());
    ring2.unseal(unseal_with_shares(&arena2, &config, &shares).unwrap());

    let read = |bundle: &pvlt_core::store::FactBundle| {
        ring2.with_domain(&domain_id, &bundle.domain.keys, |d| {
            let sk =
                d.unwrap_subject_key(&bundle.subject_key.subject_hmac, &bundle.subject_key.key)?;
            let dek = sk.unwrap_dek(&bundle.fact.fact.object_id, &bundle.fact.fact.dek)?;
            Ok(format_fact::open(dek.expose(), &bucket)?.to_vec())
        })
    };
    let bundle = store.fact_for_read(&domain_id, &fid).await.unwrap();
    assert_eq!(
        read(&bundle).unwrap(),
        secret,
        "the value survives a restart"
    );

    // Shred it. The ciphertext is still in the bucket; the key is gone.
    assert_eq!(
        store.shred_fact(&domain_id, &fid).await.unwrap(),
        ShredFact::Shredded { object_id }
    );
    let after = store.fact_for_read(&domain_id, &fid).await.unwrap();
    assert_eq!(after.fact.state, State::Shredded);
    assert_eq!(read(&after).unwrap_err(), VaultError::Shredded);
    assert!(!bucket.is_empty());

    // The same through the subject: another fact under Ada becomes unreadable by shredding her.
    let wrapped_sk_again = WrappedSubjectKey {
        wrapped: zeros(),
        ..bundle.subject_key.key.clone()
    };
    ring2
        .with_domain(&domain_id, &bundle.domain.keys, |d| {
            assert_eq!(
                d.unwrap_subject_key(&hmac, &wrapped_sk_again).unwrap_err(),
                VaultError::Shredded
            );
            Ok(())
        })
        .unwrap();
    db.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL"]
async fn live_object_ids_names_only_objects_a_reader_could_still_open() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let other_seed = w.domain(2).await;
    let alice = w.person(&seed, "alice").await;
    let bob = w.person(&seed, "bob").await;
    let carol = w.person(&other_seed, "carol").await;
    let (live, _) = fact(&seed, &alice, 1);
    let (shredded_fact, _) = fact(&seed, &alice, 2);
    let (bobs, _) = fact(&seed, &bob, 3);
    let (other_domain, _) = fact(&other_seed, &carol, 4);
    for f in [&live, &shredded_fact, &bobs, &other_domain] {
        w.store().insert_fact(f).await.unwrap();
    }
    let never_stored = [0x77; 16];
    let all = [
        live.object_id,
        shredded_fact.object_id,
        bobs.object_id,
        other_domain.object_id,
        never_stored,
    ];
    let sorted = |mut v: Vec<[u8; 16]>| {
        v.sort();
        v
    };

    // Everything stored in this domain is live; another domain's object and an unknown id are not.
    let got = w
        .store()
        .live_object_ids(&seed.domain_id, &all)
        .await
        .unwrap();
    assert_eq!(
        sorted(got),
        sorted(vec![
            live.object_id,
            shredded_fact.object_id,
            bobs.object_id
        ])
    );

    // A shredded fact's object is no longer live.
    w.store()
        .shred_fact(&seed.domain_id, &shredded_fact.fact_id)
        .await
        .unwrap();
    let got = w
        .store()
        .live_object_ids(&seed.domain_id, &all)
        .await
        .unwrap();
    assert_eq!(sorted(got), sorted(vec![live.object_id, bobs.object_id]));

    // A subject shred leaves the fact row 'active' but its key gone: that object is dead too.
    w.store()
        .shred_subject_key(&seed.domain_id, &bob.hmac)
        .await
        .unwrap();
    let got = w
        .store()
        .live_object_ids(&seed.domain_id, &all)
        .await
        .unwrap();
    assert_eq!(got, vec![live.object_id]);

    // An empty question has an empty answer.
    assert!(
        w.store()
            .live_object_ids(&seed.domain_id, &[])
            .await
            .unwrap()
            .is_empty()
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn subject_facts_lists_one_subjects_facts_and_reports_a_subject_shred_on_each() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "user:alice").await;
    let bob = w.person(&seed, "user:bob").await;
    let (a1, _) = fact(&seed, &alice, 1);
    let (a2, _) = fact(&seed, &alice, 2);
    let (b1, _) = fact(&seed, &bob, 3);
    for f in [&a1, &a2, &b1] {
        w.store().insert_fact(f).await.unwrap();
    }
    w.store()
        .shred_fact(&seed.domain_id, &a2.fact_id)
        .await
        .unwrap();

    let list = w
        .store()
        .subject_facts(&seed.domain_id, &alice.hmac, 100)
        .await
        .unwrap();
    let mut ids: Vec<_> = list.iter().map(|f| f.fact_id).collect();
    ids.sort();
    let mut want = vec![a1.fact_id, a2.fact_id];
    want.sort();
    assert_eq!(ids, want, "only alice's facts, shredded ones included");
    let one = list.iter().find(|f| f.fact_id == a1.fact_id).unwrap();
    assert_eq!(
        (one.state, one.fact_type.as_str(), one.legal_hold),
        (State::Active, a1.fact_type.as_str(), false)
    );
    assert!(near_now(one.created_at) && one.shredded_at.is_none());
    let two = list.iter().find(|f| f.fact_id == a2.fact_id).unwrap();
    assert_eq!(two.state, State::Shredded);
    assert!(two.shredded_at.is_some());
    assert_eq!(
        w.store()
            .subject_facts(&seed.domain_id, &alice.hmac, 1)
            .await
            .unwrap()
            .len(),
        1,
        "the limit is applied"
    );

    // A subject shred leaves the fact rows active but destroys the key: every fact must read as shredded.
    w.store()
        .shred_subject_key(&seed.domain_id, &alice.hmac)
        .await
        .unwrap();
    let after = w
        .store()
        .subject_facts(&seed.domain_id, &alice.hmac, 100)
        .await
        .unwrap();
    assert!(after.iter().all(|f| f.state == State::Shredded));
    let bobs = w
        .store()
        .subject_facts(&seed.domain_id, &bob.hmac, 100)
        .await
        .unwrap();
    assert_eq!(
        bobs.iter()
            .map(|f| (f.fact_id, f.state))
            .collect::<Vec<_>>(),
        [(b1.fact_id, State::Active)]
    );
    assert!(
        w.store()
            .subject_facts(&seed.domain_id, &[9; 32], 100)
            .await
            .unwrap()
            .is_empty()
    );
    w.finish().await;
}
