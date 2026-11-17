//! Issuers, policy versions, dual-control approvals and atomic batch insert, on PostgreSQL.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::sync::Arc;

use common::{World, fact, refused_with};
use pvlt_core::store::{KeyStore, NewApproval, State, StoreError};
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

fn new_id() -> Uuid {
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
    Uuid::from_u128(u128::from(N.fetch_add(1, std::sync::atomic::Ordering::SeqCst)) | (1 << 100))
}

fn approval(
    world_domain: [u8; 16],
    fact_id: Uuid,
    by: &str,
    break_glass: bool,
    ttl_secs: i64,
) -> NewApproval {
    NewApproval {
        id: new_id(),
        domain_id: world_domain,
        fact_id,
        requested_by: by.to_owned(),
        break_glass,
        expires_at: OffsetDateTime::now_utc() + Duration::seconds(ttl_secs),
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn issuers_are_registered_listed_and_disabled() {
    let w = World::new().await;
    let roles = vec!["verifier".to_owned(), "data-subject".to_owned()];
    let a = w
        .store()
        .create_issuer("backend", &[1; 32], &roles)
        .await
        .unwrap();
    let b = w
        .store()
        .create_issuer("other", &[2; 32], &[])
        .await
        .unwrap();
    assert_eq!((a.key_id, b.key_id), (1, 2));
    assert!(a.enabled);
    assert_eq!(a.roles, roles);
    assert_eq!(
        w.store().create_issuer("backend", &[3; 32], &roles).await,
        Err(StoreError::AlreadyExists)
    );
    assert!(matches!(
        w.store().create_issuer("", &[3; 32], &roles).await,
        Err(StoreError::Conflict(_))
    ));
    w.store().set_issuer_enabled(1, false).await.unwrap();
    let all = w.store().issuers().await.unwrap();
    assert_eq!(all.len(), 2);
    assert!(!all[0].enabled && all[1].enabled);
    assert_eq!(
        w.store().set_issuer_enabled(99, true).await,
        Err(StoreError::NotFound)
    );
    w.store().set_issuer_enabled(1, true).await.unwrap();
    assert!(w.store().issuers().await.unwrap()[0].enabled);
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn policies_are_versioned_and_never_change() {
    let w = World::new().await;
    assert_eq!(w.store().current_policy().await.unwrap(), None);
    let one = w
        .store()
        .put_policy(b"{\"version\":1}", &[1; 32], "alice")
        .await
        .unwrap();
    let two = w
        .store()
        .put_policy(b"{\"version\":1,\"roles\":{}}", &[2; 32], "bob")
        .await
        .unwrap();
    assert_eq!((one.version, two.version), (1, 2));
    let now = w.store().current_policy().await.unwrap().unwrap();
    assert_eq!(
        (now.version, now.hash, now.created_by.as_str()),
        (2, [2; 32], "bob")
    );
    for sql in [
        "UPDATE policies SET created_by = 'mallory'",
        "DELETE FROM policies",
    ] {
        assert_eq!(refused_with(w.db.pool(), sql).await.0, "23000", "{sql}");
    }
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn an_approval_needs_a_second_person_and_works_once() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let (f, _) = fact(&seed, &alice, 1);
    let other = fact(&seed, &alice, 2).0;
    w.store().insert_fact(&f).await.unwrap();
    let d = seed.domain_id;
    let now = OffsetDateTime::now_utc();

    let req = approval(d, f.fact_id, "admin-a", false, 300);
    let made = w.store().create_approval(&req).await.unwrap();
    assert_eq!(made.approved_by, None);
    // Not usable while pending.
    assert!(matches!(
        w.store()
            .consume_approval(&d, &req.id, &f.fact_id, now)
            .await,
        Err(StoreError::Conflict(_))
    ));
    // The requester cannot approve their own request.
    assert!(matches!(
        w.store().approve(&req.id, "admin-a", now).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        w.store().approve(&new_id(), "admin-b", now).await,
        Err(StoreError::NotFound)
    );
    let approved = w.store().approve(&req.id, "admin-b", now).await.unwrap();
    assert_eq!(approved.approved_by.as_deref(), Some("admin-b"));
    assert!(matches!(
        w.store().approve(&req.id, "admin-c", now).await,
        Err(StoreError::Conflict(_))
    ));

    // It covers one fact, in one domain.
    assert!(matches!(
        w.store()
            .consume_approval(&d, &req.id, &other.fact_id, now)
            .await,
        Err(StoreError::Conflict(_))
    ));
    assert!(matches!(
        w.store()
            .consume_approval(&[9; 16], &req.id, &f.fact_id, now)
            .await,
        Err(StoreError::Conflict(_))
    ));
    w.store()
        .consume_approval(&d, &req.id, &f.fact_id, now)
        .await
        .unwrap();
    // Used once.
    assert!(matches!(
        w.store()
            .consume_approval(&d, &req.id, &f.fact_id, now)
            .await,
        Err(StoreError::Conflict(_))
    ));
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn an_approval_expires_and_break_glass_is_the_only_way_to_approve_alone() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let (f, _) = fact(&seed, &alice, 1);
    w.store().insert_fact(&f).await.unwrap();
    let d = seed.domain_id;
    let now = OffsetDateTime::now_utc();

    let short = approval(d, f.fact_id, "admin-a", false, 5);
    w.store().create_approval(&short).await.unwrap();
    let later = now + Duration::seconds(6);
    assert!(matches!(
        w.store().approve(&short.id, "admin-b", later).await,
        Err(StoreError::Conflict(_))
    ));
    let ok = approval(d, f.fact_id, "admin-a", false, 5);
    w.store().create_approval(&ok).await.unwrap();
    w.store().approve(&ok.id, "admin-b", now).await.unwrap();
    assert!(
        matches!(
            w.store()
                .consume_approval(&d, &ok.id, &f.fact_id, later)
                .await,
            Err(StoreError::Conflict(_))
        ),
        "an approved but expired approval must not work"
    );

    let glass = approval(d, f.fact_id, "admin-a", true, 300);
    let made = w.store().create_approval(&glass).await.unwrap();
    assert_eq!(made.approved_by.as_deref(), Some("admin-a"));
    assert!(made.break_glass);
    w.store()
        .consume_approval(&d, &glass.id, &f.fact_id, now)
        .await
        .unwrap();

    // The database, not just the code, refuses a self-approval that is not break-glass.
    let sneaky = approval(d, f.fact_id, "admin-a", false, 300);
    w.store().create_approval(&sneaky).await.unwrap();
    let sql: &'static str = Box::leak(
        format!(
            "UPDATE approvals SET approved_by = 'admin-a', approved_at = now() WHERE id = '{}'",
            sneaky.id
        )
        .into_boxed_str(),
    );
    let (code, constraint) = refused_with(w.db.pool(), sql).await;
    assert_eq!(
        (code.as_str(), constraint.as_deref()),
        ("23514", Some("approvals_two_people"))
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 8)]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn of_many_concurrent_uses_of_one_approval_exactly_one_succeeds() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let (f, _) = fact(&seed, &alice, 1);
    w.store().insert_fact(&f).await.unwrap();
    let req = approval(seed.domain_id, f.fact_id, "admin-a", false, 300);
    w.store().create_approval(&req).await.unwrap();
    w.store()
        .approve(&req.id, "admin-b", OffsetDateTime::now_utc())
        .await
        .unwrap();

    let store = Arc::new(w.store().clone());
    let mut tasks = Vec::new();
    for _ in 0..16 {
        let (store, id, fact_id, domain) = (Arc::clone(&store), req.id, f.fact_id, seed.domain_id);
        tasks.push(tokio::spawn(async move {
            store
                .consume_approval(&domain, &id, &fact_id, OffsetDateTime::now_utc())
                .await
        }));
    }
    let mut ok = 0;
    for t in tasks {
        if t.await.unwrap().is_ok() {
            ok += 1;
        }
    }
    assert_eq!(ok, 1);
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_batch_of_facts_is_stored_whole_or_not_at_all() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let bob = w.person(&seed, "bob").await;
    let d = seed.domain_id;
    let (a1, _) = fact(&seed, &alice, 1);
    let (a2, _) = fact(&seed, &alice, 2);
    let (b3, _) = fact(&seed, &bob, 3);
    w.store()
        .insert_facts(&[a1.clone(), a2.clone(), b3.clone()])
        .await
        .unwrap();
    for f in [&a1, &a2, &b3] {
        assert_eq!(
            w.store()
                .fact_for_read(&d, &f.fact_id)
                .await
                .unwrap()
                .fact
                .state,
            State::Active
        );
    }

    // The third fact reuses the second's object id: the whole batch is refused and the first two are not kept.
    let (c4, _) = fact(&seed, &alice, 4);
    let (c5, _) = fact(&seed, &alice, 5);
    let mut clash = fact(&seed, &alice, 6).0;
    clash.object_id = c5.object_id;
    let got = w
        .store()
        .insert_facts(&[c4.clone(), c5.clone(), clash])
        .await;
    assert!(matches!(got, Err(StoreError::Conflict(_))), "{got:?}");
    for f in [&c4, &c5] {
        assert_eq!(
            w.store().fact_for_read(&d, &f.fact_id).await,
            Err(StoreError::NotFound)
        );
    }

    // A shredded subject in the middle of a batch refuses the whole batch.
    w.store().shred_subject_key(&d, &bob.hmac).await.unwrap();
    let (a7, _) = fact(&seed, &alice, 7);
    let (b8, _) = fact(&seed, &bob, 8);
    assert_eq!(
        w.store().insert_facts(&[a7.clone(), b8]).await,
        Err(StoreError::SubjectShredded)
    );
    assert_eq!(
        w.store().fact_for_read(&d, &a7.fact_id).await,
        Err(StoreError::NotFound)
    );
    w.finish().await;
}
