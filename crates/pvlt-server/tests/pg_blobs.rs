//! Blob rows on PostgreSQL: a blob is a fact with a layout and a completion step, and the database refuses
//! the combinations that would make no sense.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use common::{TestDb, World, fact, micros, refused_with};
use pvlt_core::store::{FactKind, KeyStore, LedgerAppend, ShredPlan, State, StoreError};
use time::{Duration, OffsetDateTime};

fn append(seq: u64, prev: [u8; 32], tag: u8) -> LedgerAppend {
    LedgerAppend {
        seq,
        prev,
        hash: [tag; 32],
        line: vec![tag; 4],
    }
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_blob_row_is_pending_until_completed_and_completes_once_with_the_expiry_it_was_given() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let d = seed.domain_id;
    let soon = micros(OffsetDateTime::now_utc() + Duration::hours(1));
    let later = micros(OffsetDateTime::now_utc() + Duration::days(30));
    let (mut b, _) = fact(&seed, &alice, 1);
    b.expires_at = Some(soon);
    w.store()
        .insert_blob(&b, 1024, 5000, Some(later))
        .await
        .unwrap();

    let rec = w.store().fact_for_read(&d, &b.fact_id).await.unwrap().fact;
    assert_eq!(rec.kind, FactKind::Blob);
    let info = rec.blob.unwrap();
    assert_eq!((info.chunk_size, info.len, info.ready), (1024, 5000, false));
    assert_eq!(info.final_expires_at, Some(later));
    assert_eq!(rec.fact.size_class, 0);
    assert_eq!(
        rec.fact.expires_at,
        Some(soon),
        "a pending blob carries its short expiry"
    );

    w.store().complete_blob(&d, &b.fact_id).await.unwrap();
    let done = w.store().fact_for_read(&d, &b.fact_id).await.unwrap().fact;
    assert!(done.blob.unwrap().ready);
    assert_eq!(done.fact.expires_at, Some(later));
    // Once.
    assert!(matches!(
        w.store().complete_blob(&d, &b.fact_id).await,
        Err(StoreError::Conflict(_))
    ));
    // A plain fact is not a blob, and a missing one is missing.
    let (plain, _) = fact(&seed, &alice, 2);
    w.store().insert_fact(&plain).await.unwrap();
    assert!(matches!(
        w.store().complete_blob(&d, &plain.fact_id).await,
        Err(StoreError::Conflict(_))
    ));
    assert_eq!(
        w.store().complete_blob(&d, &common::fact_id(99)).await,
        Err(StoreError::NotFound)
    );
    let plain_rec = w
        .store()
        .fact_for_read(&d, &plain.fact_id)
        .await
        .unwrap()
        .fact;
    assert_eq!((plain_rec.kind, plain_rec.blob), (FactKind::Fact, None));
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_shredded_blob_cannot_be_completed_and_a_shredded_subject_takes_new_blobs_with_it() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let d = seed.domain_id;
    let (b, _) = fact(&seed, &alice, 1);
    w.store().insert_blob(&b, 1024, 10, None).await.unwrap();
    w.store()
        .apply_shred(
            &d,
            &ShredPlan::Facts {
                fact_ids: vec![b.fact_id],
            },
            &append(0, [0; 32], 1),
        )
        .await
        .unwrap();
    assert!(matches!(
        w.store().complete_blob(&d, &b.fact_id).await,
        Err(StoreError::Conflict(_))
    ));
    let rec = w.store().fact_for_read(&d, &b.fact_id).await.unwrap().fact;
    assert_eq!(rec.state, State::Shredded);
    assert_eq!(
        rec.fact.dek.wrapped,
        vec![0u8; 107],
        "the data key was zeroed"
    );

    w.store().shred_subject_key(&d, &alice.hmac).await.unwrap();
    let (late, _) = fact(&seed, &alice, 2);
    assert_eq!(
        w.store().insert_blob(&late, 1024, 10, None).await,
        Err(StoreError::SubjectShredded)
    );
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn the_database_refuses_blob_rows_that_make_no_sense() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let (b, _) = fact(&seed, &alice, 1);
    let (f, _) = fact(&seed, &alice, 2);
    w.store().insert_blob(&b, 1024, 10, None).await.unwrap();
    w.store().insert_fact(&f).await.unwrap();
    let hex_b = b.fact_id.to_string();
    let hex_f = f.fact_id.to_string();
    let cases: [(&str, String, &str); 5] = [
        (
            "a plain fact marked not ready",
            format!("UPDATE facts SET ready = false WHERE fact_id = '{hex_f}'::uuid"),
            "facts_blob_columns",
        ),
        (
            "a plain fact given a chunk size",
            format!("UPDATE facts SET chunk_size = 1024 WHERE fact_id = '{hex_f}'::uuid"),
            "facts_blob_columns",
        ),
        (
            "a chunk size that is not a multiple of 1024",
            format!("UPDATE facts SET chunk_size = 1500 WHERE fact_id = '{hex_b}'::uuid"),
            "facts_chunk_size_check",
        ),
        (
            "a blob with a size class",
            format!("UPDATE facts SET size_class = 256 WHERE fact_id = '{hex_b}'::uuid"),
            "facts_size_class_check",
        ),
        (
            "an unknown kind",
            format!("UPDATE facts SET kind = 'sheet' WHERE fact_id = '{hex_b}'::uuid"),
            "facts_blob_columns",
        ),
    ];
    for (what, sql, constraint) in cases {
        let sql: &'static str = Box::leak(sql.into_boxed_str());
        let (code, got) = refused_with(w.db.pool(), sql).await;
        assert_eq!(
            (code.as_str(), got.as_deref()),
            ("23514", Some(constraint)),
            "{what}"
        );
    }
    w.finish().await;
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "needs PVLT_TEST_DATABASE_URL; run scripts/test-db.sh start"]
async fn a_blob_row_survives_an_export_and_an_import() {
    let w = World::new().await;
    let seed = w.domain(1).await;
    let alice = w.person(&seed, "alice").await;
    let d = seed.domain_id;
    let (b, _) = fact(&seed, &alice, 1);
    let later = micros(OffsetDateTime::now_utc() + Duration::days(3));
    w.store()
        .insert_blob(&b, 4096, 123_456, Some(later))
        .await
        .unwrap();
    w.store().complete_blob(&d, &b.fact_id).await.unwrap();
    let before = w.store().fact_for_read(&d, &b.fact_id).await.unwrap().fact;

    let dump = w.db.store.export_all().await.unwrap();
    let fresh = TestDb::new().await;
    fresh.store.import_all(&dump).await.unwrap();
    let after = fresh
        .store
        .fact_for_read(&d, &b.fact_id)
        .await
        .unwrap()
        .fact;
    assert_eq!(after.kind, FactKind::Blob);
    assert_eq!(after.blob, before.blob);
    assert_eq!(after.fact.expires_at, before.fact.expires_at);
    fresh.finish().await;
    w.finish().await;
}
