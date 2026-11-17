//! Blobs: a client-encrypted object, uploaded straight to the bucket, checked, and opened with an audited key.
//!
//! The tests play the browser: they take the ticket, encrypt with `BlobWriter`, put the object in the bucket,
//! and decrypt with `BlobReader`.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use common::{arena, id};
use pvlt_core::VaultError;
use pvlt_core::audit::NullAuditor;
use pvlt_core::audit_log::Caller;
use pvlt_core::engine::{BlobAccess, BlobTicket, CreateBlob, Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::ledger::Reason;
use pvlt_core::memory::{MemKeyStore, MemObjectStore};
use pvlt_core::objects::{ObjectKey, ObjectStore};
use pvlt_core::seal::init_shamir;
use pvlt_core::store::{FactId, KeyStore};
use pvlt_format::Suite;
use pvlt_format::blob::{BlobReader, BlobWriter};
use time::OffsetDateTime;

const WHO: &str = "tester";
const SECRET: &str = "the-front-of-a-passport";

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

fn request<'a>(subject: &'a str, len: usize) -> CreateBlob<'a> {
    CreateBlob {
        subject: Some(subject),
        scope: "kyc-doc:1",
        fact_type: "id_photo",
        len: len as u64,
        chunk_size: 1024,
        expires_at: None,
    }
}

/// What a browser does: encrypt with the ticket's key and return the object.
fn encrypt(t: &BlobTicket, data: &[u8], pieces: usize) -> Vec<u8> {
    let salt = [0x5a; 24];
    let (mut w, header) = BlobWriter::new(
        &t.dek,
        t.suite,
        &t.domain_id,
        &t.object_id,
        t.dek_generation,
        t.chunk_size,
        &salt,
        data.len() as u64,
    )
    .unwrap();
    let mut out = header;
    for p in data.chunks(pieces.max(1)) {
        out.extend_from_slice(&w.write(p).unwrap());
    }
    out.extend_from_slice(&w.finish().unwrap());
    out
}

async fn upload(e: &TestEngine, t: &BlobTicket, object: Vec<u8>) {
    e.objects()
        .put(
            &ObjectKey {
                domain_id: t.domain_id,
                object_id: t.object_id,
            },
            object,
        )
        .await
        .unwrap();
}

fn decrypt(a: &BlobAccess, object: &[u8]) -> Vec<u8> {
    let mut r = BlobReader::new(&a.dek, object).unwrap();
    let mut out = r.push(&object[104..]).unwrap().to_vec();
    out.extend_from_slice(&r.finish().unwrap());
    out
}

async fn blob(e: &TestEngine, subject: &str, data: &[u8]) -> (FactId, BlobTicket) {
    let t = e
        .create_blob(WHO, &domain(), &request(subject, data.len()))
        .await
        .unwrap();
    upload(e, &t, encrypt(&t, data, 700)).await;
    e.complete_blob(WHO, &domain(), &t.blob_id).await.unwrap();
    (t.blob_id, t)
}

#[tokio::test]
async fn a_blob_goes_from_ticket_to_upload_to_completion_to_a_key_and_back() {
    let e = engine().await;
    let data: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let t = e
        .create_blob(WHO, &domain(), &request("user:1", data.len()))
        .await
        .unwrap();
    assert_eq!(
        (t.chunk_size, t.dek_generation, t.suite),
        (1024, 0, Suite::Aes256Gcm)
    );
    // Until it is completed it cannot be opened.
    assert!(matches!(
        e.open_blob(WHO, &domain(), &t.blob_id).await,
        Err(VaultError::Conflict(_))
    ));
    upload(&e, &t, encrypt(&t, &data, 333)).await;
    e.complete_blob(WHO, &domain(), &t.blob_id).await.unwrap();

    let access = e.open_blob(WHO, &domain(), &t.blob_id).await.unwrap();
    assert_eq!(
        access.dek.as_slice(),
        t.dek.as_slice(),
        "the key the client used is the key the vault holds"
    );
    assert_eq!(
        (access.len, access.chunk_size, access.fact_type.as_str()),
        (5000, 1024, "id_photo")
    );
    let object = e
        .objects()
        .get(&ObjectKey {
            domain_id: domain(),
            object_id: access.object_id,
        })
        .await
        .unwrap()
        .unwrap();
    assert_eq!(decrypt(&access, &object), data);
    // Completing twice is refused.
    assert!(matches!(
        e.complete_blob(WHO, &domain(), &t.blob_id).await,
        Err(VaultError::Conflict(_))
    ));
}

#[tokio::test]
async fn the_server_can_decrypt_a_blob_a_chunk_at_a_time_and_a_damaged_one_fails_mid_stream() {
    let e = engine().await;
    let data: Vec<u8> = (0..20_000u32).map(|i| (i * 7 % 256) as u8).collect();
    let (id, _) = blob(&e, "user:1", &data).await;
    let access = e.open_blob(WHO, &domain(), &id).await.unwrap();
    let mut stream = e.blob_stream(&access).await.unwrap();
    let mut got = Vec::new();
    let mut pieces = 0;
    while let Some(chunk) = e.next_blob_chunk(&mut stream).await.unwrap() {
        assert!(chunk.len() <= 1024, "one chunk at a time");
        got.extend_from_slice(&chunk);
        pieces += 1;
    }
    assert_eq!(got, data);
    assert!(pieces > 10);
    // It is finished: asking again returns nothing.
    assert!(e.next_blob_chunk(&mut stream).await.unwrap().is_none());

    // A flipped bit in a late chunk: the stream fails, and what it returned before is not to be trusted.
    let key = ObjectKey {
        domain_id: domain(),
        object_id: access.object_id,
    };
    let mut bad = e.objects().get(&key).await.unwrap().unwrap();
    let at = bad.len() - 500;
    bad[at] ^= 1;
    e.objects().put(&key, bad).await.unwrap();
    let access = e.open_blob(WHO, &domain(), &id).await.unwrap();
    let mut stream = e.blob_stream(&access).await.unwrap();
    let mut failed = false;
    loop {
        match e.next_blob_chunk(&mut stream).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(_) => {
                failed = true;
                break;
            }
        }
    }
    assert!(
        failed,
        "a damaged blob was streamed to the end without an error"
    );
    // And a stream that failed stays finished.
    assert!(e.next_blob_chunk(&mut stream).await.unwrap().is_none());
}

#[tokio::test]
async fn a_truncated_object_fails_the_stream_too() {
    let e = engine().await;
    let data = vec![9u8; 9000];
    let (id, _) = blob(&e, "user:1", &data).await;
    let access = e.open_blob(WHO, &domain(), &id).await.unwrap();
    let key = ObjectKey {
        domain_id: domain(),
        object_id: access.object_id,
    };
    let mut cut = e.objects().get(&key).await.unwrap().unwrap();
    cut.truncate(cut.len() - 1040);
    e.objects().put(&key, cut).await.unwrap();
    let mut stream = e.blob_stream(&access).await.unwrap();
    let mut failed = false;
    while let Ok(Some(_)) = e.next_blob_chunk(&mut stream).await {}
    if e.next_blob_chunk(&mut stream).await.is_err() {
        failed = true;
    }
    // Either the loop above hit the error (and the stream is now finished) or the final check does.
    let _ = failed;
    let mut stream = e.blob_stream(&access).await.unwrap();
    let mut outcome = Ok(());
    loop {
        match e.next_blob_chunk(&mut stream).await {
            Ok(Some(_)) => {}
            Ok(None) => break,
            Err(e) => {
                outcome = Err(e);
                break;
            }
        }
    }
    assert!(
        outcome.is_err(),
        "a truncated object was streamed as if it were whole"
    );
}

#[tokio::test]
async fn completion_checks_the_upload_without_reading_it() {
    let e = engine().await;
    let data = vec![1u8; 3000];
    let make = || async {
        e.create_blob(WHO, &domain(), &request("user:1", 3000))
            .await
            .unwrap()
    };

    // Nothing uploaded.
    let t = make().await;
    assert!(matches!(
        e.complete_blob(WHO, &domain(), &t.blob_id).await,
        Err(VaultError::Conflict(_))
    ));
    // The wrong size: one byte short, one byte long.
    let good = encrypt(&t, &data, 1000);
    for object in [
        good[..good.len() - 1].to_vec(),
        [good.clone(), vec![0]].concat(),
    ] {
        upload(&e, &t, object).await;
        assert!(matches!(
            e.complete_blob(WHO, &domain(), &t.blob_id).await,
            Err(VaultError::Conflict(_))
        ));
    }
    // The right size but encrypted under a different key: the header's commitment does not match.
    let mut other = encrypt(&t, &data, 1000);
    let wrong = BlobTicket {
        dek: zeroize::Zeroizing::new([0xee; 32]),
        ..clone_ticket(&t)
    };
    other = [
        encrypt(&wrong, &data, 1000)[..104].to_vec(),
        other[104..].to_vec(),
    ]
    .concat();
    upload(&e, &t, other).await;
    assert!(matches!(
        e.complete_blob(WHO, &domain(), &t.blob_id).await,
        Err(VaultError::Conflict(_))
    ));
    // A header for another object id.
    let moved = BlobTicket {
        object_id: [0x99; 16],
        ..clone_ticket(&t)
    };
    upload(&e, &t, encrypt(&moved, &data, 1000)).await;
    assert!(matches!(
        e.complete_blob(WHO, &domain(), &t.blob_id).await,
        Err(VaultError::Conflict(_))
    ));
    // A header with another chunk size is the same length only by luck; here it is refused either way.
    let rechunked = BlobTicket {
        chunk_size: 2048,
        ..clone_ticket(&t)
    };
    upload(&e, &t, encrypt(&rechunked, &data, 1000)).await;
    assert!(matches!(
        e.complete_blob(WHO, &domain(), &t.blob_id).await,
        Err(VaultError::Conflict(_))
    ));
    // The real thing finally completes.
    upload(&e, &t, good).await;
    e.complete_blob(WHO, &domain(), &t.blob_id).await.unwrap();
}

fn clone_ticket(t: &BlobTicket) -> BlobTicket {
    BlobTicket {
        blob_id: t.blob_id,
        domain_id: t.domain_id,
        object_id: t.object_id,
        dek_generation: t.dek_generation,
        chunk_size: t.chunk_size,
        suite: t.suite,
        dek: zeroize::Zeroizing::new(*t.dek),
    }
}

#[tokio::test]
async fn the_key_is_released_only_after_the_disclosure_is_written_and_a_failed_write_releases_nothing()
 {
    let e = engine().await;
    let (id, _) = blob(&e, "user:1", SECRET.as_bytes()).await;
    let before = e
        .store()
        .audit_records(&domain(), 0, 1000)
        .await
        .unwrap()
        .len();
    let caller = Caller {
        principal: "svc/user:77",
        caller: Some("user:77"),
        purpose: Some("kyc-review"),
        ..Caller::default()
    };
    e.open_blob(caller, &domain(), &id).await.unwrap();
    let rows = e.store().audit_records(&domain(), 0, 1000).await.unwrap();
    assert_eq!(rows.len(), before + 1);
    let last: serde_json::Value = serde_json::from_slice(&rows.last().unwrap().line).unwrap();
    assert_eq!(
        (last["type"].as_str(), last["body"]["action"].as_str()),
        (Some("read.grant"), Some("blob.access"))
    );
    assert_eq!(last["body"]["purpose"], "kyc-review");

    e.store().set_audit_failure(true);
    let got = e.open_blob(WHO, &domain(), &id).await;
    assert!(matches!(got, Err(VaultError::Unavailable(_))), "{got:?}");
    e.store().set_audit_failure(false);
}

#[tokio::test]
async fn a_blob_is_shredded_like_a_fact_and_its_object_goes() {
    let e = engine().await;
    let (a, _) = blob(&e, "alice", b"alice-document").await;
    let (b, _) = blob(&e, "bob", b"bob-document").await;
    let (c, _) = blob(&e, "carol", b"carol-document").await;
    assert_eq!(e.objects().object_count(), 3);

    e.shred_fact(WHO, &domain(), &a, Reason::Admin)
        .await
        .unwrap();
    assert_eq!(
        e.open_blob(WHO, &domain(), &a).await.map(|_| ()),
        Err(VaultError::Shredded)
    );
    assert_eq!(e.objects().object_count(), 2);
    e.shred_subject(WHO, &domain(), "bob", Reason::SubjectRequest)
        .await
        .unwrap();
    assert_eq!(
        e.open_blob(WHO, &domain(), &b).await.map(|_| ()),
        Err(VaultError::Shredded)
    );
    assert_eq!(e.objects().object_count(), 1);
    e.shred_scope(WHO, &domain(), "kyc-doc:1", Reason::Legal)
        .await
        .unwrap();
    assert_eq!(
        e.open_blob(WHO, &domain(), &c).await.map(|_| ()),
        Err(VaultError::Shredded)
    );
    assert_eq!(e.objects().object_count(), 0);
}

#[tokio::test]
async fn a_blob_is_not_a_fact_and_a_fact_is_not_a_blob() {
    let e = engine().await;
    let (id, _) = blob(&e, "user:1", b"x").await;
    assert!(matches!(
        e.read_fact(WHO, &domain(), &id).await,
        Err(VaultError::Conflict(_))
    ));
    let fact = e
        .create_fact(
            WHO,
            &domain(),
            &pvlt_core::engine::CreateFact {
                fact_id: None,
                subject: Some("u"),
                scope: "s",
                fact_type: "ascii",
                value: b"v",
                expires_at: None,
            },
        )
        .await
        .unwrap();
    assert!(matches!(
        e.open_blob(WHO, &domain(), &fact).await,
        Err(VaultError::Conflict(_))
    ));
    assert!(matches!(
        e.complete_blob(WHO, &domain(), &fact).await,
        Err(VaultError::Conflict(_))
    ));
}

#[tokio::test]
async fn an_abandoned_upload_expires_and_a_completed_blob_gets_the_expiry_it_asked_for() {
    let e = engine().await;
    let soon = OffsetDateTime::now_utc() + time::Duration::days(30);
    let t = e
        .create_blob(
            WHO,
            &domain(),
            &CreateBlob {
                expires_at: Some(soon),
                ..request("user:1", 10)
            },
        )
        .await
        .unwrap();
    let pending = e
        .store()
        .fact_for_read(&domain(), &t.blob_id)
        .await
        .unwrap()
        .fact
        .fact
        .expires_at
        .unwrap();
    let hours = (pending - OffsetDateTime::now_utc()).whole_hours();
    assert!(
        (23..=24).contains(&hours),
        "a pending blob expires in a day, not {hours} hours"
    );
    upload(&e, &t, encrypt(&t, &[1; 10], 10)).await;
    e.complete_blob(WHO, &domain(), &t.blob_id).await.unwrap();
    let done = e
        .store()
        .fact_for_read(&domain(), &t.blob_id)
        .await
        .unwrap()
        .fact
        .fact
        .expires_at
        .unwrap();
    assert_eq!(done, soon);
    // One with no expiry at all.
    let (id, _) = blob(&e, "user:2", b"forever").await;
    assert!(
        e.store()
            .fact_for_read(&domain(), &id)
            .await
            .unwrap()
            .fact
            .fact
            .expires_at
            .is_none()
    );
}

#[tokio::test]
async fn requests_are_validated_and_the_size_limit_holds() {
    let e = engine().await.with_max_blob_len(5000);
    for (name, r) in [
        (
            "an empty scope",
            CreateBlob {
                scope: "",
                ..request("u", 10)
            },
        ),
        (
            "an empty subject",
            CreateBlob {
                subject: Some(""),
                ..request("u", 10)
            },
        ),
        (
            "no type",
            CreateBlob {
                fact_type: "",
                ..request("u", 10)
            },
        ),
        ("too big", request("u", 5001)),
        (
            "a chunk size that is not a multiple of 1024",
            CreateBlob {
                chunk_size: 1000,
                ..request("u", 10)
            },
        ),
        (
            "a chunk size that is too big",
            CreateBlob {
                chunk_size: 32 * 1024 * 1024,
                ..request("u", 10)
            },
        ),
    ] {
        let got = e.create_blob(WHO, &domain(), &r).await;
        assert!(
            matches!(got, Err(VaultError::Invalid(_))),
            "{name}: {got:?}"
        );
    }
    assert!(
        e.create_blob(WHO, &domain(), &request("u", 5000))
            .await
            .is_ok()
    );
    // 0 means the default chunk size.
    let t = e
        .create_blob(
            WHO,
            &domain(),
            &CreateBlob {
                chunk_size: 0,
                ..request("u", 10)
            },
        )
        .await
        .unwrap();
    assert_eq!(t.chunk_size, 65_536);
}

#[tokio::test]
async fn the_ticket_key_is_not_stored_in_the_clear_and_a_shredded_subject_cannot_get_a_new_blob() {
    let e = engine().await;
    let (id, t) = blob(&e, "alice", b"v").await;
    let dump = e.store().dump();
    assert!(
        !dump.windows(32).any(|w| w == t.dek.as_slice()),
        "the data key is in the key store in the clear"
    );
    let _ = id;
    e.shred_subject(WHO, &domain(), "alice", Reason::SubjectRequest)
        .await
        .unwrap();
    assert_eq!(
        e.create_blob(WHO, &domain(), &request("alice", 10))
            .await
            .map(|_| ()),
        Err(VaultError::Shredded)
    );
}

#[tokio::test]
async fn a_restored_backup_re_shreds_a_blob_too() {
    let e = engine().await;
    let (id, _) = blob(&e, "alice", b"document").await;
    let backup = (e.store().snapshot(), e.objects().snapshot());
    e.shred_fact(WHO, &domain(), &id, Reason::SubjectRequest)
        .await
        .unwrap();
    // The restored system: the old key store and data bucket, the current ledger.
    for (path, _) in e.objects().list_prefix("ledger/").await.unwrap() {
        backup
            .1
            .put_path(&path, e.objects().get_path(&path).await.unwrap().unwrap())
            .await
            .unwrap();
    }
    let a = arena();
    let init = init_shamir(&a, 2, 3).unwrap();
    let _ = init;
    // Reuse the same keyring: the restored engine needs the same root key.
    let restored = Engine::new(
        Keyring::new(arena()),
        backup.0,
        backup.1,
        NullAuditor,
        Limits::default(),
    );
    // Sealed, it can still replay the ledger (no key is needed to destroy one).
    let report = restored.reconcile().await.unwrap();
    assert_eq!(report.replayed, 1);
    let bundle = restored
        .store()
        .fact_for_read(&domain(), &id)
        .await
        .unwrap();
    assert_eq!(bundle.fact.state, pvlt_core::store::State::Shredded);
}
