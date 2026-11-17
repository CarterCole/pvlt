//! The bucket behaves as the engine needs, on memory and on a local directory, and the engine works over it.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pvlt_core::VaultError;
use pvlt_core::audit::NullAuditor;
use pvlt_core::engine::{CreateFact, Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::ledger::Reason;
use pvlt_core::memory::MemKeyStore;
use pvlt_core::objects::{ObjectKey, ObjectStore};
use pvlt_core::seal::init_shamir;
use pvlt_mem::{Arena, LockPolicy};
use pvlt_objects::{Bucket, S3Config};

fn key(domain: u8, object: u8) -> ObjectKey {
    ObjectKey {
        domain_id: [domain; 16],
        object_id: [object; 16],
    }
}

struct TempDir(std::path::PathBuf);

impl TempDir {
    fn new(tag: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("pvlt-objects-{tag}-{}-{nanos}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn behaves_like_a_bucket(bucket: &Bucket) {
    bucket.ping().await.unwrap();
    let (a, b, other_domain) = (key(1, 1), key(1, 2), key(2, 1));
    assert_eq!(bucket.get(&a).await.unwrap(), None);

    bucket.put(&a, vec![1, 2, 3]).await.unwrap();
    bucket.put(&b, vec![4]).await.unwrap();
    bucket.put(&other_domain, vec![5]).await.unwrap();
    assert_eq!(bucket.get(&a).await.unwrap(), Some(vec![1, 2, 3]));
    // A second write replaces.
    bucket.put(&a, vec![9, 9]).await.unwrap();
    assert_eq!(bucket.get(&a).await.unwrap(), Some(vec![9, 9]));

    let mut listed = bucket.list(&[1; 16]).await.unwrap();
    listed.sort_by_key(|m| m.key);
    assert_eq!(listed.iter().map(|m| m.key).collect::<Vec<_>>(), [a, b]);
    assert_eq!(listed[0].size, 2);
    let age = time::OffsetDateTime::now_utc() - listed[0].last_modified;
    assert!(
        age < time::Duration::minutes(1),
        "last_modified is {age} old"
    );
    assert!(bucket.list(&[3; 16]).await.unwrap().is_empty());

    bucket.delete(&a).await.unwrap();
    bucket.delete(&a).await.unwrap(); // already gone: not an error
    assert_eq!(bucket.get(&a).await.unwrap(), None);
    assert_eq!(bucket.get(&other_domain).await.unwrap(), Some(vec![5]));

    // Log files, by path.
    let ledger = |n: u64| format!("ledger/{}/{n:020}.json", "01".repeat(16));
    bucket.put_path(&ledger(0), b"zero".to_vec()).await.unwrap();
    bucket.put_path(&ledger(1), b"one".to_vec()).await.unwrap();
    bucket
        .put_path("ledger/other/00000000000000000000.json", b"x".to_vec())
        .await
        .unwrap();
    assert_eq!(
        bucket.get_path(&ledger(1)).await.unwrap(),
        Some(b"one".to_vec())
    );
    let mut paths: Vec<String> = bucket
        .list_prefix(&format!("ledger/{}/", "01".repeat(16)))
        .await
        .unwrap()
        .into_iter()
        .map(|(p, _)| p)
        .collect();
    paths.sort();
    assert_eq!(
        paths,
        [ledger(0), ledger(1)],
        "a prefix must not match a sibling"
    );
    // Sealed objects and log files do not show up in each other's listings.
    assert_eq!(bucket.list(&[1; 16]).await.unwrap().len(), 1);
    bucket.delete_path(&ledger(0)).await.unwrap();
    bucket.delete_path(&ledger(0)).await.unwrap();
    assert_eq!(bucket.get_path(&ledger(0)).await.unwrap(), None);

    // Size and ranges, without reading the whole object.
    let big: Vec<u8> = (0..5000u32).map(|i| (i % 251) as u8).collect();
    let k = key(1, 9);
    bucket.put(&k, big.clone()).await.unwrap();
    assert_eq!(bucket.head_path(&k.path()).await.unwrap(), Some(5000));
    assert_eq!(bucket.head_path("v1/none").await.unwrap(), None);
    let range = |start, len| {
        let (b, p) = (bucket, k.path());
        async move { b.get_range(&p, start, len).await.unwrap() }
    };
    assert_eq!(range(0, 104).await, Some(big[..104].to_vec()));
    assert_eq!(range(1000, 1040).await, Some(big[1000..2040].to_vec()));
    assert_eq!(
        range(4990, 100).await,
        Some(big[4990..].to_vec()),
        "a range past the end returns what is there"
    );
    assert_eq!(
        range(6000, 10).await,
        Some(Vec::new()),
        "a range wholly past the end is empty"
    );
    assert_eq!(bucket.get_range("v1/none", 0, 10).await.unwrap(), None);
    // Memory and a directory cannot make presigned URLs.
    assert_eq!(
        bucket
            .presign_put(&k.path(), std::time::Duration::from_secs(60))
            .await
            .unwrap(),
        None
    );
    assert_eq!(
        bucket
            .presign_get(&k.path(), std::time::Duration::from_secs(60))
            .await
            .unwrap(),
        None
    );
}

#[tokio::test]
async fn an_s3_bucket_makes_presigned_urls_that_hold_the_path_the_expiry_and_a_signature_but_no_secret()
 {
    let bucket = Bucket::s3(&S3Config {
        bucket: "vault".into(),
        region: "us-east-1".into(),
        endpoint: Some("https://s3.example.com".into()),
        access_key_id: "AKIDEXAMPLE".into(),
        secret_access_key: "very-secret-key-do-not-leak".into(),
        allow_http: false,
        path_style: true,
    })
    .unwrap();
    let k = key(0xab, 0x01);
    let put = bucket
        .presign_put(&k.path(), std::time::Duration::from_secs(900))
        .await
        .unwrap()
        .unwrap();
    let get = bucket
        .presign_get(&k.path(), std::time::Duration::from_secs(900))
        .await
        .unwrap()
        .unwrap();
    for url in [&put, &get] {
        assert!(url.starts_with("https://s3.example.com/vault/v1/"), "{url}");
        assert!(url.contains(&k.path()), "{url}");
        assert!(url.contains("X-Amz-Expires=900"), "{url}");
        assert!(url.contains("X-Amz-Signature="), "{url}");
        assert!(url.contains("X-Amz-Credential=AKIDEXAMPLE"), "{url}");
        assert!(
            !url.contains("very-secret-key"),
            "the secret key is in the URL"
        );
    }
    assert_ne!(put, get, "a PUT URL is signed for PUT, not GET");
    // The bucket's own debug output and its error text never carry the secret.
    assert!(!format!("{bucket:?}").contains("very-secret-key"));
}

#[tokio::test]
async fn memory_bucket() {
    behaves_like_a_bucket(&Bucket::in_memory()).await;
}

#[tokio::test]
async fn directory_bucket() {
    let dir = TempDir::new("dir");
    behaves_like_a_bucket(&Bucket::local_dir(&dir.0).unwrap()).await;
}

#[tokio::test]
async fn a_listing_ignores_files_this_layout_did_not_write() {
    let dir = TempDir::new("foreign");
    let bucket = Bucket::local_dir(&dir.0).unwrap();
    bucket.put(&key(1, 1), vec![1]).await.unwrap();
    // Something else in the domain's prefix, which a sweeper must never delete.
    let prefix = dir.0.join(format!("v1/{}", hex(&[1; 16])));
    std::fs::write(prefix.join("README"), b"not ours").unwrap();
    std::fs::create_dir_all(prefix.join("zz")).unwrap();
    std::fs::write(prefix.join("zz").join("stray"), b"not ours").unwrap();
    let listed = bucket.list(&[1; 16]).await.unwrap();
    assert_eq!(listed.len(), 1);
    assert_eq!(listed[0].key, key(1, 1));
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test]
async fn nothing_but_the_layout_names_appear_on_disk() {
    let dir = TempDir::new("layout");
    let bucket = Bucket::local_dir(&dir.0).unwrap();
    bucket
        .put(&key(0xab, 0x01), b"secret-value".to_vec())
        .await
        .unwrap();
    let mut files = Vec::new();
    let mut stack = vec![dir.0.clone()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                files.push(
                    p.strip_prefix(&dir.0)
                        .unwrap()
                        .to_string_lossy()
                        .into_owned(),
                );
            }
        }
    }
    assert_eq!(
        files,
        [format!("v1/{}/01/{}", hex(&[0xab; 16]), hex(&[0x01; 16]))]
    );
}

#[tokio::test]
async fn the_engine_works_over_a_directory_bucket_and_a_shred_leaves_nothing_in_it() {
    let dir = TempDir::new("engine");
    let arena = Arena::new(256, LockPolicy::BestEffort).unwrap();
    let init = init_shamir(&arena, 2, 3).unwrap();
    let ring = Keyring::new(arena);
    ring.unseal(init.root);
    let engine = Engine::new(
        ring,
        MemKeyStore::new(),
        Bucket::local_dir(&dir.0).unwrap(),
        NullAuditor,
        Limits::default(),
    );
    let domain = [7u8; 16];
    engine.ensure_domain(&domain).await.unwrap();
    let request = CreateFact {
        fact_id: None,
        subject: Some("alice"),
        scope: "kyc",
        fact_type: "ascii",
        value: b"on-disk-secret-value",
        expires_at: None,
    };
    let fact_id = engine.create_fact("t", &domain, &request).await.unwrap();
    assert_eq!(
        engine
            .read_fact("t", &domain, &fact_id)
            .await
            .unwrap()
            .value
            .as_slice(),
        b"on-disk-secret-value"
    );
    assert_eq!(engine.objects().list(&domain).await.unwrap().len(), 1);

    engine
        .shred_fact("t", &domain, &fact_id, Reason::Admin)
        .await
        .unwrap();
    assert!(engine.objects().list(&domain).await.unwrap().is_empty());
    assert_eq!(
        engine.read_fact("t", &domain, &fact_id).await.map(|_| ()),
        Err(VaultError::Shredded)
    );
}
