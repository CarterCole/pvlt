//! Auto-unseal, with a stand-in KMS: enrolment, the unseal at start, and every way it must refuse.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use pvlt_core::audit::NullAuditor;
use pvlt_core::engine::{Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::memory::{MemKeyStore, MemObjectStore};
use pvlt_core::seal::{UnsealShare, init_shamir, unseal_key_from_shares};
use pvlt_mem::{Arena, LockPolicy};
use pvlt_server::app::App;
use pvlt_server::kms::{self, KmsError, UnsealKms};
use pvlt_server::pg::KmsSeal;

fn arena() -> Arena {
    Arena::new(256, LockPolicy::BestEffort).unwrap()
}

/// A KMS that behaves like the real one where it matters: the ciphertext is bound to the key id and the
/// encryption context, and it can be switched off.
struct FakeKms {
    key_id: String,
    pad: [u8; 32],
    up: Arc<AtomicBool>,
}

impl FakeKms {
    fn new(key_id: &str) -> Self {
        Self {
            key_id: key_id.into(),
            pad: [0x5a; 32],
            up: Arc::new(AtomicBool::new(true)),
        }
    }
    fn tag(&self, context: &[(&'static str, String)]) -> Vec<u8> {
        let mut t = self.key_id.clone().into_bytes();
        for (k, v) in context {
            t.extend_from_slice(format!("|{k}={v}").as_bytes());
        }
        t.push(b'#');
        t
    }
}

impl UnsealKms for FakeKms {
    fn provider(&self) -> &'static str {
        "aws-kms"
    }
    fn key_id(&self) -> &str {
        &self.key_id
    }
    async fn encrypt(
        &self,
        plaintext: &[u8],
        context: &[(&'static str, String)],
    ) -> Result<Vec<u8>, KmsError> {
        if !self.up.load(Ordering::SeqCst) {
            return Err(KmsError::new("the KMS is unreachable", "down"));
        }
        let mut out = self.tag(context);
        out.extend(plaintext.iter().zip(self.pad.iter()).map(|(a, b)| a ^ b));
        Ok(out)
    }
    async fn decrypt(
        &self,
        wrapped: &[u8],
        context: &[(&'static str, String)],
    ) -> Result<Vec<u8>, KmsError> {
        if !self.up.load(Ordering::SeqCst) {
            return Err(KmsError::new("the KMS is unreachable", "down"));
        }
        let tag = self.tag(context);
        let body = wrapped
            .strip_prefix(tag.as_slice())
            .ok_or_else(|| KmsError::new("the KMS refused to unwrap the unseal key", "context"))?;
        Ok(body
            .iter()
            .zip(self.pad.iter())
            .map(|(a, b)| a ^ b)
            .collect())
    }
}

type TestApp = App<MemKeyStore, MemObjectStore, NullAuditor>;

struct Vault {
    app: Arc<TestApp>,
    shares: Vec<String>,
    config: pvlt_core::seal::SealConfig,
}

/// A sealed vault: the root key is wrapped, nothing is open.
fn sealed_vault() -> Vault {
    let a = arena();
    let init = init_shamir(&a, 2, 3).unwrap();
    let shares = init
        .shares
        .iter()
        .map(|s| s.to_text().as_str().to_owned())
        .collect();
    let config = init.config.clone();
    let engine = Engine::new(
        Keyring::new(a),
        MemKeyStore::new(),
        MemObjectStore::new(),
        NullAuditor,
        Limits {
            max_value_len: 1024,
        },
    );
    let app = Arc::new(App::new(engine, [3; 16], None, None, init.config));
    Vault {
        app,
        shares,
        config,
    }
}

fn unseal_key(v: &Vault, which: &[usize]) -> pvlt_core::seal::UnsealKey {
    let shares: Vec<UnsealShare> = which
        .iter()
        .map(|i| UnsealShare::from_text(&v.shares[*i]).unwrap())
        .collect();
    unseal_key_from_shares(&arena(), &v.config, &shares).unwrap()
}

async fn enrolled(v: &Vault, kms: &FakeKms) -> KmsSeal {
    kms::enroll(kms, &v.config.root.id, &unseal_key(v, &[0, 2]))
        .await
        .unwrap()
}

#[tokio::test]
async fn an_enrolled_vault_unseals_itself_and_the_shares_still_work() {
    let v = sealed_vault();
    let kms = FakeKms::new("alias/pvlt-unseal");
    let seal = enrolled(&v, &kms).await;
    assert!(v.app.unseal_status().sealed);
    kms::try_unseal(&v.app, &kms, &seal).await.unwrap();
    assert!(!v.app.unseal_status().sealed);

    // Sealing on purpose and unsealing with shares still works: the KMS never became the only way in.
    v.app.seal();
    assert!(v.app.unseal_status().sealed);
    v.app.submit_share(&v.shares[1]).unwrap();
    let status = v.app.submit_share(&v.shares[2]).unwrap();
    assert!(!status.sealed);
}

#[tokio::test]
async fn the_stored_record_holds_no_key_and_is_not_the_unseal_key() {
    let v = sealed_vault();
    let kms = FakeKms::new("alias/pvlt-unseal");
    let seal = enrolled(&v, &kms).await;
    let key = unseal_key(&v, &[0, 1]);
    assert_ne!(seal.wrapped.as_slice(), key.expose().as_slice());
    assert!(
        !seal
            .wrapped
            .windows(32)
            .any(|w| w == key.expose().as_slice())
    );
    assert_eq!(seal.provider, "aws-kms");
    assert_eq!(seal.key_id, "alias/pvlt-unseal");
}

#[tokio::test]
async fn a_record_for_another_vault_or_another_kms_key_is_refused_before_any_call() {
    let v = sealed_vault();
    let other = sealed_vault();
    let kms = FakeKms::new("alias/pvlt-unseal");
    let theirs = enrolled(&other, &kms).await;
    let err = kms::try_unseal(&v.app, &kms, &theirs).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "the stored auto-unseal record is for a different vault"
    );
    assert!(v.app.unseal_status().sealed);

    let mine = enrolled(&v, &kms).await;
    let wrong_key = FakeKms::new("alias/someone-else");
    let err = kms::try_unseal(&v.app, &wrong_key, &mine)
        .await
        .unwrap_err();
    assert!(err.to_string().contains("different KMS key"));
    assert!(v.app.unseal_status().sealed);
}

#[tokio::test]
async fn a_ciphertext_moved_to_another_vault_does_not_open_it() {
    // Same KMS key, so the key id matches; only the encryption context differs. This is the copy-paste attack.
    let v = sealed_vault();
    let other = sealed_vault();
    let kms = FakeKms::new("alias/pvlt-unseal");
    let theirs = enrolled(&other, &kms).await;
    let forged = KmsSeal {
        root_key_id: v.config.root.id,
        ..theirs
    };
    let err = kms::try_unseal(&v.app, &kms, &forged).await.unwrap_err();
    assert_eq!(err.to_string(), "the KMS refused to unwrap the unseal key");
    assert!(v.app.unseal_status().sealed);
}

#[tokio::test]
async fn a_key_that_does_not_open_the_root_key_leaves_it_sealed() {
    // A KMS that returns a different 32 bytes than were enrolled.
    let v = sealed_vault();
    let kms = FakeKms::new("alias/pvlt-unseal");
    let mut seal = enrolled(&v, &kms).await;
    let last = seal.wrapped.len() - 1;
    seal.wrapped[last] ^= 0xff;
    let err = kms::try_unseal(&v.app, &kms, &seal).await.unwrap_err();
    assert_eq!(
        err.to_string(),
        "the unseal key from the KMS did not open the root key"
    );
    assert!(v.app.unseal_status().sealed);
}

#[tokio::test]
async fn a_kms_outage_leaves_it_sealed_then_recovers_when_the_kms_returns() {
    let v = sealed_vault();
    let kms = FakeKms::new("alias/pvlt-unseal");
    let seal = enrolled(&v, &kms).await;
    kms.up.store(false, Ordering::SeqCst);
    let err = kms::try_unseal(&v.app, &kms, &seal).await.unwrap_err();
    assert_eq!(err.to_string(), "the KMS is unreachable");
    assert!(v.app.unseal_status().sealed);

    let up = Arc::clone(&kms.up);
    let task = tokio::spawn(kms::keep_trying(
        Arc::clone(&v.app),
        kms,
        seal,
        Duration::from_millis(20),
    ));
    tokio::time::sleep(Duration::from_millis(80)).await;
    assert!(v.app.unseal_status().sealed, "still down, still sealed");
    up.store(true, Ordering::SeqCst);
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("keeps trying until the KMS answers")
        .unwrap();
    assert!(!v.app.unseal_status().sealed);
}

#[tokio::test]
async fn retries_stop_when_someone_unseals_by_hand() {
    let v = sealed_vault();
    let kms = FakeKms::new("alias/pvlt-unseal");
    let seal = enrolled(&v, &kms).await;
    kms.up.store(false, Ordering::SeqCst);
    let task = tokio::spawn(kms::keep_trying(
        Arc::clone(&v.app),
        kms,
        seal,
        Duration::from_millis(20),
    ));
    v.app.submit_share(&v.shares[0]).unwrap();
    v.app.submit_share(&v.shares[1]).unwrap();
    tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("stops once unsealed")
        .unwrap();
}

#[test]
fn enrolment_needs_enough_good_shares_from_this_vault() {
    let v = sealed_vault();
    let other = sealed_vault();
    let one = [UnsealShare::from_text(&v.shares[0]).unwrap()];
    assert!(unseal_key_from_shares(&arena(), &v.config, &one).is_err());
    let foreign = [
        UnsealShare::from_text(&other.shares[0]).unwrap(),
        UnsealShare::from_text(&other.shares[1]).unwrap(),
    ];
    assert!(unseal_key_from_shares(&arena(), &v.config, &foreign).is_err());
}
