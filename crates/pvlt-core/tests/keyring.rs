//! The sealed and unsealed state of a vault.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, mpsc};
use std::time::Duration;

use common::{arena, id};
use pvlt_core::VaultError;
use pvlt_core::keyring::Keyring;
use pvlt_core::keys::{WrappedDomainKeys, WrappedRoot};
use pvlt_core::seal::{init_shamir, unseal_with_shares};

fn unsealed() -> (
    Keyring,
    WrappedDomainKeys,
    pvlt_core::seal::SealConfig,
    Vec<pvlt_core::seal::UnsealShare>,
) {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    let ring = Keyring::new(a);
    ring.unseal(init.root);
    let wrapped = ring.create_domain(&id(1)).unwrap();
    (ring, wrapped, init.config, init.shares)
}

fn zeroed(w: &WrappedDomainKeys) -> WrappedDomainKeys {
    WrappedDomainKeys {
        kek: vec![0; 107],
        ..w.clone()
    }
}

#[test]
fn a_new_keyring_is_sealed_and_refuses_everything() {
    let ring = Keyring::new(arena());
    assert!(ring.is_sealed());
    assert_eq!(ring.root_key_id().unwrap_err(), VaultError::Sealed);
    assert_eq!(ring.create_domain(&id(1)).unwrap_err(), VaultError::Sealed);
    let w = WrappedDomainKeys {
        kek_version: 1,
        kek: vec![],
        bik_version: 1,
        bik: vec![],
        bix_version: 1,
        bix: vec![],
    };
    assert_eq!(
        ring.with_domain(&id(1), &w, |_| Ok(())).unwrap_err(),
        VaultError::Sealed
    );
    assert!(
        !ring.seal(),
        "sealing a sealed vault reports that nothing happened"
    );
}

#[test]
fn unseal_with_shares_then_use_a_domain() {
    let a = arena();
    let init = init_shamir(&a, 3, 5).unwrap();
    let ring = Keyring::new(a.clone());
    let wrapped = {
        ring.unseal(init.root);
        ring.create_domain(&id(1)).unwrap()
    };
    ring.seal();

    // A restart: only the stored config, the stored wrapped domain keys and three shares remain.
    let picked: Vec<_> = [4, 0, 2]
        .iter()
        .map(|i| pvlt_core::seal::UnsealShare::from_text(&init.shares[*i].to_text()).unwrap())
        .collect();
    let root = unseal_with_shares(&a, &init.config, &picked).unwrap();
    let ring = Keyring::new(a);
    ring.unseal(root);
    assert!(!ring.is_sealed());
    let h = ring
        .with_domain(&id(1), &wrapped, |d| d.subject_hmac("user:1"))
        .unwrap();
    assert_ne!(h, [0; 32]);
}

#[test]
fn a_domain_survives_a_restart_with_the_same_blind_ids() {
    let (ring, wrapped, config, shares) = unsealed();
    let before = ring
        .with_domain(&id(1), &wrapped, |d| d.subject_hmac("user:1"))
        .unwrap();
    ring.seal();

    let a = arena();
    let picked: Vec<_> = [1, 3, 4]
        .iter()
        .map(|i| pvlt_core::seal::UnsealShare::from_text(&shares[*i].to_text()).unwrap())
        .collect();
    let fresh = Keyring::new(a.clone());
    fresh.unseal(unseal_with_shares(&a, &config, &picked).unwrap());
    let after = fresh
        .with_domain(&id(1), &wrapped, |d| d.subject_hmac("user:1"))
        .unwrap();
    assert_eq!(before, after);
}

#[test]
fn the_cache_is_used_for_identical_bytes() {
    let (ring, wrapped, ..) = unsealed();
    let first = ring
        .with_domain(&id(1), &wrapped, |d| Ok(std::ptr::from_ref(d) as usize))
        .unwrap();
    let again = ring
        .with_domain(&id(1), &wrapped, |d| Ok(std::ptr::from_ref(d) as usize))
        .unwrap();
    assert_eq!(first, again, "same bytes, same cached keys");
    assert_eq!(
        ring.arena().slots_in_use(),
        4,
        "root plus one domain's three keys; a hit allocates nothing"
    );
}

#[test]
fn a_shredded_domain_is_never_served_from_the_cache() {
    let (ring, wrapped, ..) = unsealed();
    ring.with_domain(&id(1), &wrapped, |_| Ok(())).unwrap();

    // The key store now holds zeros for the KEK: the cache must not paper over that.
    let gone = zeroed(&wrapped);
    assert_eq!(
        ring.with_domain(&id(1), &gone, |_| Ok(())).unwrap_err(),
        VaultError::Shredded
    );

    // And the failure evicted the entry: the cached keys are gone, so only a bundle that opens works again.
    assert_eq!(
        ring.arena().slots_in_use(),
        1,
        "the domain's keys were wiped, only the root remains"
    );
    assert_eq!(
        ring.with_domain(&id(1), &gone, |_| Ok(())).unwrap_err(),
        VaultError::Shredded
    );
    ring.with_domain(&id(1), &wrapped, |_| Ok(())).unwrap();
}

#[test]
fn changed_bytes_are_not_served_from_the_cache() {
    let (ring, wrapped, ..) = unsealed();
    let mut damaged = wrapped.clone();
    damaged.bik[80] ^= 1;
    assert_eq!(
        ring.with_domain(&id(1), &damaged, |_| Ok(())).unwrap_err(),
        VaultError::OpenFailed
    );
}

#[test]
fn a_bundle_for_another_domain_does_not_open() {
    let (ring, wrapped, ..) = unsealed();
    assert_eq!(
        ring.with_domain(&id(2), &wrapped, |_| Ok(())).unwrap_err(),
        VaultError::OpenFailed
    );
}

#[test]
fn sealing_wipes_every_key() {
    let (ring, wrapped, ..) = unsealed();
    ring.with_domain(&id(1), &wrapped, |_| Ok(())).unwrap();
    assert_eq!(ring.arena().slots_in_use(), 4);
    assert!(ring.seal());
    assert_eq!(
        ring.arena().slots_in_use(),
        0,
        "root, KEK, BIK and BIX are all gone"
    );
    assert!(ring.is_sealed());
    assert_eq!(
        ring.with_domain(&id(1), &wrapped, |_| Ok(())).unwrap_err(),
        VaultError::Sealed
    );
}

#[test]
fn unsealing_again_replaces_the_old_root() {
    let a = arena();
    let ring = Keyring::new(a.clone());
    let first = init_shamir(&a, 2, 3).unwrap();
    let first_id = *first.root.id();
    ring.unseal(first.root);
    let second = init_shamir(&a, 2, 3).unwrap();
    let second_id = *second.root.id();
    ring.unseal(second.root);
    assert_eq!(ring.root_key_id().unwrap(), second_id);
    assert_ne!(first_id, second_id);
    assert_eq!(a.slots_in_use(), 1, "the first root key was wiped");
}

#[test]
fn seal_waits_for_work_in_flight_and_no_key_outlives_it() {
    let (ring, wrapped, ..) = unsealed();
    let ring = Arc::new(ring);
    let finished = Arc::new(AtomicBool::new(false));
    let (started_tx, started_rx) = mpsc::channel();

    let worker = {
        let (ring, wrapped, finished) = (Arc::clone(&ring), wrapped.clone(), Arc::clone(&finished));
        std::thread::spawn(move || {
            ring.with_domain(&id(1), &wrapped, |d| {
                started_tx.send(()).unwrap();
                std::thread::sleep(Duration::from_millis(150));
                let h = d.subject_hmac("user:1")?;
                finished.store(true, Ordering::SeqCst);
                Ok(h)
            })
        })
    };

    started_rx.recv().unwrap();
    assert!(ring.seal());
    assert!(
        finished.load(Ordering::SeqCst),
        "seal returned while a closure was still using the keys"
    );
    assert!(
        worker.join().unwrap().is_ok(),
        "the in-flight call completed normally"
    );
    assert_eq!(ring.arena().slots_in_use(), 0);
    assert_eq!(
        ring.with_domain(&id(1), &wrapped, |_| Ok(())).unwrap_err(),
        VaultError::Sealed
    );
}

#[test]
fn many_threads_using_a_domain_while_it_is_sealed_and_unsealed() {
    let a = arena();
    let init = init_shamir(&a, 2, 3).unwrap();
    let ring = Arc::new(Keyring::new(a.clone()));
    ring.unseal(init.root);
    let wrapped = ring.create_domain(&id(1)).unwrap();

    // Re-unsealing needs a root key each time; keep unwrapped copies from the config and shares.
    let reunseal = |ring: &Keyring| {
        let picked: Vec<_> = [0, 1]
            .iter()
            .map(|i| pvlt_core::seal::UnsealShare::from_text(&init.shares[*i].to_text()).unwrap())
            .collect();
        ring.unseal(unseal_with_shares(&a, &init.config, &picked).unwrap());
    };

    std::thread::scope(|s| {
        for _ in 0..6 {
            let (ring, wrapped) = (Arc::clone(&ring), wrapped.clone());
            s.spawn(move || {
                for _ in 0..300 {
                    match ring.with_domain(&id(1), &wrapped, |d| d.subject_hmac("user:1")) {
                        Ok(_) | Err(VaultError::Sealed) => {}
                        Err(e) => panic!("unexpected error: {e}"),
                    }
                }
            });
        }
        for _ in 0..20 {
            ring.seal();
            reunseal(&ring);
        }
    });
    assert!(!ring.is_sealed());
    assert!(ring.with_domain(&id(1), &wrapped, |_| Ok(())).is_ok());
}

#[test]
fn wrapped_root_in_the_config_is_the_only_root_material_kept() {
    let (_ring, _w, config, _shares) = unsealed();
    let WrappedRoot { wrapped, .. } = config.root;
    assert_eq!(wrapped.len(), 107);
    // The config is ciphertext: it is safe to hold in a key store (PLAN.md 3.6).
}
