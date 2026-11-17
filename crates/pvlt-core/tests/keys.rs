//! The key hierarchy: what opens, what must not, and what shredding does at each level.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

mod common;

use common::{arena, id};
use pvlt_core::VaultError;
use pvlt_core::keys::{
    DomainKeys, EphemeralKey, KeyMaterial, RootKey, WrappedDek, WrappedDomainKeys, WrappedRoot,
    WrappedSubjectKey,
};
use pvlt_format::{Suite, blob, fact};

fn zeroed() -> Vec<u8> {
    vec![0; 107]
}

fn flip(mut v: Vec<u8>, at: usize) -> Vec<u8> {
    v[at] ^= 1;
    v
}

// --- Root key --------------------------------------------------------------------------------------------

#[test]
fn root_key_round_trips_through_the_unseal_key() {
    let a = arena();
    let unseal = EphemeralKey::random().unwrap();
    let root = RootKey::generate(&a).unwrap();
    let wrapped = root.wrap(&unseal).unwrap();
    assert_eq!(wrapped.wrapped.len(), 107);
    let opened = RootKey::unwrap(&a, &unseal, &wrapped).unwrap();
    assert_eq!(opened.expose(), root.expose());
    assert_eq!((opened.id(), opened.version()), (root.id(), 1));
}

#[test]
fn root_key_does_not_open_with_the_wrong_key_or_a_changed_record() {
    let a = arena();
    let unseal = EphemeralKey::random().unwrap();
    let root = RootKey::generate(&a).unwrap();
    let w = root.wrap(&unseal).unwrap();

    let other = EphemeralKey::random().unwrap();
    assert_eq!(
        RootKey::unwrap(&a, &other, &w).unwrap_err(),
        VaultError::OpenFailed
    );
    let moved = WrappedRoot {
        id: id(9),
        ..w.clone()
    };
    assert_eq!(
        RootKey::unwrap(&a, &unseal, &moved).unwrap_err(),
        VaultError::OpenFailed,
        "id is bound"
    );
    let bumped = WrappedRoot {
        version: 2,
        ..w.clone()
    };
    assert_eq!(
        RootKey::unwrap(&a, &unseal, &bumped).unwrap_err(),
        VaultError::OpenFailed,
        "version is bound"
    );
    for at in [0, 5, 30, 70, 106] {
        let damaged = WrappedRoot {
            wrapped: flip(w.wrapped.clone(), at),
            ..w.clone()
        };
        assert!(RootKey::unwrap(&a, &unseal, &damaged).is_err(), "byte {at}");
    }
    let gone = WrappedRoot {
        wrapped: zeroed(),
        ..w
    };
    assert_eq!(
        RootKey::unwrap(&a, &unseal, &gone).unwrap_err(),
        VaultError::Shredded
    );
}

#[test]
fn each_root_key_is_different() {
    let a = arena();
    let (r1, r2) = (
        RootKey::generate(&a).unwrap(),
        RootKey::generate(&a).unwrap(),
    );
    assert_ne!(r1.expose(), r2.expose());
    assert_ne!(r1.id(), r2.id());
}

// --- Domain keys -----------------------------------------------------------------------------------------

fn domain_setup() -> (pvlt_mem::Arena, RootKey, DomainKeys, WrappedDomainKeys) {
    let a = arena();
    let root = RootKey::generate(&a).unwrap();
    let (keys, wrapped) = DomainKeys::create(&a, &root, &id(1)).unwrap();
    (a, root, keys, wrapped)
}

#[test]
fn domain_keys_round_trip_and_give_the_same_blind_ids() {
    let (a, root, keys, wrapped) = domain_setup();
    let opened = DomainKeys::unwrap(&a, &root, &id(1), &wrapped).unwrap();
    assert_eq!(
        opened.subject_hmac("user:1234").unwrap(),
        keys.subject_hmac("user:1234").unwrap()
    );
    assert_eq!(
        opened.scope_hmac("kyc-doc:1").unwrap(),
        keys.scope_hmac("kyc-doc:1").unwrap()
    );
    assert_eq!(
        opened.index_value("id-doc", b"X1").unwrap(),
        keys.index_value("id-doc", b"X1").unwrap()
    );
    assert_eq!(
        (
            opened.kek_version(),
            opened.bik_version(),
            opened.bix_version()
        ),
        (1, 1, 1)
    );
    assert_eq!(opened.domain_id(), &id(1));
}

#[test]
fn domain_keys_are_bound_to_their_domain_and_root() {
    let (a, root, _keys, wrapped) = domain_setup();
    assert_eq!(
        DomainKeys::unwrap(&a, &root, &id(2), &wrapped).unwrap_err(),
        VaultError::OpenFailed,
        "domain"
    );
    let other_root = RootKey::generate(&a).unwrap();
    assert_eq!(
        DomainKeys::unwrap(&a, &other_root, &id(1), &wrapped).unwrap_err(),
        VaultError::OpenFailed,
        "root"
    );
    let bumped = WrappedDomainKeys {
        kek_version: 2,
        ..wrapped.clone()
    };
    assert_eq!(
        DomainKeys::unwrap(&a, &root, &id(1), &bumped).unwrap_err(),
        VaultError::OpenFailed,
        "version"
    );
}

#[test]
fn wrapped_domain_keys_cannot_be_swapped_between_slots() {
    let (a, root, _keys, w) = domain_setup();
    for swapped in [
        WrappedDomainKeys {
            kek: w.bik.clone(),
            bik: w.kek.clone(),
            ..w.clone()
        },
        WrappedDomainKeys {
            bik: w.bix.clone(),
            bix: w.bik.clone(),
            ..w.clone()
        },
        WrappedDomainKeys {
            kek: w.bix.clone(),
            ..w.clone()
        },
    ] {
        assert_eq!(
            DomainKeys::unwrap(&a, &root, &id(1), &swapped).unwrap_err(),
            VaultError::OpenFailed
        );
    }
}

#[test]
fn blind_ids_differ_by_domain_and_are_stable_within_one() {
    let a = arena();
    let root = RootKey::generate(&a).unwrap();
    let (d1, _) = DomainKeys::create(&a, &root, &id(1)).unwrap();
    let (d2, _) = DomainKeys::create(&a, &root, &id(2)).unwrap();
    assert_eq!(
        d1.subject_hmac("user:1").unwrap(),
        d1.subject_hmac("user:1").unwrap()
    );
    assert_ne!(
        d1.subject_hmac("user:1").unwrap(),
        d2.subject_hmac("user:1").unwrap()
    );
    assert_ne!(
        d1.subject_hmac("user:1").unwrap(),
        d1.subject_hmac("user:2").unwrap()
    );
    assert_ne!(
        d1.subject_hmac("x").unwrap(),
        d1.pseudo_subject_hmac("x").unwrap()
    );
    assert_ne!(d1.subject_hmac("x").unwrap(), d1.scope_hmac("x").unwrap());
    assert_eq!(
        d1.subject_hmac("Zo\u{eb}").unwrap(),
        d1.subject_hmac("Zoe\u{308}").unwrap(),
        "NFC"
    );
    assert_eq!(
        d1.subject_hmac(&"x".repeat(1025)).unwrap_err(),
        VaultError::Invalid("subject or scope longer than 1024 bytes")
    );
}

#[test]
fn damaged_domain_keys_do_not_open() {
    let (a, root, _k, w) = domain_setup();
    for which in 0..3 {
        let mut d = w.clone();
        let field = match which {
            0 => &mut d.kek,
            1 => &mut d.bik,
            _ => &mut d.bix,
        };
        *field = flip(field.clone(), 80);
        assert!(DomainKeys::unwrap(&a, &root, &id(1), &d).is_err());
    }
    let gone = WrappedDomainKeys { kek: zeroed(), ..w };
    assert_eq!(
        DomainKeys::unwrap(&a, &root, &id(1), &gone).unwrap_err(),
        VaultError::Shredded
    );
}

// --- Subject keys and data keys --------------------------------------------------------------------------

struct Fixture {
    domain: DomainKeys,
}

fn fixture() -> Fixture {
    let a = arena();
    let root = RootKey::generate(&a).unwrap();
    let (domain, _) = DomainKeys::create(&a, &root, &id(1)).unwrap();
    Fixture { domain }
}

#[test]
fn subject_key_and_dek_round_trip() {
    let f = fixture();
    let sh = f.domain.subject_hmac("user:1234").unwrap();
    let (sk, wsk) = f.domain.new_subject_key(&sh, 1).unwrap();
    let (dek, wdek) = sk.new_dek(&id(5), 0).unwrap();

    let sk2 = f.domain.unwrap_subject_key(&sh, &wsk).unwrap();
    assert_eq!(sk2.expose(), sk.expose());
    let dek2 = sk2.unwrap_dek(&id(5), &wdek).unwrap();
    assert_eq!(dek2.expose(), dek.expose());
    assert_eq!(
        (dek2.object_id(), dek2.generation(), dek2.domain_id()),
        (&id(5), 0, &id(1))
    );
}

#[test]
fn a_subject_key_is_bound_to_its_subject_domain_and_version() {
    let f = fixture();
    let sh = f.domain.subject_hmac("user:1").unwrap();
    let other = f.domain.subject_hmac("user:2").unwrap();
    let (_sk, wsk) = f.domain.new_subject_key(&sh, 1).unwrap();

    assert_eq!(
        f.domain.unwrap_subject_key(&other, &wsk).unwrap_err(),
        VaultError::OpenFailed,
        "another subject"
    );
    let bumped = WrappedSubjectKey {
        version: 2,
        ..wsk.clone()
    };
    assert_eq!(
        f.domain.unwrap_subject_key(&sh, &bumped).unwrap_err(),
        VaultError::OpenFailed,
        "version"
    );
    let wrong_kek = WrappedSubjectKey {
        kek_version: 9,
        ..wsk.clone()
    };
    assert!(matches!(
        f.domain.unwrap_subject_key(&sh, &wrong_kek),
        Err(VaultError::Invalid(_))
    ));

    let a = arena();
    let root = RootKey::generate(&a).unwrap();
    let (elsewhere, _) = DomainKeys::create(&a, &root, &id(1)).unwrap();
    assert_eq!(
        elsewhere.unwrap_subject_key(&sh, &wsk).unwrap_err(),
        VaultError::OpenFailed,
        "another domain's KEK"
    );
}

#[test]
fn a_dek_is_bound_to_its_object_generation_and_subject() {
    let f = fixture();
    let (ha, hb) = (
        f.domain.subject_hmac("a").unwrap(),
        f.domain.subject_hmac("b").unwrap(),
    );
    let (ska, _) = f.domain.new_subject_key(&ha, 1).unwrap();
    let (skb, _) = f.domain.new_subject_key(&hb, 1).unwrap();
    let (_dek, wdek) = ska.new_dek(&id(5), 0).unwrap();

    assert_eq!(
        ska.unwrap_dek(&id(6), &wdek).unwrap_err(),
        VaultError::OpenFailed,
        "another object"
    );
    let regen = WrappedDek {
        generation: 1,
        ..wdek.clone()
    };
    assert_eq!(
        ska.unwrap_dek(&id(5), &regen).unwrap_err(),
        VaultError::OpenFailed,
        "another generation"
    );
    assert_eq!(
        skb.unwrap_dek(&id(5), &wdek).unwrap_err(),
        VaultError::OpenFailed,
        "another subject's key"
    );
    let stale = WrappedDek {
        subject_key_version: 7,
        ..wdek
    };
    assert!(matches!(
        ska.unwrap_dek(&id(5), &stale),
        Err(VaultError::Invalid(_))
    ));
}

#[test]
fn every_key_is_fresh() {
    let f = fixture();
    let sh = f.domain.subject_hmac("a").unwrap();
    let (sk, w1) = f.domain.new_subject_key(&sh, 1).unwrap();
    let (sk2, _) = f.domain.new_subject_key(&sh, 1).unwrap();
    assert_ne!(sk.expose(), sk2.expose());
    let (d1, wd1) = sk.new_dek(&id(5), 0).unwrap();
    let (d2, wd2) = sk.new_dek(&id(5), 0).unwrap();
    assert_ne!(d1.expose(), d2.expose());
    assert_ne!(wd1.wrapped, wd2.wrapped, "a fresh salt per wrap");
    assert_ne!(
        w1.wrapped,
        f.domain.new_subject_key(&sh, 1).unwrap().1.wrapped
    );
}

// --- Crypto-shredding through the whole hierarchy --------------------------------------------------------

/// Seals a fact and a blob under a subject, then shreds at each level and checks what is left readable.
#[test]
fn shredding_a_subject_key_makes_its_objects_unreadable() {
    let a = arena();
    let root = RootKey::generate(&a).unwrap();
    let (domain, _) = DomainKeys::create(&a, &root, &id(1)).unwrap();
    let alice = domain.subject_hmac("user:alice").unwrap();
    let bob = domain.subject_hmac("user:bob").unwrap();
    let (ska, wska) = domain.new_subject_key(&alice, 1).unwrap();
    let (skb, wskb) = domain.new_subject_key(&bob, 1).unwrap();

    let seal_fact = |sk: &pvlt_core::keys::SubjectKey, oid: u8, text: &[u8]| {
        let (dek, wdek) = sk.new_dek(&id(oid), 0).unwrap();
        let object = fact::seal(
            dek.expose(),
            Suite::XChaCha20Poly1305,
            dek.domain_id(),
            dek.object_id(),
            dek.generation(),
            &[oid; 24],
            text,
        )
        .unwrap();
        (wdek, object)
    };
    let (wd_a, obj_a) = seal_fact(&ska, 10, b"Alice Example");
    let (wd_b, obj_b) = seal_fact(&skb, 11, b"Bob Example");
    let (dek_blob, wd_blob) = ska.new_dek(&id(12), 0).unwrap();
    let blob_obj = blob::seal(
        dek_blob.expose(),
        Suite::Aes256Gcm,
        &id(1),
        &id(12),
        0,
        blob::CHUNK_MIN,
        &[12; 24],
        &[0x42; 3000],
    )
    .unwrap();

    let read = |wsk: &WrappedSubjectKey, who: &[u8; 32], oid: u8, wd: &WrappedDek, obj: &[u8]| {
        let sk = domain.unwrap_subject_key(who, wsk)?;
        let dek = sk.unwrap_dek(&id(oid), wd)?;
        Ok::<_, VaultError>(fact::open(dek.expose(), obj)?.to_vec())
    };
    assert_eq!(
        read(&wska, &alice, 10, &wd_a, &obj_a).unwrap(),
        b"Alice Example"
    );
    assert_eq!(
        read(&wskb, &bob, 11, &wd_b, &obj_b).unwrap(),
        b"Bob Example"
    );
    let blob_dek = ska.unwrap_dek(&id(12), &wd_blob).unwrap();
    assert_eq!(
        blob::open(blob_dek.expose(), &blob_obj).unwrap().to_vec(),
        vec![0x42; 3000]
    );

    // Shred Alice: destroy her wrapped subject key. One operation, however many objects she has: her fact and
    // her blob are both under it, so neither can get a data key any more.
    let shredded = WrappedSubjectKey {
        wrapped: zeroed(),
        ..wska.clone()
    };
    assert_eq!(
        read(&shredded, &alice, 10, &wd_a, &obj_a).unwrap_err(),
        VaultError::Shredded
    );
    assert_eq!(
        domain.unwrap_subject_key(&alice, &shredded).unwrap_err(),
        VaultError::Shredded
    );

    // Bob is untouched.
    assert_eq!(
        read(&wskb, &bob, 11, &wd_b, &obj_b).unwrap(),
        b"Bob Example"
    );

    // Without Alice's subject key nothing else the attacker has can recover her DEKs: another subject's key
    // does not open them, and a fresh key for the same subject is a different key.
    assert_eq!(
        skb.unwrap_dek(&id(10), &wd_a).unwrap_err(),
        VaultError::OpenFailed
    );
    let (fresh, _) = domain.new_subject_key(&alice, 1).unwrap();
    assert_eq!(
        fresh.unwrap_dek(&id(10), &wd_a).unwrap_err(),
        VaultError::OpenFailed
    );
}

/// The reason the shred ledger exists: destroying a key in the live key store does nothing about a backup that
/// still holds it. This test records the limit, so nobody reads the test above as more than it shows.
#[test]
fn a_restored_backup_of_the_wrapped_key_brings_the_data_back() {
    let a = arena();
    let root = RootKey::generate(&a).unwrap();
    let (domain, _) = DomainKeys::create(&a, &root, &id(1)).unwrap();
    let sh = domain.subject_hmac("user:alice").unwrap();
    let (sk, wsk) = domain.new_subject_key(&sh, 1).unwrap();
    let (dek, wdek) = sk.new_dek(&id(10), 0).unwrap();
    let object = fact::seal(
        dek.expose(),
        Suite::XChaCha20Poly1305,
        &id(1),
        &id(10),
        0,
        &[1; 24],
        b"secret",
    )
    .unwrap();

    let backup_of_wsk = wsk.clone();
    let shredded = WrappedSubjectKey {
        wrapped: zeroed(),
        ..wsk
    };
    assert_eq!(
        domain.unwrap_subject_key(&sh, &shredded).unwrap_err(),
        VaultError::Shredded
    );

    let restored = domain.unwrap_subject_key(&sh, &backup_of_wsk).unwrap();
    let dek = restored.unwrap_dek(&id(10), &wdek).unwrap();
    assert_eq!(
        fact::open(dek.expose(), &object).unwrap().to_vec(),
        b"secret"
    );
}

// --- Hygiene ---------------------------------------------------------------------------------------------

#[test]
fn debug_output_never_shows_key_bytes() {
    let a = arena();
    let root = RootKey::generate(&a).unwrap();
    let (domain, wrapped) = DomainKeys::create(&a, &root, &id(1)).unwrap();
    let sh = domain.subject_hmac("u").unwrap();
    let (sk, _) = domain.new_subject_key(&sh, 1).unwrap();
    let (dek, _) = sk.new_dek(&id(5), 0).unwrap();
    let eph = EphemeralKey::random().unwrap();

    let shown = format!("{root:?} {domain:?} {sk:?} {dek:?} {eph:?}");
    for key in [root.expose(), sk.expose(), dek.expose(), eph.expose()] {
        assert!(!shown.contains(&hex::encode(key)));
        assert!(
            !shown.contains(&format!("{key:?}")),
            "a key printed as a byte list"
        );
    }
    // The wrapped form is ciphertext and may be printed.
    assert!(format!("{wrapped:?}").contains("kek"));
}

#[test]
fn keys_in_the_arena_are_wiped_and_freed_when_dropped() {
    let a = arena();
    assert_eq!(a.slots_in_use(), 0);
    let root = RootKey::generate(&a).unwrap();
    assert_eq!(a.slots_in_use(), 1);
    let (domain, _) = DomainKeys::create(&a, &root, &id(1)).unwrap();
    assert_eq!(a.slots_in_use(), 4, "root, KEK, BIK, BIX");
    drop(domain);
    assert_eq!(a.slots_in_use(), 1);
    drop(root);
    assert_eq!(a.slots_in_use(), 0);
}

#[test]
fn a_full_arena_is_unavailable_not_a_panic() {
    let a = pvlt_mem::Arena::new(1, pvlt_mem::LockPolicy::BestEffort).unwrap();
    let root = RootKey::generate(&a).unwrap();
    let mut held = Vec::new();
    let err = loop {
        match DomainKeys::create(&a, &root, &id(1)) {
            Ok(d) => held.push(d),
            Err(e) => break e,
        }
    };
    assert_eq!(err, VaultError::Unavailable("key memory is full"));
    // The failed attempt took some slots before running out; they must all have come back.
    assert_eq!(
        a.slots_in_use(),
        1 + 3 * held.len(),
        "the root key plus three keys per domain that was made"
    );
}
