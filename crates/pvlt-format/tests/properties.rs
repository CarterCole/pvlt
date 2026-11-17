//! Property tests: round trips, and that any single-bit change to a sealed unit makes it fail to open.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use proptest::prelude::*;
use pvlt_format::blob::{self, CHUNK_MIN};
use pvlt_format::header::HEADER_LEN;
use pvlt_format::{Suite, TAG_LEN, blind, fact, log, wrap};
use serde_json::Value;

fn suites() -> impl Strategy<Value = Suite> {
    let mut all = vec![Suite::XChaCha20Poly1305, Suite::Aes256Gcm];
    if cfg!(feature = "gcm-siv") {
        all.push(Suite::Aes256GcmSiv);
    }
    prop::sample::select(all)
}

fn bytes<const N: usize>() -> impl Strategy<Value = [u8; N]> {
    prop::array::uniform::<_, N>(any::<u8>())
}

fn flip(mut v: Vec<u8>, at: prop::sample::Index, bit: u8) -> Vec<u8> {
    let i = at.index(v.len());
    v[i] ^= 1 << bit;
    v
}

proptest! {
    #[test]
    fn fact_round_trip(
        suite in suites(), dek in bytes::<32>(), dom in bytes::<16>(), oid in bytes::<16>(),
        generation in any::<u32>(), salt in bytes::<24>(),
        value in prop::collection::vec(any::<u8>(), 0..5000),
    ) {
        let object = fact::seal(&dek, suite, &dom, &oid, generation, &salt, &value).unwrap();
        prop_assert_eq!(object.len(), HEADER_LEN + fact::size_class(value.len()).unwrap() + TAG_LEN);
        prop_assert_eq!(fact::open(&dek, &object).unwrap().to_vec(), value);
    }

    #[test]
    fn fact_any_bit_flip_fails(
        suite in suites(), dek in bytes::<32>(), oid in bytes::<16>(), salt in bytes::<24>(),
        value in prop::collection::vec(any::<u8>(), 0..300),
        at in any::<prop::sample::Index>(), bit in 0u8..8,
    ) {
        let object = fact::seal(&dek, suite, &[7; 16], &oid, 0, &salt, &value).unwrap();
        prop_assert!(fact::open(&dek, &flip(object, at, bit)).is_err());
    }

    #[test]
    fn fact_wrong_key_fails(
        dek in bytes::<32>(), other in bytes::<32>(), salt in bytes::<24>(),
        value in prop::collection::vec(any::<u8>(), 0..100),
    ) {
        prop_assume!(dek != other);
        let object = fact::seal(&dek, Suite::XChaCha20Poly1305, &[1; 16], &[2; 16], 0, &salt, &value).unwrap();
        prop_assert!(fact::open(&other, &object).is_err());
    }

    #[test]
    fn blob_round_trip(
        suite in suites(), dek in bytes::<32>(), oid in bytes::<16>(), salt in bytes::<24>(),
        data in prop::collection::vec(any::<u8>(), 0..5000),
    ) {
        let object = blob::seal(&dek, suite, &[9; 16], &oid, 0, CHUNK_MIN, &salt, &data).unwrap();
        prop_assert_eq!(blob::open(&dek, &object).unwrap().to_vec(), data);
    }

    #[test]
    fn blob_any_bit_flip_fails(
        suite in suites(), dek in bytes::<32>(), salt in bytes::<24>(),
        data in prop::collection::vec(any::<u8>(), 0..3000),
        at in any::<prop::sample::Index>(), bit in 0u8..8,
    ) {
        let object = blob::seal(&dek, suite, &[9; 16], &[3; 16], 0, CHUNK_MIN, &salt, &data).unwrap();
        prop_assert!(blob::open(&dek, &flip(object, at, bit)).is_err());
    }

    #[test]
    fn blob_any_truncation_fails(
        suite in suites(), dek in bytes::<32>(), salt in bytes::<24>(),
        data in prop::collection::vec(any::<u8>(), 0..3000),
        cut in any::<prop::sample::Index>(),
    ) {
        let object = blob::seal(&dek, suite, &[9; 16], &[3; 16], 0, CHUNK_MIN, &salt, &data).unwrap();
        let keep = cut.index(object.len());
        prop_assert!(blob::open(&dek, &object[..keep]).is_err());
    }

    /// Cutting exactly on a chunk boundary leaves only valid chunks, so only the `last` flag can catch it.
    #[test]
    fn blob_chunk_aligned_truncation_fails(
        suite in suites(), dek in bytes::<32>(), salt in bytes::<24>(),
        data in prop::collection::vec(any::<u8>(), 2100..5000),
        cut in any::<prop::sample::Index>(),
    ) {
        let object = blob::seal(&dek, suite, &[9; 16], &[3; 16], 0, CHUNK_MIN, &salt, &data).unwrap();
        let sealed = usize::try_from(CHUNK_MIN).unwrap() + TAG_LEN;
        let chunks = (object.len() - HEADER_LEN) / sealed;
        prop_assume!(chunks >= 2);
        let keep = HEADER_LEN + cut.index(chunks) * sealed;
        prop_assert!(blob::open(&dek, &object[..keep]).is_err());
    }

    #[test]
    fn blob_swapping_two_chunks_fails(
        suite in suites(), dek in bytes::<32>(), salt in bytes::<24>(),
        data in prop::collection::vec(any::<u8>(), 2100..5000),
    ) {
        let object = blob::seal(&dek, suite, &[9; 16], &[3; 16], 0, CHUNK_MIN, &salt, &data).unwrap();
        let sealed = usize::try_from(CHUNK_MIN).unwrap() + TAG_LEN;
        let mut swapped = object[..HEADER_LEN].to_vec();
        swapped.extend_from_slice(&object[HEADER_LEN + sealed..HEADER_LEN + 2 * sealed]);
        swapped.extend_from_slice(&object[HEADER_LEN..HEADER_LEN + sealed]);
        swapped.extend_from_slice(&object[HEADER_LEN + 2 * sealed..]);
        prop_assert!(blob::open(&dek, &swapped).is_err());
    }

    #[test]
    fn wrap_round_trip_and_bit_flip(
        suite in suites(), parent in bytes::<32>(), child in bytes::<32>(), salt in bytes::<24>(),
        wctx in prop::collection::vec(any::<u8>(), 0..200),
        at in any::<prop::sample::Index>(), bit in 0u8..8,
    ) {
        let wrapped = wrap::wrap(&parent, suite, &salt, &wctx, &child).unwrap();
        prop_assert_eq!(wrapped.len(), wrap::WRAPPED_LEN);
        prop_assert_eq!(*wrap::unwrap(&parent, &wrapped, &wctx).unwrap(), child);
        prop_assert!(wrap::unwrap(&parent, &flip(wrapped, at, bit), &wctx).is_err());
    }

    #[test]
    fn wrap_other_context_fails(
        parent in bytes::<32>(), child in bytes::<32>(), salt in bytes::<24>(),
        a in prop::collection::vec(any::<u8>(), 0..50), b in prop::collection::vec(any::<u8>(), 0..50),
    ) {
        prop_assume!(a != b);
        let wrapped = wrap::wrap(&parent, Suite::XChaCha20Poly1305, &salt, &a, &child).unwrap();
        prop_assert!(wrap::unwrap(&parent, &wrapped, &b).is_err());
    }

    #[test]
    fn padme_properties(len in 2u64..(1 << 40)) {
        let p = blob::padme(len).unwrap();
        prop_assert!(p >= len);
        prop_assert!((p - len) * 8 <= len, "overhead above 12.5%");
        prop_assert_eq!(blob::padme(p), Some(p), "padme is idempotent");
    }

    #[test]
    fn padme_is_monotonic(a in 2u64..(1 << 30), b in 2u64..(1 << 30)) {
        let (lo, hi) = if a <= b { (a, b) } else { (b, a) };
        prop_assert!(blob::padme(lo).unwrap() <= blob::padme(hi).unwrap());
    }

    #[test]
    fn size_class_fits(len in 0usize..fact::MAX_VALUE_LEN) {
        let c = fact::size_class(len).unwrap();
        prop_assert!(c > len, "the marker byte must fit");
        prop_assert!(fact::CLASSES.contains(&c));
    }

    #[test]
    fn blind_ids_are_domain_separated(bik in bytes::<32>(), s in "\\PC{0,64}") {
        let subject = blind::subject_hmac(&bik, &s).unwrap();
        let scope = blind::scope_hmac(&bik, &s).unwrap();
        let pseudo = blind::pseudo_subject_hmac(&bik, &s).unwrap();
        prop_assert!(subject != scope && scope != pseudo && subject != pseudo);
    }

    #[test]
    fn nfc_forms_give_one_id(bik in bytes::<32>()) {
        let composed = blind::subject_hmac(&bik, "Zo\u{eb}").unwrap();
        let decomposed = blind::subject_hmac(&bik, "Zoe\u{308}").unwrap();
        prop_assert_eq!(composed, decomposed);
    }

    /// The hand-written canonical JSON must match an independent RFC 8785 implementation on the v1 subset.
    #[test]
    fn jcs_matches_reference_implementation(v in json_subset()) {
        let ours = log::jcs(&v).unwrap();
        let theirs = serde_json_canonicalizer::to_vec(&v).unwrap();
        prop_assert_eq!(ours, theirs);
    }
}

/// JSON values within what v1 entries allow: ASCII keys, integers in 0..2^53, any string.
fn json_subset() -> impl Strategy<Value = Value> {
    let leaf = prop_oneof![
        Just(Value::Null),
        any::<bool>().prop_map(Value::Bool),
        (0u64..=log::INT_MAX).prop_map(Value::from),
        "\\PC{0,20}".prop_map(Value::String),
        // Control characters, quotes, backslashes and non-BMP characters exercise string escaping.
        prop::collection::vec(
            prop_oneof![
                Just('\u{0}'),
                Just('\u{1f}'),
                Just('"'),
                Just('\\'),
                Just('\u{1f600}'),
                any::<char>()
            ],
            0..8
        )
        .prop_map(|cs| Value::String(cs.into_iter().collect())),
    ];
    leaf.prop_recursive(4, 48, 6, |inner| {
        prop_oneof![
            prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
            prop::collection::btree_map("[ -~]{0,8}", inner, 0..5)
                .prop_map(|m| Value::Object(m.into_iter().collect())),
        ]
    })
}

#[test]
fn jcs_rejects_what_v1_does_not_allow() {
    assert!(log::jcs(&serde_json::json!({"k": -1})).is_err());
    assert!(log::jcs(&serde_json::json!({"k": 1.5})).is_err());
    assert!(log::jcs(&serde_json::json!({"k": 9_007_199_254_740_992u64})).is_err());
    assert!(log::jcs(&serde_json::json!({"k\u{e9}": 1})).is_err());
    assert!(log::jcs(&serde_json::json!({"k": 9_007_199_254_740_991u64})).is_ok());
}
