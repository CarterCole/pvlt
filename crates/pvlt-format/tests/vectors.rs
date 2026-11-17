//! Replays the known-answer vectors in `spec/vectors/` (written by the Python reference) through this crate.
//!
//! Every `expected` value must be reproduced byte for byte, and every `must_fail` case must fail. Suite
//! `0x0002` vectors are skipped unless the `gcm-siv` feature is on; run `cargo test --all-features` for all.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pvlt_format::{Error, Suite, blind, blob, fact, log, suite::testing, wrap};
use serde_json::Value;
use sha2::{Digest, Sha256};

fn load(name: &str) -> Value {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/../../spec/vectors/");
    let text = std::fs::read_to_string(format!("{path}{name}")).unwrap();
    serde_json::from_str(&text).unwrap()
}

fn vectors(name: &str) -> Vec<Value> {
    match load(name)["vectors"].clone() {
        Value::Array(a) => a,
        other => panic!("{name}: vectors is not a list: {other}"),
    }
}

fn s(v: &Value) -> &str {
    v.as_str().unwrap()
}

fn h(v: &Value) -> Vec<u8> {
    hex::decode(s(v)).unwrap()
}

fn arr<const N: usize>(v: &Value) -> [u8; N] {
    h(v).try_into().unwrap()
}

fn u32_of(v: &Value) -> u32 {
    u32::try_from(v.as_u64().unwrap()).unwrap()
}

/// `Some(suite)` if this build can run the vector, `None` if the suite is compiled out.
fn suite_of(v: &Value) -> Option<Suite> {
    let id = u16::try_from(v["suite"].as_u64().unwrap()).unwrap();
    if id == 0x0002 && !cfg!(feature = "gcm-siv") {
        return None;
    }
    Some(Suite::from_id(id).unwrap())
}

/// The reference's `fx(name, n)`: SHA-256 of `pvlt-vector:<name>:<i>`, concatenated and cut to `n` bytes.
fn fx(name: &str, n: usize) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while out.len() < n {
        out.extend_from_slice(&Sha256::digest(format!("pvlt-vector:{name}:{i}")));
        i += 1;
    }
    out.truncate(n);
    out
}

fn fx_arr<const N: usize>(name: &str) -> [u8; N] {
    fx(name, N).try_into().unwrap()
}

/// Counts what ran, so a loop that silently skips everything cannot pass.
fn expect_ran(file: &str, ran: usize, skipped: usize, total: usize) {
    assert_eq!(
        ran + skipped,
        total,
        "{file}: some vectors were neither run nor skipped"
    );
    assert!(ran > 0, "{file}: nothing ran");
}

#[test]
fn derive() {
    let (mut ran, mut skipped) = (0, 0);
    let all = vectors("derive.json");
    for v in &all {
        let Some(suite) = suite_of(v) else {
            skipped += 1;
            continue;
        };
        let e = &v["expected"];
        let (info, ek, ck, n_single, n_chunk0, n_chunk7) = testing::derive_parts(
            &arr(&v["key"]),
            suite,
            &arr(&v["salt"]),
            s(&v["label"]),
            &h(&v["ctx"]),
        )
        .unwrap();
        let name = s(&v["name"]);
        assert_eq!(info, h(&e["info"]), "{name}: info");
        assert_eq!(ek.to_vec(), h(&e["ek"]), "{name}: ek");
        assert_eq!(ck.to_vec(), h(&e["ck"]), "{name}: ck");
        assert_eq!(n_single, h(&e["nonce_single"]), "{name}: single nonce");
        assert_eq!(n_chunk0, h(&e["nonce_chunk_0"]), "{name}: chunk 0 nonce");
        assert_eq!(
            n_chunk7,
            h(&e["nonce_chunk_7_last"]),
            "{name}: chunk 7 nonce"
        );
        ran += 1;
    }
    expect_ran("derive.json", ran, skipped, all.len());
}

#[test]
fn facts() {
    let (mut ran, mut skipped) = (0, 0);
    let all = vectors("fact.json");
    for v in &all {
        let Some(suite) = suite_of(v) else {
            skipped += 1;
            continue;
        };
        let name = s(&v["name"]);
        let (dek, value) = (arr(&v["dek"]), h(&v["value"]));
        let object = fact::seal(
            &dek,
            suite,
            &arr(&v["domain_id"]),
            &arr(&v["object_id"]),
            u32_of(&v["dek_generation"]),
            &arr(&v["salt"]),
            &value,
        )
        .unwrap();
        assert_eq!(object, h(&v["expected"]["object"]), "{name}: sealed object");
        assert_eq!(
            fact::size_class(value.len()),
            v["expected"]["size_class"].as_u64().map(|c| c as usize),
            "{name}"
        );
        assert_eq!(
            fact::open(&dek, &object).unwrap().to_vec(),
            value,
            "{name}: round trip"
        );
        ran += 1;
    }
    expect_ran("fact.json", ran, skipped, all.len());
}

#[test]
fn blobs() {
    let (mut ran, mut skipped) = (0, 0);
    let all = vectors("blob.json");
    for v in &all {
        let Some(suite) = suite_of(v) else {
            skipped += 1;
            continue;
        };
        let name = s(&v["name"]);
        let (dek, data) = (arr(&v["dek"]), h(&v["data"]));
        let object = blob::seal(
            &dek,
            suite,
            &arr(&v["domain_id"]),
            &arr(&v["object_id"]),
            u32_of(&v["dek_generation"]),
            u32_of(&v["chunk_size"]),
            &arr(&v["salt"]),
            &data,
        )
        .unwrap();
        assert_eq!(object, h(&v["expected"]["object"]), "{name}: sealed object");
        assert_eq!(
            blob::open(&dek, &object).unwrap().to_vec(),
            data,
            "{name}: round trip"
        );
        let padded = v["expected"]["padded_len"].as_u64().unwrap();
        assert_eq!(
            blob::padme(data.len() as u64 + 8),
            Some(padded),
            "{name}: padme"
        );
        ran += 1;
    }
    expect_ran("blob.json", ran, skipped, all.len());
}

/// The wrap context for a vector's `kind`, rebuilt with the crate's builders from the reference's inputs.
fn expected_wctx(kind: &str) -> Vec<u8> {
    let domain: [u8; 16] = fx_arr("domain_id");
    let root_id: [u8; 16] = fx_arr("root_key_id");
    let sign_id: [u8; 16] = fx_arr("sign-key-id");
    let subject = blind::subject_hmac(&fx_arr("bik"), "user:1234").unwrap();
    match kind {
        "kek" => wrap::ctx::kek(&domain, 1, &root_id, 1),
        "bik" => wrap::ctx::bik(&domain, 1, &root_id, 1),
        "bix" => wrap::ctx::bix(&domain, 2, &root_id, 1),
        "subject" => wrap::ctx::subject(&domain, &subject, 1, 1),
        "dek" => wrap::ctx::dek(&domain, &subject, 1, &fx_arr("wrap-oid"), 0),
        "root" => wrap::ctx::root(&root_id, 1),
        "sign ledger" => wrap::ctx::sign(&domain, wrap::SignPurpose::Ledger, &sign_id, &root_id, 1),
        "sign checkpoint" => wrap::ctx::sign(
            &domain,
            wrap::SignPurpose::Checkpoint,
            &sign_id,
            &root_id,
            1,
        ),
        other => panic!("unknown wrap kind {other}"),
    }
    .unwrap()
}

#[test]
fn wrapped_keys() {
    let (mut ran, mut skipped) = (0, 0);
    let all = vectors("wrap.json");
    for v in &all {
        let Some(suite) = suite_of(v) else {
            skipped += 1;
            continue;
        };
        let name = s(&v["name"]);
        let (parent, child, wctx) = (arr(&v["parent"]), arr(&v["child"]), h(&v["wctx"]));
        let kind = name.split_once(' ').unwrap().1;
        assert_eq!(expected_wctx(kind), wctx, "{name}: wrap context builder");
        let wrapped = wrap::wrap(&parent, suite, &arr(&v["salt"]), &wctx, &child).unwrap();
        assert_eq!(wrapped, h(&v["expected"]["wrapped"]), "{name}: wrapped key");
        assert_eq!(
            *wrap::unwrap(&parent, &wrapped, &wctx).unwrap(),
            child,
            "{name}: round trip"
        );
        ran += 1;
    }
    expect_ran("wrap.json", ran, skipped, all.len());
}

#[test]
fn blind_ids() {
    let all = vectors("blind.json");
    for v in &all {
        let name = s(&v["name"]);
        let key = arr(&v["key"]);
        let got = match s(&v["fn"]) {
            "subject_hmac" => blind::subject_hmac(&key, s(&v["input"])),
            "scope_hmac" => blind::scope_hmac(&key, s(&v["input"])),
            "pseudo_subject_hmac" => blind::pseudo_subject_hmac(&key, s(&v["input"])),
            "index_value" => blind::index_value(&key, s(&v["index_name"]), &h(&v["input_hex"])),
            other => panic!("unknown fn {other}"),
        }
        .unwrap();
        assert_eq!(got.to_vec(), h(&v["expected"]), "{name}");
    }
    expect_ran("blind.json", all.len(), 0, all.len());
}

#[test]
fn logs() {
    let doc = load("log.json");
    let v = &doc["vectors"];

    let ledger = &v["ledger"];
    let (seed, public): ([u8; 32], [u8; 32]) =
        (arr(&ledger["signing_seed"]), arr(&ledger["signing_public"]));
    assert_eq!(log::public_key(&seed), public, "ledger public key");
    let key_id: [u8; 16] = arr(&ledger["key_id"]);
    let mut entries = Vec::new();
    for item in ledger["entries"].as_array().unwrap() {
        let (entry, e) = (&item["entry"], &item["expected"]);
        assert_eq!(
            log::jcs(entry).unwrap(),
            s(&e["jcs"]).as_bytes(),
            "entry jcs"
        );
        assert_eq!(
            log::entry_hash(entry).unwrap().to_vec(),
            h(&e["entry_hash"]),
            "entry hash"
        );
        assert_eq!(
            log::ledger_sign(&seed, entry).unwrap().to_vec(),
            h(&e["sig"]),
            "ledger signature"
        );
        let line = log::ledger_line(&seed, &key_id, entry).unwrap();
        assert_eq!(line, s(&e["line"]).as_bytes(), "ledger line");
        assert_eq!(
            &log::ledger_verify(&public, &line).unwrap(),
            entry,
            "ledger line verifies"
        );
        entries.push(entry.clone());
    }
    assert_eq!(
        log::verify_chain(&entries).unwrap().to_vec(),
        h(&ledger["expected_head"]),
        "chain head"
    );

    let audit = &v["audit"];
    assert_eq!(
        log::jcs(&audit["entry"]).unwrap(),
        s(&audit["expected"]["jcs"]).as_bytes(),
        "audit jcs"
    );
    assert_eq!(
        log::entry_hash(&audit["entry"]).unwrap().to_vec(),
        h(&audit["expected"]["entry_hash"]),
        "audit hash"
    );

    let cp = &v["checkpoint"];
    let (cp_seed, cp_public): ([u8; 32], [u8; 32]) =
        (arr(&cp["signing_seed"]), arr(&cp["signing_public"]));
    assert_eq!(
        log::public_key(&cp_seed),
        cp_public,
        "checkpoint public key"
    );
    let (checkpoint, e) = (&cp["checkpoint"], &cp["expected"]);
    assert_eq!(
        log::jcs(checkpoint).unwrap(),
        s(&e["jcs"]).as_bytes(),
        "checkpoint jcs"
    );
    assert_eq!(
        log::checkpoint_sign(&cp_seed, checkpoint).unwrap().to_vec(),
        h(&e["sig"]),
        "checkpoint signature"
    );
    log::checkpoint_verify(&cp_public, checkpoint, s(&e["sig"])).unwrap();
}

#[test]
fn tampered_inputs_fail() {
    let (mut ran, mut skipped) = (0, 0);
    let all = vectors("tamper.json");
    for v in &all {
        let name = s(&v["name"]);
        assert_eq!(
            v["must_fail"],
            Value::Bool(true),
            "{name}: not a must_fail vector"
        );
        let result: Result<(), Error> = match s(&v["op"]) {
            "fact_open" => fact::open(&arr(&v["dek"]), &h(&v["object"])).map(drop),
            "blob_open" => blob::open(&arr(&v["dek"]), &h(&v["object"])).map(drop),
            "unwrap" => {
                wrap::unwrap(&arr(&v["parent"]), &h(&v["wrapped"]), &h(&v["wctx"])).map(drop)
            }
            other => panic!("unknown op {other}"),
        };
        let err = result.expect_err(name);
        if s(&v["op"]) == "unwrap" {
            let want = if s(&v["error"]) == "shredded" {
                Error::Shredded
            } else {
                Error::OpenFailed
            };
            assert_eq!(err, want, "{name}");
        }
        ran += 1;
    }
    skipped += 0;
    expect_ran("tamper.json", ran, skipped, all.len());
}

#[test]
fn suite_ids() {
    assert_eq!(Suite::from_id(0x0001).unwrap().id(), 0x0001);
    assert_eq!(Suite::from_id(0x0003).unwrap().id(), 0x0003);
    for bad in [0x0000, 0x0004, 0xffff] {
        assert_eq!(Suite::from_id(bad), Err(Error::UnsupportedSuite));
    }
    assert_eq!(Suite::from_id(0x0002).is_ok(), cfg!(feature = "gcm-siv"));
}
