//! Verifying delegated tokens: what is accepted, and every way a token can be refused.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;

use biscuit_auth::builder::Algorithm;
use biscuit_auth::{Biscuit, KeyPair, PrivateKey};
use pvlt_server::tokens::{
    Claims, IssuerKeys, TokenError, attenuate_expiry, attenuate_with_fact, generate_issuer_key,
    mint, public_key_of, verify,
};
use uuid::Uuid;

const NOW: i64 = 1_800_000_000;
const TTL: i64 = 300;

struct Registry(HashMap<u32, [u8; 32]>);

impl IssuerKeys for Registry {
    fn public_key(&self, key_id: u32) -> Option<[u8; 32]> {
        self.0.get(&key_id).copied()
    }
}

struct Rig {
    seed: [u8; 32],
    keys: Registry,
}

fn rig() -> Rig {
    let (seed, public) = generate_issuer_key();
    Rig {
        seed,
        keys: Registry(HashMap::from([(7, public)])),
    }
}

fn claims() -> Claims {
    Claims {
        issuer_key_id: 7,
        caller: Some("user:77".into()),
        subject: Some("user:1234".into()),
        roles: vec!["verifier".into(), "data-subject".into()],
        purpose: Some("kyc-review".into()),
        reason: Some("ticket 4411".into()),
        request_id: "req-1".into(),
        actions: vec!["read".into()],
        resource_fact: Some(Uuid::from_bytes([5; 16])),
        resource_scope: Some("kyc-doc:42".into()),
        resource_subject: Some("user:1234".into()),
        grants: vec!["order_open".into()],
        approval: Some("appr-9".into()),
        expires: NOW + 60,
    }
}

#[test]
fn a_token_round_trips_with_every_claim() {
    let r = rig();
    let token = mint(&r.seed, &claims()).unwrap();
    assert_eq!(verify(&token, &r.keys, NOW, TTL).unwrap(), {
        let mut c = claims();
        c.roles.sort();
        c
    });
}

#[test]
fn a_minimal_token_has_only_what_it_must() {
    let r = rig();
    let c = Claims {
        issuer_key_id: 7,
        request_id: "r".into(),
        expires: NOW + 10,
        ..Claims::default()
    };
    let got = verify(&mint(&r.seed, &c).unwrap(), &r.keys, NOW, TTL).unwrap();
    assert_eq!(got, c);
    assert!(got.roles.is_empty() && got.caller.is_none() && got.resource_fact.is_none());
}

#[test]
fn time_is_enforced_both_ways() {
    let r = rig();
    let token = mint(&r.seed, &claims()).unwrap();
    assert!(verify(&token, &r.keys, NOW + 59, TTL).is_ok());
    assert_eq!(
        verify(&token, &r.keys, NOW + 60, TTL),
        Err(TokenError::Expired)
    );
    assert_eq!(
        verify(&token, &r.keys, NOW + 3600, TTL),
        Err(TokenError::Expired)
    );
    // A long-lived token is refused even though it is genuine and unexpired.
    let long = mint(
        &r.seed,
        &Claims {
            expires: NOW + TTL + 1,
            ..claims()
        },
    )
    .unwrap();
    assert_eq!(
        verify(&long, &r.keys, NOW, TTL),
        Err(TokenError::LifetimeTooLong)
    );
    let edge = mint(
        &r.seed,
        &Claims {
            expires: NOW + TTL,
            ..claims()
        },
    )
    .unwrap();
    assert!(verify(&edge, &r.keys, NOW, TTL).is_ok());
}

#[test]
fn a_token_from_an_unregistered_issuer_or_signed_by_the_wrong_key_is_refused() {
    let r = rig();
    // Unknown key id.
    let other_id = mint(
        &r.seed,
        &Claims {
            issuer_key_id: 8,
            ..claims()
        },
    )
    .unwrap();
    assert_eq!(
        verify(&other_id, &r.keys, NOW, TTL),
        Err(TokenError::UnknownIssuer)
    );
    // A registered id, but signed by someone else's key.
    let (stranger, _) = generate_issuer_key();
    let forged = mint(&stranger, &claims()).unwrap();
    assert_eq!(
        verify(&forged, &r.keys, NOW, TTL),
        Err(TokenError::Rejected)
    );
    // No root key id at all.
    let kp = KeyPair::from(&PrivateKey::from_bytes(&r.seed, Algorithm::Ed25519).unwrap());
    let no_id = Biscuit::builder()
        .fact("expires(1800000100)")
        .unwrap()
        .fact("request_id(\"r\")")
        .unwrap()
        .build(&kp)
        .unwrap()
        .to_base64()
        .unwrap();
    assert_eq!(
        verify(&no_id, &r.keys, NOW, TTL),
        Err(TokenError::UnknownIssuer)
    );
}

#[test]
fn a_disabled_issuer_is_the_same_as_an_unknown_one() {
    let r = rig();
    let token = mint(&r.seed, &claims()).unwrap();
    let empty = Registry(HashMap::new());
    assert_eq!(
        verify(&token, &empty, NOW, TTL),
        Err(TokenError::UnknownIssuer)
    );
}

#[test]
fn damaged_or_nonsense_tokens_are_refused_without_a_panic() {
    let r = rig();
    let token = mint(&r.seed, &claims()).unwrap();
    assert!(verify("", &r.keys, NOW, TTL).is_err());
    assert!(verify("not a token", &r.keys, NOW, TTL).is_err());
    assert!(verify(&"A".repeat(10_000), &r.keys, NOW, TTL).is_err());
    for at in [0, 5, token.len() / 2, token.len() - 2] {
        let mut bytes = token.clone().into_bytes();
        bytes[at] = if bytes[at] == b'A' { b'B' } else { b'A' };
        let bad = String::from_utf8(bytes).unwrap();
        assert!(
            verify(&bad, &r.keys, NOW, TTL).is_err(),
            "a change at {at} was accepted"
        );
    }
    assert!(verify(&token[..token.len() / 2], &r.keys, NOW, TTL).is_err());
}

#[test]
fn required_claims_and_claim_shapes_are_checked() {
    let r = rig();
    let kp = KeyPair::from(&PrivateKey::from_bytes(&r.seed, Algorithm::Ed25519).unwrap());
    let build = |facts: &[&str]| {
        let mut b = Biscuit::builder().root_key_id(7);
        for f in facts {
            b = b.fact(*f).unwrap();
        }
        b.build(&kp).unwrap().to_base64().unwrap()
    };
    let t = |facts: &[&str]| verify(&build(facts), &r.keys, NOW, TTL);
    assert_eq!(
        t(&["request_id(\"r\")"]),
        Err(TokenError::Missing("expires"))
    );
    assert_eq!(
        t(&["expires(1800000100)"]),
        Err(TokenError::Missing("request_id"))
    );
    assert_eq!(
        t(&[
            "expires(1800000100)",
            "expires(1800000200)",
            "request_id(\"r\")"
        ]),
        Err(TokenError::Invalid("expires"))
    );
    assert_eq!(
        t(&[
            "expires(1800000100)",
            "request_id(\"r\")",
            "caller(\"a\")",
            "caller(\"b\")"
        ]),
        Err(TokenError::Invalid("caller"))
    );
    assert_eq!(
        t(&[
            "expires(1800000100)",
            "request_id(\"r\")",
            "resource_fact(\"not-a-uuid\")"
        ]),
        Err(TokenError::Invalid("resource_fact"))
    );
    let long = format!("caller(\"{}\")", "x".repeat(300));
    assert_eq!(
        t(&["expires(1800000100)", "request_id(\"r\")", long.as_str()]),
        Err(TokenError::Invalid("caller"))
    );
    assert!(t(&["expires(1800000100)", "request_id(\"r\")"]).is_ok());
}

#[test]
fn attenuation_can_only_narrow_a_token() {
    let r = rig();
    let token = mint(&r.seed, &claims()).unwrap();
    // The holder can shorten it...
    let shorter = attenuate_expiry(&token, &r.keys, NOW + 10).unwrap();
    assert!(verify(&shorter, &r.keys, NOW + 9, TTL).is_ok());
    assert_eq!(
        verify(&shorter, &r.keys, NOW + 10, TTL),
        Err(TokenError::Rejected)
    );
    // ...but cannot lengthen it: the original limit still applies.
    let longer = attenuate_expiry(&token, &r.keys, NOW + 100_000).unwrap();
    assert_eq!(
        verify(&longer, &r.keys, NOW + 60, TTL),
        Err(TokenError::Expired)
    );
    // And a fact added in a later block is never read, so a holder cannot grant themselves a role.
    let sneaky = attenuate_with_fact(
        &mint(&r.seed, &Claims { roles: vec!["data-subject".into()], ..claims() }).unwrap(),
        &r.keys,
        "role(\"admin\"); caller(\"user:1\"); resource_fact(\"00000000-0000-0000-0000-000000000000\");",
    )
    .unwrap();
    let got = verify(&sneaky, &r.keys, NOW, TTL).unwrap();
    assert_eq!(got.roles, ["data-subject"]);
    assert_eq!(got.caller.as_deref(), Some("user:77"));
    assert_eq!(got.resource_fact, Some(Uuid::from_bytes([5; 16])));
}

#[test]
fn the_public_key_matches_the_seed() {
    let (seed, public) = generate_issuer_key();
    assert_eq!(public_key_of(&seed).unwrap(), public);
}
