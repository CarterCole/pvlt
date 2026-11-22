//! Verifying delegated tokens: what is accepted, and every way a token can be refused.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::HashMap;
use std::time::{Duration, Instant};

use biscuit_auth::builder::Algorithm;
use biscuit_auth::{Biscuit, KeyPair, PrivateKey};
use pvlt_server::tokens::{
    Claims, IssuerKeys, MAX_ATTENUATION_CHECKS, MAX_CHECK_ALTERNATIVES, MAX_QUERY_SIZE,
    MAX_REPEATS, MAX_TOKEN_LEN, TokenError, attenuate_expiry, attenuate_with_fact,
    generate_issuer_key, mint, public_key_of, verify,
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
    // And a holder cannot grant themselves a role: a token whose later block holds a fact is refused outright.
    let sneaky = attenuate_with_fact(
        &mint(&r.seed, &Claims { roles: vec!["data-subject".into()], ..claims() }).unwrap(),
        &r.keys,
        "role(\"admin\"); caller(\"user:1\"); resource_fact(\"00000000-0000-0000-0000-000000000000\");",
    )
    .unwrap();
    assert_eq!(
        verify(&sneaky, &r.keys, NOW, TTL),
        Err(TokenError::Rejected)
    );
    // So is one whose later block holds a rule, even one that derives nothing a claim reads.
    let ruled = attenuate_with_fact(&token, &r.keys, "seen($r) <- role($r);").unwrap();
    assert_eq!(verify(&ruled, &r.keys, NOW, TTL), Err(TokenError::Rejected));
}

/// Every claim, each repeatable one as many times as allowed: as many facts as a genuine token can carry, and so
/// the most a check in a later block can join over.
fn full_claims() -> Claims {
    let many = |name: &str| -> Vec<String> {
        (0..MAX_REPEATS)
            .map(|i| format!("{name}-{i:02}-{}", "x".repeat(16)))
            .collect()
    };
    Claims {
        roles: many("role"),
        actions: many("action"),
        grants: many("grant"),
        ..claims()
    }
}

#[test]
fn a_full_token_verifies_while_many_threads_verify_at_once() {
    let r = rig();
    // Every claim at its most, and a narrowing check: as much Datalog as a genuine token can carry.
    let full = full_claims();
    let token = attenuate_expiry(&mint(&r.seed, &full).unwrap(), &r.keys, NOW + 30).unwrap();
    assert!(token.len() <= MAX_TOKEN_LEN);
    let threads = std::thread::available_parallelism().map_or(4, |n| n.get()) * 2;
    // With biscuit-auth's default 1 ms time limit, about 1 in 8 of these were refused in a debug build.
    let refused: usize = std::thread::scope(|s| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    (0..25)
                        .filter(|_| verify(&token, &r.keys, NOW, TTL).as_ref() != Ok(&full))
                        .count()
                })
            })
            .collect();
        workers.into_iter().map(|w| w.join().unwrap()).sum()
    });
    assert_eq!(refused, 0, "{refused} of {} were refused", threads * 25);
}

/// Each of these blocks of Datalog passes its own check when it is small. Large, it would still pass if it ran to
/// the end, so a refusal of it in the authority block can only come from a run limit.
mod hostile {
    /// Derives one new fact per round, `n` rounds in all, with fewer than `3n` facts.
    pub fn rounds(n: usize) -> String {
        let edges: String = (0..n).map(|i| format!("edge({i}, {});", i + 1)).collect();
        format!("{edges} reach(0); reach($b) <- reach($a), edge($a, $b); check if reach({n});")
    }

    /// Derives `n * n` facts in one round.
    pub fn facts(n: usize) -> String {
        let f: String = (0..n).map(|i| format!("f({i});")).collect();
        format!(
            "{f} pair($a, $b) <- f($a), f($b); check if pair({m}, {m});",
            m = n - 1
        )
    }

    /// `rounds(n)`, with a rule that tries `width³` combinations in every round and never matches.
    pub fn slow(n: usize, width: usize) -> String {
        let f: String = (0..width).map(|i| format!("f({i});")).collect();
        format!(
            "{} {f} never($a) <- f($a), f($b), f($c), $a + $b + $c < 0;",
            rounds(n)
        )
    }
}

/// A token whose authority block holds `code` as well as the claims a token needs. Only the issuer can write
/// there, so it is not held to the attenuation limits, and the run limits are what bound it.
fn with_authority(r: &Rig, code: &str) -> String {
    let kp = KeyPair::from(&PrivateKey::from_bytes(&r.seed, Algorithm::Ed25519).unwrap());
    Biscuit::builder()
        .root_key_id(7)
        .code(format!("expires({}); request_id(\"r\"); {code}", NOW + 60))
        .unwrap()
        .build(&kp)
        .unwrap()
        .to_base64()
        .unwrap()
}

/// Runs `f`, which must answer within a second. Each hostile block below would run for many seconds, or minutes,
/// in a debug build if its Datalog ran to the end; refusing it before anything runs takes milliseconds.
fn fast<T>(f: impl FnOnce() -> T) -> T {
    let start = Instant::now();
    let out = f();
    let took = start.elapsed();
    assert!(took < Duration::from_secs(1), "took {took:?}");
    out
}

#[test]
fn run_limits_still_stop_hostile_rules_in_the_authority_block() {
    let r = rig();
    let with = |code: &str| {
        let t = with_authority(&r, code);
        assert!(t.len() <= MAX_TOKEN_LEN);
        verify(&t, &r.keys, NOW, TTL)
    };

    for small in [hostile::rounds(10), hostile::facts(10), hostile::slow(3, 4)] {
        assert!(with(&small).is_ok(), "{small}");
    }
    // 150 rounds, against a limit of 100.
    assert_eq!(with(&hostile::rounds(150)), Err(TokenError::Rejected));
    // 1600 facts, against a limit of 1000.
    assert_eq!(with(&hostile::facts(40)), Err(TokenError::Rejected));
    // 90 rounds and about 230 facts are both inside their limits, so only the time limit can refuse this. Run to
    // the end it takes seconds in a debug build, and then passes.
    assert_eq!(with(&hostile::slow(90, 30)), Err(TokenError::Rejected));

    // In a later block, where any holder could add them, the same blocks hold facts and rules, so every one of
    // them, small or large, is refused before it runs.
    let token = mint(&r.seed, &claims()).unwrap();
    for code in [
        hostile::rounds(10),
        hostile::facts(10),
        hostile::slow(3, 4),
        hostile::rounds(150),
        hostile::facts(40),
        hostile::slow(90, 30),
    ] {
        let t = attenuate_with_fact(&token, &r.keys, &code).unwrap();
        assert_eq!(
            fast(|| verify(&t, &r.keys, NOW, TTL)),
            Err(TokenError::Rejected),
            "{code}"
        );
    }
}

#[test]
fn a_hostile_check_block_is_refused_before_it_runs() {
    let r = rig();
    let token = mint(&r.seed, &claims()).unwrap();
    let with = |base: &str, code: &str| {
        let t = attenuate_with_fact(base, &r.keys, code).unwrap();
        assert!(t.len() <= MAX_TOKEN_LEN);
        t
    };
    // 80 facts and a check that joins four of them: 80^4, about 41 million matches, every one tried because none
    // can pass. biscuit-auth reads its time limit only between queries, so this ran to the end: 230 s in a debug
    // build, from a token of 1.8 KB.
    let f80: String = (0..80).map(|i| format!("f({i});")).collect();
    let k80 = format!("{f80} check if f($a), f($b), f($c), f($d), $a + $b + $c + $d == -1;");
    let hostile = with(&token, &k80);
    assert_eq!(
        fast(|| verify(&hostile, &r.keys, NOW, TTL)),
        Err(TokenError::Rejected)
    );
    // An expired token carrying it is refused as expired before anything runs, and so is one that lives too long.
    assert_eq!(
        fast(|| verify(&hostile, &r.keys, NOW + 60, TTL)),
        Err(TokenError::Expired)
    );
    let long = mint(
        &r.seed,
        &Claims {
            expires: NOW + TTL + 1,
            ..claims()
        },
    )
    .unwrap();
    assert_eq!(
        fast(|| verify(&with(&long, &k80), &r.keys, NOW, TTL)),
        Err(TokenError::LifetimeTooLong)
    );

    // With no facts of its own, a check can still join the token's claims: 20 copies of `role(..)` over its two
    // roles is 2^20 matches, 24 s in a debug build.
    let roles: Vec<String> = (0..20).map(|i| format!("role($v{i})")).collect();
    let joins = with(
        &token,
        &format!("check if {}, $v0 == \"none\";", roles.join(", ")),
    );
    // Nested `.all()` loops need no facts at all: 10^7 evaluations, about 10 s.
    let mut nested = String::from("true");
    for depth in 0..7 {
        nested = format!("[0, 1, 2, 3, 4, 5, 6, 7, 8, 9].all($c{depth} -> {nested})");
    }
    let loops = with(&token, &format!("check if {nested};"));
    // `.matches()` compiles its regex each time, about 45 ms, and two predicates over a full token's roles make it
    // do that 1024 times.
    let full = mint(&r.seed, &full_claims()).unwrap();
    let regex = with(
        &full,
        "check if role($a), role($b), $a.matches(\"((a{100}){100}){10}\");",
    );
    for t in [joins, loops, regex] {
        assert_eq!(
            fast(|| verify(&t, &r.keys, NOW, TTL)),
            Err(TokenError::Rejected)
        );
    }
}

#[test]
fn a_hostile_rule_block_is_refused_before_it_runs() {
    let r = rig();
    let token = mint(&r.seed, &claims()).unwrap();
    // One round of this rule builds 30^4 = 810 000 facts, all held in memory before biscuit-auth reads its fact
    // limit at the end of the round.
    let f30: String = (0..30).map(|i| format!("f({i});")).collect();
    let rule = attenuate_with_fact(
        &token,
        &r.keys,
        &format!("{f30} p($a, $b, $c, $d) <- f($a), f($b), f($c), f($d);"),
    )
    .unwrap();
    assert_eq!(
        fast(|| verify(&rule, &r.keys, NOW, TTL)),
        Err(TokenError::Rejected)
    );
    // The same rule over a full token's own roles needs no facts of its own: 32^4, about a million.
    let full = mint(&r.seed, &full_claims()).unwrap();
    let rule = attenuate_with_fact(
        &full,
        &r.keys,
        "p($a, $b, $c, $d) <- role($a), role($b), role($c), role($d);",
    )
    .unwrap();
    assert_eq!(
        fast(|| verify(&rule, &r.keys, NOW, TTL)),
        Err(TokenError::Rejected)
    );
}

#[test]
fn narrowing_checks_within_the_limits_pass_and_past_them_are_refused() {
    let r = rig();
    let token = mint(&r.seed, &claims()).unwrap();
    let with = |blocks: &[&str]| {
        let mut t = token.clone();
        for b in blocks {
            t = attenuate_with_fact(&t, &r.keys, b).unwrap();
        }
        assert!(t.len() <= MAX_TOKEN_LEN);
        verify(&t, &r.keys, NOW, TTL)
    };
    let before = "2030-01-01T00:00:00Z";

    // Checks a holder might really add.
    for ok in [
        format!("check if time($t), $t < {before};"),
        "check if action(\"read\");".to_owned(),
        "check if action($a), [\"read\", \"list\"].contains($a);".to_owned(),
        format!(
            "check if time($t), action($a), $t < {before} && ($a == \"read\" || $a == \"list\");"
        ),
        "check if resource_scope($s), $s.starts_with(\"kyc-doc:\");".to_owned(),
        "check if action(\"list\") or action(\"read\");".to_owned(),
        "check all action($a), $a == \"read\";".to_owned(),
        "reject if role(\"admin\");".to_owned(),
        "check if action(\"read\") trusting previous;".to_owned(),
    ] {
        assert!(with(&[&ok]).is_ok(), "{ok}");
    }

    // A check over three claims is refused. Split into one check each, it says the same thing and passes.
    let three = format!(
        "check if time($t), action(\"read\"), resource_scope(\"kyc-doc:42\"), $t < {before};"
    );
    assert_eq!(with(&[&three]), Err(TokenError::Rejected));
    let split = format!(
        "check if time($t), $t < {before}; check if action(\"read\"); check if resource_scope(\"kyc-doc:42\");"
    );
    assert!(with(&[&split]).is_ok());

    // At most MAX_ATTENUATION_CHECKS checks in all the later blocks together.
    let checks = |range: std::ops::Range<usize>| -> String {
        range
            .map(|i| format!("check if time($t), $t < 2030-01-01T00:00:{i:02}Z;"))
            .collect()
    };
    let half = MAX_ATTENUATION_CHECKS / 2;
    assert!(with(&[&checks(0..MAX_ATTENUATION_CHECKS)]).is_ok());
    assert!(with(&[&checks(0..half), &checks(half..MAX_ATTENUATION_CHECKS)]).is_ok());
    assert_eq!(
        with(&[&checks(0..MAX_ATTENUATION_CHECKS + 1)]),
        Err(TokenError::Rejected)
    );
    assert_eq!(
        with(&[&checks(0..half), &checks(half..MAX_ATTENUATION_CHECKS + 1)]),
        Err(TokenError::Rejected)
    );

    // At most MAX_CHECK_ALTERNATIVES `or` alternatives in one check.
    let alternatives = |n: usize| -> String {
        let alts: Vec<String> = (0..n)
            .map(|i| format!("action(\"action-{i}\")"))
            .chain(["action(\"read\")".to_owned()])
            .collect();
        format!("check if {};", alts.join(" or "))
    };
    assert!(with(&[&alternatives(MAX_CHECK_ALTERNATIVES - 1)]).is_ok());
    assert_eq!(
        with(&[&alternatives(MAX_CHECK_ALTERNATIVES)]),
        Err(TokenError::Rejected)
    );

    // At most MAX_QUERY_SIZE in one alternative. `action($a)` is 1, `$a` and `.contains()` are 1 each, and the
    // array is 1 plus one per element, so an array of MAX_QUERY_SIZE - 4 allowed actions is as large as fits.
    let allowed = |n: usize| -> String {
        let items: Vec<String> = (1..n)
            .map(|i| format!("\"action-{i}\""))
            .chain(["\"read\"".to_owned()])
            .collect();
        format!("check if action($a), [{}].contains($a);", items.join(", "))
    };
    assert!(with(&[&allowed(MAX_QUERY_SIZE - 4)]).is_ok());
    assert_eq!(
        with(&[&allowed(MAX_QUERY_SIZE - 3)]),
        Err(TokenError::Rejected)
    );

    // `.all()`, `.any()` and `.matches()` are refused however small.
    for refused in [
        "check if action($a), [\"read\"].any($x -> $x == $a);",
        "check if action($a), [\"read\"].all($x -> $x == $a);",
        "check if action($a), $a.matches(\"^re\");",
    ] {
        assert_eq!(with(&[refused]), Err(TokenError::Rejected), "{refused}");
    }
}

#[test]
fn the_public_key_matches_the_seed() {
    let (seed, public) = generate_issuer_key();
    assert_eq!(public_key_of(&seed).unwrap(), public);
}
