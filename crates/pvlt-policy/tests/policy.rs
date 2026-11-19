//! The policy engine as a table of allow and deny cases, plus the strictness of the policy format.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pvlt_policy::policy::{
    Action, Allowed, Context, Decision, Denial, Policy, Request, RoleLimits,
};

const POLICY: &str = r#"{
  "version": 1,
  "restricted_types": ["id_number"],
  "roles": {
    "verifier": {
      "allow": [{ "types": ["identity", "doc_key", "id_number"], "actions": ["read"] }],
      "require": { "purposes": ["kyc-review", "dispute"], "reason": true },
      "limits": { "read_per_hour": 100 }
    },
    "data-subject": { "allow": [{ "types": ["*"], "actions": ["read"], "when": ["self"] }] },
    "fulfillment": { "allow": [{ "types": ["address"], "actions": ["read"], "when": ["grant:order_open"] }] },
    "app-backend": {
      "allow": [{ "types": ["*"], "actions": ["create", "shred", "rebind"] }],
      "limits": { "create_per_hour": 5000, "shred_per_hour": 50 }
    },
    "support": { "allow": [] }
  }
}"#;

fn s(v: &[&str]) -> Vec<String> {
    v.iter().map(|x| (*x).to_owned()).collect()
}

struct Case {
    name: &'static str,
    roles: &'static [&'static str],
    issuer_roles: &'static [&'static str],
    caller: Option<&'static str>,
    subject: Option<&'static str>,
    purpose: Option<&'static str>,
    reason: Option<&'static str>,
    grants: &'static [&'static str],
    action: Action,
    fact_type: Option<&'static str>,
    subject_matches: bool,
    expect: Decision,
}

fn allow(role: &str, restricted: bool, limits: RoleLimits) -> Decision {
    Decision::Allow(Allowed {
        role: role.to_owned(),
        limits,
        restricted,
    })
}

fn base() -> Case {
    Case {
        name: "",
        roles: &[],
        issuer_roles: &[
            "verifier",
            "data-subject",
            "fulfillment",
            "app-backend",
            "support",
            "admin",
        ],
        caller: None,
        subject: None,
        purpose: None,
        reason: None,
        grants: &[],
        action: Action::Read,
        fact_type: Some("identity"),
        subject_matches: false,
        expect: Decision::Deny(Denial::NoUsableRole),
    }
}

fn cases() -> Vec<Case> {
    let verifier_limits = RoleLimits {
        read_per_hour: Some(100),
        ..RoleLimits::default()
    };
    let backend_limits = RoleLimits {
        create_per_hour: Some(5000),
        shred_per_hour: Some(50),
        ..RoleLimits::default()
    };
    vec![
        Case {
            name: "verifier reads identity with a purpose and a reason",
            roles: &["verifier"],
            caller: Some("user:77"),
            purpose: Some("kyc-review"),
            reason: Some("ticket 1"),
            expect: allow("verifier", false, verifier_limits),
            ..base()
        },
        Case {
            name: "verifier with the second allowed purpose",
            roles: &["verifier"],
            purpose: Some("dispute"),
            reason: Some("x"),
            expect: allow("verifier", false, verifier_limits),
            ..base()
        },
        Case {
            name: "verifier without a purpose",
            roles: &["verifier"],
            reason: Some("x"),
            expect: Decision::Deny(Denial::PurposeRequired),
            ..base()
        },
        Case {
            name: "verifier with a purpose the role does not list",
            roles: &["verifier"],
            purpose: Some("marketing"),
            reason: Some("x"),
            expect: Decision::Deny(Denial::PurposeRequired),
            ..base()
        },
        Case {
            name: "verifier without a reason",
            roles: &["verifier"],
            purpose: Some("kyc-review"),
            expect: Decision::Deny(Denial::ReasonRequired),
            ..base()
        },
        Case {
            name: "verifier with an empty reason",
            roles: &["verifier"],
            purpose: Some("kyc-review"),
            reason: Some(""),
            expect: Decision::Deny(Denial::ReasonRequired),
            ..base()
        },
        Case {
            name: "verifier reads an address, which the role does not cover",
            roles: &["verifier"],
            purpose: Some("kyc-review"),
            reason: Some("x"),
            fact_type: Some("address"),
            expect: Decision::Deny(Denial::NotAllowed),
            ..base()
        },
        Case {
            name: "verifier cannot shred",
            roles: &["verifier"],
            purpose: Some("kyc-review"),
            reason: Some("x"),
            action: Action::Shred,
            expect: Decision::Deny(Denial::NotAllowed),
            ..base()
        },
        Case {
            name: "verifier cannot create",
            roles: &["verifier"],
            purpose: Some("kyc-review"),
            reason: Some("x"),
            action: Action::Create,
            expect: Decision::Deny(Denial::NotAllowed),
            ..base()
        },
        Case {
            name: "reading a restricted type is allowed but flagged for dual control",
            roles: &["verifier"],
            purpose: Some("kyc-review"),
            reason: Some("x"),
            fact_type: Some("id_number"),
            expect: allow("verifier", true, verifier_limits),
            ..base()
        },
        Case {
            name: "data subject reads their own fact",
            roles: &["data-subject"],
            caller: Some("user:1"),
            subject: Some("user:1"),
            subject_matches: true,
            expect: allow("data-subject", false, RoleLimits::default()),
            ..base()
        },
        Case {
            name: "data subject reads someone else's fact",
            roles: &["data-subject"],
            caller: Some("user:1"),
            subject: Some("user:1"),
            subject_matches: false,
            expect: Decision::Deny(Denial::ConditionFailed),
            ..base()
        },
        Case {
            name: "token names a different caller and subject",
            roles: &["data-subject"],
            caller: Some("user:2"),
            subject: Some("user:1"),
            subject_matches: true,
            expect: Decision::Deny(Denial::ConditionFailed),
            ..base()
        },
        Case {
            name: "data subject token with no caller",
            roles: &["data-subject"],
            subject: Some("user:1"),
            subject_matches: true,
            expect: Decision::Deny(Denial::ConditionFailed),
            ..base()
        },
        Case {
            name: "data subject token with no subject",
            roles: &["data-subject"],
            caller: Some("user:1"),
            subject_matches: true,
            expect: Decision::Deny(Denial::ConditionFailed),
            ..base()
        },
        Case {
            name: "data subject cannot shred their own facts",
            roles: &["data-subject"],
            caller: Some("user:1"),
            subject: Some("user:1"),
            subject_matches: true,
            action: Action::Shred,
            expect: Decision::Deny(Denial::NotAllowed),
            ..base()
        },
        Case {
            name: "fulfillment reads an address with the grant",
            roles: &["fulfillment"],
            grants: &["order_open"],
            fact_type: Some("address"),
            expect: allow("fulfillment", false, RoleLimits::default()),
            ..base()
        },
        Case {
            name: "fulfillment without the grant",
            roles: &["fulfillment"],
            fact_type: Some("address"),
            expect: Decision::Deny(Denial::ConditionFailed),
            ..base()
        },
        Case {
            name: "fulfillment with a different grant",
            roles: &["fulfillment"],
            grants: &["order_closed"],
            fact_type: Some("address"),
            expect: Decision::Deny(Denial::ConditionFailed),
            ..base()
        },
        Case {
            name: "fulfillment reads identity, which it does not cover",
            roles: &["fulfillment"],
            grants: &["order_open"],
            expect: Decision::Deny(Denial::NotAllowed),
            ..base()
        },
        Case {
            name: "the service creates any type",
            roles: &["app-backend"],
            action: Action::Create,
            fact_type: Some("anything"),
            expect: allow("app-backend", false, backend_limits),
            ..base()
        },
        Case {
            name: "the service cannot read without a user's role",
            roles: &["app-backend"],
            expect: Decision::Deny(Denial::NotAllowed),
            ..base()
        },
        Case {
            name: "the service shreds a whole scope or subject (no single type)",
            roles: &["app-backend"],
            action: Action::Shred,
            fact_type: None,
            expect: allow("app-backend", false, backend_limits),
            ..base()
        },
        Case {
            name: "a verifier cannot shred a whole scope: only a rule for every type covers it",
            roles: &["verifier"],
            purpose: Some("kyc-review"),
            reason: Some("x"),
            action: Action::Shred,
            fact_type: None,
            expect: Decision::Deny(Denial::NotAllowed),
            ..base()
        },
        Case {
            name: "the issuer is not registered for the asserted role",
            roles: &["verifier"],
            issuer_roles: &["app-backend"],
            purpose: Some("kyc-review"),
            reason: Some("x"),
            expect: Decision::Deny(Denial::NoUsableRole),
            ..base()
        },
        Case {
            name: "a signed role the policy does not define",
            roles: &["root"],
            expect: Decision::Deny(Denial::NoUsableRole),
            ..base()
        },
        Case {
            name: "admin is registered but the policy gives it no read",
            roles: &["admin"],
            expect: Decision::Deny(Denial::NoUsableRole),
            ..base()
        },
        Case {
            name: "a role with no rules allows nothing",
            roles: &["support"],
            expect: Decision::Deny(Denial::NotAllowed),
            ..base()
        },
        Case {
            name: "no roles at all",
            roles: &[],
            expect: Decision::Deny(Denial::NoUsableRole),
            ..base()
        },
        Case {
            name: "a second role rescues a request the first denies",
            roles: &["data-subject", "verifier"],
            caller: Some("user:77"),
            purpose: Some("kyc-review"),
            reason: Some("x"),
            expect: allow("verifier", false, verifier_limits),
            ..base()
        },
        Case {
            name: "the issuer may assert one of two roles, so only that one counts",
            roles: &["data-subject", "verifier"],
            issuer_roles: &["data-subject"],
            caller: Some("user:77"),
            purpose: Some("kyc-review"),
            reason: Some("x"),
            expect: Decision::Deny(Denial::ConditionFailed),
            ..base()
        },
    ]
}

#[test]
fn the_decision_table() {
    let policy = Policy::from_json(POLICY.as_bytes()).unwrap();
    for c in cases() {
        let roles = s(c.roles);
        let issuer_roles = s(c.issuer_roles);
        let grants = s(c.grants);
        let ctx = Context {
            roles: &roles,
            issuer_roles: &issuer_roles,
            caller: c.caller,
            subject: c.subject,
            purpose: c.purpose,
            reason: c.reason,
            grants: &grants,
        };
        let req = Request {
            action: c.action,
            fact_type: c.fact_type,
            subject_matches: c.subject_matches,
        };
        assert_eq!(policy.decide(&ctx, &req), c.expect, "{}", c.name);
    }
}

#[test]
fn the_default_is_deny_for_every_request_against_an_empty_policy() {
    let policy = Policy::from_json(br#"{"version":1}"#).unwrap();
    for action in [Action::Create, Action::Read, Action::Shred, Action::Rebind] {
        let roles = s(&["verifier", "admin", "root"]);
        let ctx = Context {
            roles: &roles,
            issuer_roles: &roles,
            caller: Some("a"),
            subject: Some("a"),
            purpose: Some("p"),
            reason: Some("r"),
            grants: &[],
        };
        let req = Request {
            action,
            fact_type: Some("identity"),
            subject_matches: true,
        };
        assert_eq!(
            policy.decide(&ctx, &req),
            Decision::Deny(Denial::NoUsableRole)
        );
    }
}

#[test]
fn the_compat_token_is_refused_everything_unless_the_policy_defines_a_compat_role() {
    let none = Policy::from_json(POLICY.as_bytes()).unwrap();
    assert!(!none.has_compat_role());
    for action in [Action::Create, Action::Read, Action::Shred] {
        let req = Request {
            action,
            fact_type: Some("ascii"),
            subject_matches: false,
        };
        assert_eq!(
            none.decide_compat(&req),
            Decision::Deny(Denial::NoUsableRole),
            "{action:?}"
        );
        assert_eq!(
            Policy::default().decide_compat(&req),
            Decision::Deny(Denial::NoUsableRole),
            "no policy at all: {action:?}"
        );
    }
    let narrowed = Policy::from_json(br#"{"version":1,"roles":{"compat":{"allow":[{"types":["*"],"actions":["create","read"]}],"limits":{"read_per_hour":10}}}}"#).unwrap();
    let read = Request {
        action: Action::Read,
        fact_type: Some("ascii"),
        subject_matches: false,
    };
    let shred = Request {
        action: Action::Shred,
        fact_type: Some("ascii"),
        subject_matches: false,
    };
    match narrowed.decide_compat(&read) {
        Decision::Allow(a) => assert_eq!(a.limits.read_per_hour, Some(10)),
        other => panic!("{other:?}"),
    }
    assert_eq!(
        narrowed.decide_compat(&shred),
        Decision::Deny(Denial::NotAllowed)
    );
    // The compat token states no purpose, so a role that requires one can never allow it.
    let strict = Policy::from_json(br#"{"version":1,"roles":{"compat":{"allow":[{"types":["*"],"actions":["read"]}],"require":{"purposes":["x"]}}}}"#).unwrap();
    assert_eq!(
        strict.decide_compat(&read),
        Decision::Deny(Denial::PurposeRequired)
    );
    // Nor can a self-access rule, which needs a caller and subject the compat token does not have.
    let selfish = Policy::from_json(br#"{"version":1,"roles":{"compat":{"allow":[{"types":["*"],"actions":["read"],"when":["self"]}]}}}"#).unwrap();
    assert_eq!(
        selfish.decide_compat(&read),
        Decision::Deny(Denial::ConditionFailed)
    );
}

#[test]
fn a_compat_read_of_a_restricted_type_is_flagged_for_dual_control() {
    let p = Policy::from_json(br#"{"version":1,"restricted_types":["base64"],"roles":{"compat":{"allow":[{"types":["*"],"actions":["create","read"]}]}}}"#).unwrap();
    let req = |action, t| Request {
        action,
        fact_type: Some(t),
        subject_matches: false,
    };
    let flagged = |d: Decision| match d {
        Decision::Allow(a) => a.restricted,
        Decision::Deny(d) => panic!("{d:?}"),
    };
    assert!(flagged(p.decide_compat(&req(Action::Read, "base64"))));
    assert!(!flagged(p.decide_compat(&req(Action::Read, "ascii"))));
    // Only a read discloses; creating a restricted type needs nothing extra.
    assert!(!flagged(p.decide_compat(&req(Action::Create, "base64"))));
}

#[test]
fn totals_are_parsed_kept_in_canonical_form_and_reported_when_missing() {
    let p = Policy::from_json(br#"{"version":1,"roles":{
        "a":{"allow":[{"types":["*"],"actions":["read"]}],"limits":{"read_per_hour":5,"total_read_per_hour":50}},
        "b":{"allow":[{"types":["*"],"actions":["read"]}],"limits":{"read_per_hour":5}},
        "c":{"allow":[{"types":["*"],"actions":["read"]}]}}}"#).unwrap();
    let a = p.roles["a"].limits;
    assert_eq!(
        (a.for_action(Action::Read), a.total_for_action(Action::Read)),
        (Some(5), Some(50))
    );
    assert_eq!(p.roles_without_totals(), ["b"]);
    let again = Policy::from_json(&p.canonical_json().unwrap()).unwrap();
    assert_eq!(again, p);
    // A policy without totals keeps the hash it had before totals existed.
    let old = Policy::from_json(POLICY.as_bytes()).unwrap();
    assert!(
        !String::from_utf8(old.canonical_json().unwrap())
            .unwrap()
            .contains("total_")
    );
}

#[test]
fn a_policy_is_parsed_strictly() {
    let bad: &[(&str, &str)] = &[
        ("not json", "nope"),
        ("wrong version", r#"{"version":2}"#),
        ("no version", r#"{}"#),
        ("an unknown top-level field", r#"{"version":1,"rolez":{}}"#),
        (
            "an unknown role field",
            r#"{"version":1,"roles":{"a":{"allows":[]}}}"#,
        ),
        (
            "an unknown rule field",
            r#"{"version":1,"roles":{"a":{"allow":[{"types":["x"],"actions":["read"],"whenn":[]}]}}}"#,
        ),
        (
            "an unknown action",
            r#"{"version":1,"roles":{"a":{"allow":[{"types":["x"],"actions":["delete"]}]}}}"#,
        ),
        (
            "a rule with no actions",
            r#"{"version":1,"roles":{"a":{"allow":[{"types":["x"],"actions":[]}]}}}"#,
        ),
        (
            "a rule with no types",
            r#"{"version":1,"roles":{"a":{"allow":[{"types":[],"actions":["read"]}]}}}"#,
        ),
        (
            "an unknown condition",
            r#"{"version":1,"roles":{"a":{"allow":[{"types":["x"],"actions":["read"],"when":["caller == subject"]}]}}}"#,
        ),
        (
            "an empty grant name",
            r#"{"version":1,"roles":{"a":{"allow":[{"types":["x"],"actions":["read"],"when":["grant:"]}]}}}"#,
        ),
        (
            "a wildcard in a role name",
            r#"{"version":1,"roles":{"a*":{}}}"#,
        ),
        ("an empty role name", r#"{"version":1,"roles":{"":{}}}"#),
        (
            "a role name with a space",
            r#"{"version":1,"roles":{"a b":{}}}"#,
        ),
        (
            "a wildcard restricted type",
            r#"{"version":1,"restricted_types":["*"]}"#,
        ),
        (
            "a purpose with a space",
            r#"{"version":1,"roles":{"a":{"require":{"purposes":["a b"]}}}}"#,
        ),
        (
            "a negative limit",
            r#"{"version":1,"roles":{"a":{"limits":{"read_per_hour":-1}}}}"#,
        ),
        (
            "a limit for an unknown action",
            r#"{"version":1,"roles":{"a":{"limits":{"delete_per_hour":1}}}}"#,
        ),
    ];
    for (name, doc) in bad {
        let err = Policy::from_json(doc.as_bytes());
        assert!(err.is_err(), "{name} was accepted");
        assert!(
            !err.unwrap_err().to_string().contains("caller == subject"),
            "{name} echoed its input"
        );
    }
    let many: String = format!(
        r#"{{"version":1,"roles":{{{}}}}}"#,
        (0..300)
            .map(|i| format!("\"r{i}\":{{}}"))
            .collect::<Vec<_>>()
            .join(",")
    );
    assert!(Policy::from_json(many.as_bytes()).is_err());
}

#[test]
fn the_canonical_form_and_hash_ignore_layout_and_order_but_not_meaning() {
    let a = Policy::from_json(POLICY.as_bytes()).unwrap();
    let reordered = r#"{"roles":{"support":{"allow":[]},"verifier":{"limits":{"read_per_hour":100},"require":{"reason":true,"purposes":["dispute","kyc-review"]},"allow":[{"actions":["read"],"types":["id_number","doc_key","identity"]}]},
      "app-backend":{"limits":{"shred_per_hour":50,"create_per_hour":5000},"allow":[{"actions":["rebind","shred","create"],"types":["*"]}]},
      "fulfillment":{"allow":[{"when":["grant:order_open"],"types":["address"],"actions":["read"]}]},
      "data-subject":{"allow":[{"types":["*"],"when":["self"],"actions":["read"]}]}},"restricted_types":["id_number"],"version":1}"#;
    let b = Policy::from_json(reordered.as_bytes()).unwrap();
    assert_eq!(a.canonical_json().unwrap(), b.canonical_json().unwrap());
    assert_eq!(a.hash().unwrap(), b.hash().unwrap());
    // The canonical form parses back to the same policy, and is itself canonical.
    let canon = a.canonical_json().unwrap();
    let again = Policy::from_json(&canon).unwrap();
    assert_eq!(again.canonical_json().unwrap(), canon);

    // Changing anything that changes meaning changes the hash.
    for changed in [
        POLICY.replace(r#""read_per_hour": 100"#, r#""read_per_hour": 101"#),
        POLICY.replace(r#"["id_number"]"#, r#"[]"#),
        POLICY.replace(r#""reason": true"#, r#""reason": false"#),
        POLICY.replace(r#""grant:order_open""#, r#""grant:order_closed""#),
        POLICY.replace(
            r#""support": { "allow": [] }"#,
            r#""support": { "allow": [] }, "extra": {}"#,
        ),
    ] {
        let c = Policy::from_json(changed.as_bytes()).unwrap();
        assert_ne!(c.hash().unwrap(), a.hash().unwrap(), "{changed}");
    }
}
