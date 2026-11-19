//! M3: delegated tokens, issuers, policy, role separation, rate limits and dual control, over HTTP.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::{Arc, Mutex};

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use pvlt_core::audit::{Action, AuditEvent, Auditor};
use pvlt_core::engine::{Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::memory::{MemKeyStore, MemObjectStore};
use pvlt_core::objects::ObjectStore as _;
use pvlt_core::seal::init_shamir;
use pvlt_core::store::KeyStore;
use pvlt_mem::{Arena, LockPolicy};
use pvlt_server::app::{Admin, App, Token};
use pvlt_server::tokens::{Claims, generate_issuer_key, mint};
use pvlt_server::{admin, routes};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

const ALICE: &str = "alice-admin-token-0123456789";
const BOB: &str = "bob-admin-token-0123456789";
const COMPAT: &str = "compat-token-for-tests";
const SECRET: &str = "Quentin-Q.-Nightingale-1987-03-09";

const POLICY: &str = r#"{
  "version": 1,
  "restricted_types": ["id_number"],
  "roles": {
    "verifier": {
      "allow": [{ "types": ["identity", "doc_key", "id_number"], "actions": ["read"] }],
      "require": { "purposes": ["kyc-review"], "reason": true },
      "limits": { "read_per_hour": 1000 }
    },
    "data-subject": { "allow": [{ "types": ["*"], "actions": ["read"], "when": ["self"] }] },
    "fulfillment": { "allow": [{ "types": ["address"], "actions": ["read"], "when": ["grant:order_open"] }] },
    "app-backend": { "allow": [{ "types": ["*"], "actions": ["create", "shred"] }] }
  }
}"#;

type Event = (String, Action, Option<Uuid>, &'static str);

#[derive(Default, Clone)]
struct Recorder(Arc<Mutex<Vec<Event>>>);

impl Auditor for Recorder {
    fn record(&self, e: &AuditEvent<'_>) {
        self.0
            .lock()
            .unwrap()
            .push((e.principal.to_owned(), e.action, e.fact_id, e.outcome));
    }
}

type TestApp = App<MemKeyStore, MemObjectStore, Recorder>;

struct Rig {
    app: Arc<TestApp>,
    data: Router,
    admin: Router,
    seed: [u8; 32],
    recorder: Recorder,
}

fn now() -> i64 {
    OffsetDateTime::now_utc().unix_timestamp()
}

async fn call(
    router: &Router,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Option<Value>,
) -> (StatusCode, Value, String) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(b) = bearer {
        req = req.header("Authorization", format!("Bearer {b}"));
    }
    let req = req
        .body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
        .unwrap();
    let res = router.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    )
}

async fn rig_with(break_glass: bool, policy: Option<&str>) -> Rig {
    let a = Arena::new(256, LockPolicy::BestEffort).unwrap();
    let init = init_shamir(&a, 2, 3).unwrap();
    let ring = Keyring::new(a);
    ring.unseal(init.root);
    let recorder = Recorder::default();
    let engine = Engine::new(
        ring,
        MemKeyStore::new(),
        MemObjectStore::new(),
        recorder.clone(),
        Limits::default(),
    );
    let app = Arc::new(
        App::new(engine, [3; 16], Some(Token::new(COMPAT)), None, init.config)
            .with_admins(vec![
                Admin {
                    name: "alice".into(),
                    token: Token::new(ALICE),
                },
                Admin {
                    name: "bob".into(),
                    token: Token::new(BOB),
                },
            ])
            .with_access_limits(300, break_glass),
    );
    app.reload_access().await.unwrap();
    let (seed, public) = generate_issuer_key();
    let rig = Rig {
        data: routes::data_router(Arc::clone(&app)),
        admin: admin::router(Arc::clone(&app)),
        app,
        seed,
        recorder,
    };
    // Register the issuer for the roles a typical service would be allowed to assert, then set the policy.
    let (status, ..) = call(
        &rig.admin,
        Method::POST,
        "/v2/admin/issuers",
        Some(ALICE),
        Some(json!({"name":"backend","public_key":hex::encode(public),"roles":["verifier","data-subject","fulfillment","app-backend"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    if let Some(p) = policy.or(Some(POLICY)) {
        let (status, ..) = call_raw_put(&rig, p).await;
        assert_eq!(status, StatusCode::OK);
    }
    rig
}

async fn rig() -> Rig {
    rig_with(false, None).await
}

async fn call_raw_put(r: &Rig, policy: &str) -> (StatusCode, Value, String) {
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/v2/admin/policy")
        .header("Authorization", format!("Bearer {ALICE}"))
        .body(Body::from(policy.to_owned()))
        .unwrap();
    let res = r.admin.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    )
}

fn claims(roles: &[&str]) -> Claims {
    Claims {
        issuer_key_id: 1,
        roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        request_id: "req-1".into(),
        expires: now() + 60,
        ..Claims::default()
    }
}

fn token(r: &Rig, c: &Claims) -> String {
    mint(&r.seed, c).unwrap()
}

async fn create(r: &Rig, subject: &str, fact_type: &str, scope: &str, value: &str) -> Uuid {
    let t = token(r, &claims(&["app-backend"]));
    let (status, body, text) = call(
        &r.data,
        Method::POST,
        "/v2/facts",
        Some(&t),
        Some(json!({"type":fact_type,"scope":scope,"subject":subject,"value":value})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
}

async fn read(r: &Rig, id: Uuid, c: &Claims) -> (StatusCode, Value, String) {
    let t = token(r, c);
    call(
        &r.data,
        Method::GET,
        &format!("/v2/facts/{id}"),
        Some(&t),
        None,
    )
    .await
}

fn verifier() -> Claims {
    Claims {
        caller: Some("user:77".into()),
        purpose: Some("kyc-review".into()),
        reason: Some("ticket 4411".into()),
        ..claims(&["verifier"])
    }
}

// --- Authentication ----------------------------------------------------------------------------------------

#[tokio::test]
async fn a_service_creates_and_a_verifier_reads_with_a_purpose_and_a_reason() {
    let r = rig().await;
    let id = create(&r, "user:1234", "identity", "kyc-doc:1", SECRET).await;
    let (status, body, _) = read(&r, id, &verifier()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (body["value"].as_str(), body["type"].as_str()),
        (Some(SECRET), Some("identity"))
    );
}

#[tokio::test]
async fn requests_without_a_good_token_are_401_and_say_nothing_about_why() {
    let r = rig().await;
    let id = create(&r, "u", "identity", "s", "v").await;
    let good = token(&r, &verifier());
    let expired = token(
        &r,
        &Claims {
            expires: now() - 5,
            ..verifier()
        },
    );
    let too_long = token(
        &r,
        &Claims {
            expires: now() + 100_000,
            ..verifier()
        },
    );
    let unknown_issuer = token(
        &r,
        &Claims {
            issuer_key_id: 99,
            ..verifier()
        },
    );
    let (stranger, _) = generate_issuer_key();
    let forged = mint(&stranger, &verifier()).unwrap();
    for (name, bearer) in [
        ("none", None),
        ("garbage", Some("not-a-token".to_owned())),
        ("expired", Some(expired)),
        ("a lifetime beyond the maximum", Some(too_long)),
        ("an unregistered issuer", Some(unknown_issuer)),
        ("the wrong signing key", Some(forged)),
        (
            "a damaged token",
            Some(format!("{}x", &good[..good.len() - 3])),
        ),
    ] {
        let (status, body, text) = call(
            &r.data,
            Method::GET,
            &format!("/v2/facts/{id}"),
            bearer.as_deref(),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name}");
        assert_eq!(body["error"], "denied", "{name}");
        assert!(
            !text.contains("expired") && !text.contains("signature"),
            "{name} says why: {text}"
        );
    }
}

#[tokio::test]
async fn the_static_compat_token_and_an_admin_token_are_not_request_tokens() {
    let r = rig().await;
    let id = create(&r, "u", "identity", "s", "v").await;
    for bearer in [COMPAT, ALICE] {
        let (status, ..) = call(
            &r.data,
            Method::GET,
            &format!("/v2/facts/{id}"),
            Some(bearer),
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
}

#[tokio::test]
async fn attenuation_narrows_a_token_and_cannot_add_a_role() {
    let r = rig().await;
    let id = create(&r, "u", "identity", "s", "v").await;
    let base = token(&r, &verifier());
    let keys = r.app.access();
    // Shortened: fine until it runs out.
    let shorter = pvlt_server::tokens::attenuate_expiry(&base, keys.as_ref(), now() + 30).unwrap();
    assert_eq!(
        call(
            &r.data,
            Method::GET,
            &format!("/v2/facts/{id}"),
            Some(&shorter),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let spent = pvlt_server::tokens::attenuate_expiry(&base, keys.as_ref(), now() - 1).unwrap();
    assert_eq!(
        call(
            &r.data,
            Method::GET,
            &format!("/v2/facts/{id}"),
            Some(&spent),
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    // A holder who adds a role in a later block gains nothing.
    let plain = token(&r, &claims(&["data-subject"]));
    let sneaky = pvlt_server::tokens::attenuate_with_fact(
        &plain,
        keys.as_ref(),
        "role(\"verifier\"); purpose(\"kyc-review\"); reason(\"x\");",
    )
    .unwrap();
    assert_eq!(
        call(
            &r.data,
            Method::GET,
            &format!("/v2/facts/{id}"),
            Some(&sneaky),
            None
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
}

// --- Issuers -----------------------------------------------------------------------------------------------

#[tokio::test]
async fn an_issuer_can_only_assert_the_roles_it_is_registered_for() {
    let r = rig().await;
    let id = create(&r, "u", "identity", "s", "v").await;
    let (seed, public) = generate_issuer_key();
    let (status, body, _) = call(
        &r.admin,
        Method::POST,
        "/v2/admin/issuers",
        Some(ALICE),
        Some(json!({"name":"marketing","public_key":hex::encode(public),"roles":["app-backend"]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let key_id = u32::try_from(body["key_id"].as_u64().unwrap()).unwrap();
    // The policy has a verifier role and the token is genuine, but this issuer may not assert it.
    let t = mint(
        &seed,
        &Claims {
            issuer_key_id: key_id,
            ..verifier()
        },
    )
    .unwrap();
    let (status, body, _) = call(
        &r.data,
        Method::GET,
        &format!("/v2/facts/{id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(
        (status, body["message"].clone()),
        (StatusCode::FORBIDDEN, json!("no_usable_role"))
    );
}

#[tokio::test]
async fn disabling_an_issuer_stops_its_tokens_at_once_and_enabling_restores_them() {
    let r = rig().await;
    let id = create(&r, "u", "identity", "s", "v").await;
    let t = token(&r, &verifier());
    let path = format!("/v2/facts/{id}");
    let get = || call(&r.data, Method::GET, &path, Some(&t), None);
    assert_eq!(get().await.0, StatusCode::OK);
    let (status, ..) = call(
        &r.admin,
        Method::POST,
        "/v2/admin/issuers/1/disable",
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(get().await.0, StatusCode::UNAUTHORIZED);
    call(
        &r.admin,
        Method::POST,
        "/v2/admin/issuers/1/enable",
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(get().await.0, StatusCode::OK);
    let (status, ..) = call(
        &r.admin,
        Method::POST,
        "/v2/admin/issuers/99/disable",
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn issuer_registration_is_validated_and_names_are_unique() {
    let r = rig().await;
    let (_, public) = generate_issuer_key();
    let ok = json!({"name":"second","public_key":hex::encode(public),"roles":[]});
    assert_eq!(
        call(
            &r.admin,
            Method::POST,
            "/v2/admin/issuers",
            Some(ALICE),
            Some(ok.clone())
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &r.admin,
            Method::POST,
            "/v2/admin/issuers",
            Some(ALICE),
            Some(ok)
        )
        .await
        .0,
        StatusCode::CONFLICT
    );
    for bad in [
        json!({"name":"x","public_key":"abcd","roles":[]}),
        json!({"name":"","public_key":hex::encode(public),"roles":[]}),
        json!({"name":"a b","public_key":hex::encode(public),"roles":[]}),
        json!({"name":"x","public_key":hex::encode(public),"roles":["bad role"]}),
        json!({"name":"x","public_key":hex::encode(public)}),
    ] {
        assert_eq!(
            call(
                &r.admin,
                Method::POST,
                "/v2/admin/issuers",
                Some(ALICE),
                Some(bad)
            )
            .await
            .0,
            StatusCode::BAD_REQUEST
        );
    }
    let (_, list, _) = call(
        &r.admin,
        Method::GET,
        "/v2/admin/issuers",
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(list.as_array().unwrap().len(), 2);
}

// --- Policy through HTTP -------------------------------------------------------------------------------------

#[tokio::test]
async fn the_decision_table_over_http() {
    let r = rig().await;
    let id_fact = create(&r, "user:1234", "identity", "kyc-doc:1", SECRET).await;
    let address = create(&r, "user:1234", "address", "physical-order:9", "1 Main St").await;
    let other_persons = create(&r, "user:9999", "identity", "kyc-doc:2", "someone else").await;

    let cases: Vec<(&str, Uuid, Claims, StatusCode, &str)> = vec![
        (
            "verifier with purpose and reason",
            id_fact,
            verifier(),
            StatusCode::OK,
            "",
        ),
        (
            "verifier without a purpose",
            id_fact,
            Claims {
                purpose: None,
                ..verifier()
            },
            StatusCode::FORBIDDEN,
            "purpose",
        ),
        (
            "verifier with a wrong purpose",
            id_fact,
            Claims {
                purpose: Some("marketing".into()),
                ..verifier()
            },
            StatusCode::FORBIDDEN,
            "purpose",
        ),
        (
            "verifier without a reason",
            id_fact,
            Claims {
                reason: None,
                ..verifier()
            },
            StatusCode::FORBIDDEN,
            "reason",
        ),
        (
            "verifier reading an address",
            address,
            verifier(),
            StatusCode::FORBIDDEN,
            "not_allowed",
        ),
        (
            "the data subject reads their own fact",
            id_fact,
            Claims {
                caller: Some("user:1234".into()),
                subject: Some("user:1234".into()),
                ..claims(&["data-subject"])
            },
            StatusCode::OK,
            "",
        ),
        (
            "a data subject reads someone else's",
            other_persons,
            Claims {
                caller: Some("user:1234".into()),
                subject: Some("user:1234".into()),
                ..claims(&["data-subject"])
            },
            StatusCode::FORBIDDEN,
            "condition_failed",
        ),
        (
            "a token claiming to be another subject",
            id_fact,
            Claims {
                caller: Some("user:1".into()),
                subject: Some("user:9999".into()),
                ..claims(&["data-subject"])
            },
            StatusCode::FORBIDDEN,
            "condition_failed",
        ),
        (
            "fulfillment with the grant",
            address,
            Claims {
                grants: vec!["order_open".into()],
                ..claims(&["fulfillment"])
            },
            StatusCode::OK,
            "",
        ),
        (
            "fulfillment without the grant",
            address,
            claims(&["fulfillment"]),
            StatusCode::FORBIDDEN,
            "condition_failed",
        ),
        (
            "the service cannot read",
            id_fact,
            claims(&["app-backend"]),
            StatusCode::FORBIDDEN,
            "not_allowed",
        ),
        (
            "a role the policy never heard of",
            id_fact,
            claims(&["root"]),
            StatusCode::FORBIDDEN,
            "no_usable_role",
        ),
        (
            "no roles",
            id_fact,
            claims(&[]),
            StatusCode::FORBIDDEN,
            "no_usable_role",
        ),
    ];
    for (name, id, c, want, code) in cases {
        let (status, body, text) = read(&r, id, &c).await;
        assert_eq!(status, want, "{name}: {text}");
        if want == StatusCode::FORBIDDEN {
            assert_eq!(body["message"], code, "{name}");
        }
        if want != StatusCode::OK {
            assert!(!text.contains(SECRET), "{name} leaked a value in an error");
        }
    }
}

#[tokio::test]
async fn a_read_of_a_shredded_or_missing_fact_is_410_or_404() {
    let r = rig().await;
    let id = create(&r, "u", "identity", "s", "v").await;
    let t = token(&r, &claims(&["app-backend"]));
    let (status, body, _) = call(
        &r.data,
        Method::DELETE,
        &format!("/v2/facts/{id}"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(
        (status, body["outcome"].clone()),
        (StatusCode::OK, json!("shredded"))
    );
    assert_eq!(read(&r, id, &verifier()).await.0, StatusCode::GONE);
    assert_eq!(
        read(&r, Uuid::from_bytes([9; 16]), &verifier()).await.0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn token_limits_confine_a_token_to_one_fact_scope_subject_or_action() {
    let r = rig().await;
    let mine = create(&r, "user:1", "identity", "kyc-doc:1", "mine").await;
    let theirs = create(&r, "user:2", "identity", "kyc-doc:2", "theirs").await;
    let get = |id, extra: fn(Claims, Uuid) -> Claims| {
        let c = extra(verifier(), mine);
        let r = &r;
        async move { read(r, id, &c).await.0 }
    };
    assert_eq!(
        get(mine, |c, f| Claims {
            resource_fact: Some(f),
            ..c
        })
        .await,
        StatusCode::OK
    );
    assert_eq!(
        get(theirs, |c, f| Claims {
            resource_fact: Some(f),
            ..c
        })
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get(mine, |c, _| Claims {
            resource_scope: Some("kyc-doc:1".into()),
            ..c
        })
        .await,
        StatusCode::OK
    );
    assert_eq!(
        get(theirs, |c, _| Claims {
            resource_scope: Some("kyc-doc:1".into()),
            ..c
        })
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get(mine, |c, _| Claims {
            resource_subject: Some("user:1".into()),
            ..c
        })
        .await,
        StatusCode::OK
    );
    assert_eq!(
        get(theirs, |c, _| Claims {
            resource_subject: Some("user:1".into()),
            ..c
        })
        .await,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        get(mine, |c, _| Claims {
            actions: vec!["read".into()],
            ..c
        })
        .await,
        StatusCode::OK
    );
    assert_eq!(
        get(mine, |c, _| Claims {
            actions: vec!["create".into()],
            ..c
        })
        .await,
        StatusCode::FORBIDDEN
    );
}

#[tokio::test]
async fn a_policy_change_applies_at_once_and_a_bad_policy_changes_nothing() {
    let r = rig().await;
    let id = create(&r, "u", "identity", "s", "v").await;
    assert_eq!(read(&r, id, &verifier()).await.0, StatusCode::OK);

    let (status, before, _) =
        call(&r.admin, Method::GET, "/v2/admin/policy", Some(ALICE), None).await;
    assert_eq!(status, StatusCode::OK);
    let tighter = POLICY.replace(
        r#""types": ["identity", "doc_key", "id_number"]"#,
        r#""types": ["doc_key"]"#,
    );
    let (status, after, _) = call_raw_put(&r, &tighter).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        after["version"].as_i64().unwrap(),
        before["version"].as_i64().unwrap() + 1
    );
    assert_ne!(after["hash"], before["hash"]);
    assert_eq!(read(&r, id, &verifier()).await.0, StatusCode::FORBIDDEN);

    // A policy with a typo is refused, says so without echoing it, and the policy in force is unchanged.
    let (status, _, text) =
        call_raw_put(&r, r#"{"version":1,"rolez":{"secret-role-name":{}}}"#).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!text.contains("secret-role-name"));
    let (_, still, _) = call(&r.admin, Method::GET, "/v2/admin/policy", Some(ALICE), None).await;
    assert_eq!(still["hash"], after["hash"]);
    assert_eq!(read(&r, id, &verifier()).await.0, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn with_no_policy_everything_on_v2_is_denied_and_the_compat_token_still_works() {
    let a = Arena::new(256, LockPolicy::BestEffort).unwrap();
    let init = init_shamir(&a, 2, 3).unwrap();
    let ring = Keyring::new(a);
    ring.unseal(init.root);
    let engine = Engine::new(
        ring,
        MemKeyStore::new(),
        MemObjectStore::new(),
        Recorder::default(),
        Limits::default(),
    );
    let app = Arc::new(App::new(
        engine,
        [3; 16],
        Some(Token::new(COMPAT)),
        None,
        init.config,
    ));
    app.reload_access().await.unwrap();
    let data = routes::data_router(app);
    let (status, ..) = call(
        &data,
        Method::POST,
        "/v2/facts",
        Some("anything"),
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    let req = Request::builder()
        .method(Method::POST)
        .uri("/api/v1/facts")
        .header("X-OPV-GRANT-TOKEN", COMPAT)
        .body(Body::from(
            json!({"fact_type_slug":"ascii","scope_custom_id":"s","value":"v"}).to_string(),
        ))
        .unwrap();
    assert_eq!(
        data.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_compat_token_can_be_narrowed_by_a_compat_role() {
    let policy = r#"{"version":1,"roles":{"compat":{"allow":[{"types":["*"],"actions":["create","read"]}]}}}"#;
    let r = rig_with(false, Some(policy)).await;
    let compat = |method: Method, path: String, body: Option<Value>| {
        let data = r.data.clone();
        async move {
            let mut req = Request::builder()
                .method(method)
                .uri(path)
                .header("X-OPV-GRANT-TOKEN", COMPAT);
            if body.is_some() {
                req = req.header("Content-Type", "application/json");
            }
            let res = data
                .oneshot(
                    req.body(Body::from(body.map(|b| b.to_string()).unwrap_or_default()))
                        .unwrap(),
                )
                .await
                .unwrap();
            let status = res.status();
            let bytes = res.into_body().collect().await.unwrap().to_bytes();
            (
                status,
                serde_json::from_slice::<Value>(&bytes).unwrap_or(Value::Null),
            )
        }
    };
    let (status, body) = compat(
        Method::POST,
        "/api/v1/facts".into(),
        Some(json!({"fact_type_slug":"ascii","scope_custom_id":"s","value":"v"})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let id = body["id"].as_str().unwrap().to_owned();
    assert_eq!(
        compat(Method::GET, format!("/api/v1/facts/{id}"), None)
            .await
            .0,
        StatusCode::OK
    );
    // The role does not allow shred, so the compat delete is refused and the fact survives.
    let (status, body) = compat(Method::DELETE, format!("/api/v1/facts/{id}"), None).await;
    assert_eq!(
        (status, body["message"].clone()),
        (StatusCode::FORBIDDEN, json!("not_allowed"))
    );
    assert_eq!(
        compat(Method::GET, format!("/api/v1/facts/{id}"), None)
            .await
            .0,
        StatusCode::OK
    );
}

// --- Role separation -----------------------------------------------------------------------------------------

#[tokio::test]
async fn admin_and_data_credentials_do_not_cross_listeners_and_an_admin_cannot_read() {
    let r = rig().await;
    let id = create(&r, "u", "identity", "s", "v").await;
    let t = token(&r, &verifier());
    // A request token on the admin listener.
    for path in ["/v2/admin/policy", "/v2/admin/issuers"] {
        assert_eq!(
            call(&r.admin, Method::GET, path, Some(&t), None).await.0,
            StatusCode::UNAUTHORIZED,
            "{path}"
        );
    }
    assert_eq!(
        call(&r.admin, Method::PUT, "/v2/admin/policy", Some(&t), None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    // An admin credential on the data listener, and no read route on the admin listener at all.
    assert_eq!(
        call(
            &r.data,
            Method::GET,
            &format!("/v2/facts/{id}"),
            Some(ALICE),
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &r.admin,
            Method::GET,
            &format!("/v2/facts/{id}"),
            Some(ALICE),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &r.admin,
            Method::GET,
            &format!("/api/v1/facts/{id}"),
            Some(ALICE),
            None
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    // And policy cannot make an admin credential a reader: the credential is not a token, whatever roles say.
    let with_admin_role = POLICY.replace(
        r#""app-backend""#,
        r#""admin": {"allow":[{"types":["*"],"actions":["read"]}]}, "app-backend""#,
    );
    assert_eq!(call_raw_put(&r, &with_admin_role).await.0, StatusCode::OK);
    assert_eq!(
        call(
            &r.data,
            Method::GET,
            &format!("/v2/facts/{id}"),
            Some(ALICE),
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
}

// --- Rate limits ---------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_role_limit_stops_a_bulk_reader_and_says_when_to_retry() {
    let r = rig_with(
        false,
        Some(&POLICY.replace("\"read_per_hour\": 1000", "\"read_per_hour\": 4")),
    )
    .await;
    let id = create(&r, "u", "identity", "s", "v").await;
    for _ in 0..4 {
        assert_eq!(read(&r, id, &verifier()).await.0, StatusCode::OK);
    }
    let t = token(&r, &verifier());
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/v2/facts/{id}"))
        .header("Authorization", format!("Bearer {t}"))
        .body(Body::empty())
        .unwrap();
    let res = r.data.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry: u64 = res.headers()["retry-after"]
        .to_str()
        .unwrap()
        .parse()
        .unwrap();
    assert!((1..=3600).contains(&retry));
    // Another caller has their own count; the same caller reading a different action is not limited.
    let other = Claims {
        caller: Some("user:88".into()),
        ..verifier()
    };
    assert_eq!(read(&r, id, &other).await.0, StatusCode::OK);
    assert!(
        r.recorder
            .0
            .lock()
            .unwrap()
            .iter()
            .any(|e| e.3 == "rate_limited")
    );
}

// --- Dual control ----------------------------------------------------------------------------------------------

async fn approval_flow(r: &Rig, fact: Uuid) -> Uuid {
    let (status, body, text) = call(
        &r.admin,
        Method::POST,
        "/v2/admin/approvals",
        Some(ALICE),
        Some(json!({"fact_id": fact})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(body["approved"], false);
    let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    // The requester cannot approve their own request.
    let (status, ..) = call(
        &r.admin,
        Method::POST,
        &format!("/v2/admin/approvals/{id}/approve"),
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, body, _) = call(
        &r.admin,
        Method::POST,
        &format!("/v2/admin/approvals/{id}/approve"),
        Some(BOB),
        None,
    )
    .await;
    assert_eq!(
        (status, body["approved"].clone()),
        (StatusCode::OK, json!(true))
    );
    id
}

#[tokio::test]
async fn a_restricted_read_needs_an_approval_from_a_second_admin_and_works_once() {
    let r = rig().await;
    let id = create(&r, "user:1", "id_number", "kyc-doc:1", "X-123-456").await;
    // No approval named in the token.
    let (status, body, _) = read(&r, id, &verifier()).await;
    assert_eq!(
        (status, body["message"].clone()),
        (StatusCode::FORBIDDEN, json!("approval_required"))
    );

    let approval = approval_flow(&r, id).await;
    let with = Claims {
        approval: Some(approval.to_string()),
        ..verifier()
    };
    let (status, body, _) = read(&r, id, &with).await;
    assert_eq!(
        (status, body["value"].clone()),
        (StatusCode::OK, json!("X-123-456"))
    );
    // Spent.
    let (status, body, _) = read(&r, id, &with).await;
    assert_eq!(
        (status, body["message"].clone()),
        (StatusCode::FORBIDDEN, json!("approval_invalid"))
    );
}

#[tokio::test]
async fn an_approval_is_for_one_fact_and_a_pending_or_unknown_one_does_not_work() {
    let r = rig().await;
    let one = create(&r, "user:1", "id_number", "s", "one").await;
    let two = create(&r, "user:2", "id_number", "s", "two").await;
    let approved = approval_flow(&r, one).await;
    let (_, pending, _) = call(
        &r.admin,
        Method::POST,
        "/v2/admin/approvals",
        Some(ALICE),
        Some(json!({"fact_id": two})),
    )
    .await;
    for (name, fact, approval) in [
        ("an approval for another fact", two, approved.to_string()),
        (
            "a pending approval",
            two,
            pending["id"].as_str().unwrap().to_owned(),
        ),
        (
            "an unknown approval",
            two,
            Uuid::from_bytes([4; 16]).to_string(),
        ),
        ("not even a UUID", two, "nope".to_owned()),
    ] {
        let (status, body, _) = read(
            &r,
            fact,
            &Claims {
                approval: Some(approval),
                ..verifier()
            },
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{name}");
        assert!(
            ["approval_invalid", "approval_required"].contains(&body["message"].as_str().unwrap()),
            "{name}"
        );
    }
    // The approval for the right fact still works after all those attempts.
    let ok = Claims {
        approval: Some(approved.to_string()),
        ..verifier()
    };
    assert_eq!(read(&r, one, &ok).await.0, StatusCode::OK);
}

#[tokio::test]
async fn break_glass_lets_one_admin_approve_alone_only_when_enabled_and_briefly() {
    let off = rig().await;
    let id = create(&off, "user:1", "id_number", "s", "v").await;
    let (status, body, _) = call(
        &off.admin,
        Method::POST,
        "/v2/admin/approvals",
        Some(ALICE),
        Some(json!({"fact_id": id, "break_glass": true})),
    )
    .await;
    assert_eq!(
        (status, body["message"].clone()),
        (StatusCode::FORBIDDEN, json!("break_glass_disabled"))
    );

    let on = rig_with(true, None).await;
    let id = create(&on, "user:1", "id_number", "s", "v").await;
    let (status, body, _) = call(
        &on.admin,
        Method::POST,
        "/v2/admin/approvals",
        Some(ALICE),
        Some(json!({"fact_id": id, "break_glass": true})),
    )
    .await;
    assert_eq!(
        (status, body["approved"].clone()),
        (StatusCode::OK, json!(true))
    );
    let approval = body["id"].as_str().unwrap().to_owned();
    let remaining = body["expires_at_unix"].as_i64().unwrap() - now();
    assert!((1..=300).contains(&remaining), "{remaining}");
    // Break-glass is capped at five minutes; an ordinary approval at fifteen.
    let (status, ..) = call(
        &on.admin,
        Method::POST,
        "/v2/admin/approvals",
        Some(ALICE),
        Some(json!({"fact_id": id, "break_glass": true, "ttl_secs": 301})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, ..) = call(
        &on.admin,
        Method::POST,
        "/v2/admin/approvals",
        Some(ALICE),
        Some(json!({"fact_id": id, "ttl_secs": 901})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, ..) = call(
        &on.admin,
        Method::POST,
        "/v2/admin/approvals",
        Some(ALICE),
        Some(json!({"fact_id": id, "ttl_secs": 0})),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        read(
            &on,
            id,
            &Claims {
                approval: Some(approval),
                ..verifier()
            }
        )
        .await
        .0,
        StatusCode::OK
    );
}

// --- Creating -------------------------------------------------------------------------------------------------

#[tokio::test]
async fn a_batch_is_all_or_nothing_and_each_fact_is_authorized() {
    let r = rig().await;
    let t = token(&r, &claims(&["app-backend"]));
    let (status, body, _) = call(
        &r.data,
        Method::POST,
        "/v2/facts/batch",
        Some(&t),
        Some(json!({"facts":[
            {"type":"doc_key","scope":"kyc-doc:1","subject":"user:1","value_b64":"//4="},
            {"type":"doc_path","scope":"kyc-doc:1","subject":"user:1","value":"kyc/user1/a.bin"}
        ]})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let ids = body["ids"].as_array().unwrap();
    assert_eq!(ids.len(), 2);
    let first = Uuid::parse_str(ids[0].as_str().unwrap()).unwrap();
    let (status, body, _) = read(
        &r,
        first,
        &Claims {
            purpose: Some("kyc-review".into()),
            ..verifier()
        },
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // A non-UTF-8 value comes back as base64.
    assert_eq!(body["value_b64"], "//4=");

    // One fact the role may not create: nothing at all is created. The compat-less service role is allowed any
    // type, so use a token limited to creating nothing but `doc_key`.
    let narrow = token(
        &r,
        &Claims {
            actions: vec!["create".into()],
            resource_scope: Some("kyc-doc:2".into()),
            ..claims(&["app-backend"])
        },
    );
    let (status, ..) = call(
        &r.data,
        Method::POST,
        "/v2/facts/batch",
        Some(&narrow),
        Some(json!({"facts":[
            {"type":"doc_key","scope":"kyc-doc:2","value":"a"},
            {"type":"doc_path","scope":"kyc-doc:OTHER","value":"b"}
        ]})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        r.app.engine.objects().object_count(),
        2,
        "the refused batch must have written nothing"
    );
    // Malformed batches.
    for bad in [
        json!({"facts":[]}),
        json!({"facts":[{"type":"x","scope":"s"}]}),
        json!({"facts":[{"type":"x","scope":"s","value":"a","value_b64":"AA=="}]}),
        json!({}),
    ] {
        let (status, ..) = call(
            &r.data,
            Method::POST,
            "/v2/facts/batch",
            Some(&t),
            Some(bad),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
}

#[tokio::test]
async fn retention_is_bounded_and_turns_into_an_expiry() {
    let r = rig().await;
    let t = token(&r, &claims(&["app-backend"]));
    for bad in [json!(0), json!(36_501), json!(-1)] {
        let (status, ..) = call(
            &r.data,
            Method::POST,
            "/v2/facts",
            Some(&t),
            Some(json!({"type":"address","scope":"s","value":"v","retain_days":bad})),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
    }
    let (status, body, _) = call(
        &r.data,
        Method::POST,
        "/v2/facts",
        Some(&t),
        Some(json!({"type":"address","scope":"s","value":"v","retain_days":30})),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let id = Uuid::parse_str(body["id"].as_str().unwrap()).unwrap();
    let meta = r
        .app
        .engine
        .store()
        .fact_for_read(&[3; 16], &id)
        .await
        .unwrap();
    let days = (meta.fact.fact.expires_at.unwrap() - OffsetDateTime::now_utc()).whole_days();
    assert!((29..=30).contains(&days), "{days}");
}

#[tokio::test]
async fn a_whole_subject_or_scope_is_shredded_only_by_a_role_with_a_rule_for_every_type() {
    let r = rig().await;
    let a = create(&r, "user:1", "identity", "kyc-doc:1", "a").await;
    let b = create(&r, "user:2", "identity", "kyc-doc:2", "b").await;
    let backend = token(&r, &claims(&["app-backend"]));
    let (status, body, _) = call(
        &r.data,
        Method::POST,
        "/v2/shred/subject",
        Some(&backend),
        Some(json!({"subject":"user:1","reason":"subject_request"})),
    )
    .await;
    assert_eq!(
        (status, body["outcome"].clone()),
        (StatusCode::OK, json!("shredded"))
    );
    assert_eq!(read(&r, a, &verifier()).await.0, StatusCode::GONE);
    assert_eq!(read(&r, b, &verifier()).await.0, StatusCode::OK);
    let (status, body, _) = call(
        &r.data,
        Method::POST,
        "/v2/shred/scope",
        Some(&backend),
        Some(json!({"scope":"kyc-doc:2"})),
    )
    .await;
    assert_eq!((status, body["count"].clone()), (StatusCode::OK, json!(1)));
    // A verifier has no shred rule at all.
    let (status, ..) = call(
        &r.data,
        Method::POST,
        "/v2/shred/subject",
        Some(&token(&r, &verifier())),
        Some(json!({"subject":"user:2"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    // A token limited to one subject cannot shred another.
    let limited = token(
        &r,
        &Claims {
            resource_subject: Some("user:7".into()),
            ..claims(&["app-backend"])
        },
    );
    let (status, ..) = call(
        &r.data,
        Method::POST,
        "/v2/shred/subject",
        Some(&limited),
        Some(json!({"subject":"user:8"})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// --- Audit ----------------------------------------------------------------------------------------------------

#[tokio::test]
async fn denials_and_successes_are_reported_with_the_caller_and_never_with_a_value_or_token() {
    let r = rig().await;
    let id = create(&r, "user:1", "identity", "kyc-doc:1", SECRET).await;
    let good = verifier();
    read(&r, id, &good).await;
    read(
        &r,
        id,
        &Claims {
            purpose: None,
            ..verifier()
        },
    )
    .await;
    let bad = format!("{}x", token(&r, &good));
    call(
        &r.data,
        Method::GET,
        &format!("/v2/facts/{id}"),
        Some(&bad),
        None,
    )
    .await;

    let events = r.recorder.0.lock().unwrap().clone();
    let reads: Vec<_> = events
        .iter()
        .filter(|e| e.1 == Action::Read)
        .map(|e| (e.0.as_str(), e.3))
        .collect();
    assert!(reads.contains(&("backend/user:77", "ok")), "{reads:?}");
    assert!(reads.contains(&("backend/user:77", "purpose")), "{reads:?}");
    assert!(
        reads.contains(&("unauthenticated", "bad_token")),
        "{reads:?}"
    );
    let text = format!("{events:?}");
    assert!(
        !text.contains(SECRET) && !text.contains(&bad),
        "an audit event holds a value or a token"
    );
}

// --- M4: the audit log over HTTP ------------------------------------------------------------------------------

async fn audit_rows(r: &Rig) -> Vec<(String, String, Value)> {
    r.app
        .engine
        .store()
        .audit_records(&[3; 16], 0, 10_000)
        .await
        .unwrap()
        .into_iter()
        .map(|row| {
            let line: Value = serde_json::from_slice(&row.line).unwrap();
            (row.kind, row.principal, line["body"].clone())
        })
        .collect()
}

#[tokio::test]
async fn a_v2_read_is_in_the_durable_log_with_the_callers_account_of_themselves() {
    let r = rig().await;
    let id = create(&r, "user:1234", "identity", "kyc-doc:1", SECRET).await;
    let (status, ..) = read(&r, id, &verifier()).await;
    assert_eq!(status, StatusCode::OK);
    let rows = audit_rows(&r).await;
    let (_, principal, body) = rows.iter().find(|(k, ..)| k == "read.grant").unwrap();
    assert_eq!(principal, "backend/user:77");
    assert_eq!(body["roles"], json!(["verifier"]));
    assert_eq!(body["purpose"], "kyc-review");
    assert_eq!(body["reason"], "ticket 4411");
    assert_eq!(body["request_id"], "req-1");
    let policy = r.app.access().policy_hash;
    assert_eq!(body["policy_hash"], hex::encode(policy));
    assert_ne!(body["policy_hash"], hex::encode([0u8; 32]));
    // The create by the service is there too, and no entry holds the value.
    assert!(
        rows.iter()
            .any(|(k, p, _)| k == "create" && p == "backend/service")
    );
    assert!(!format!("{rows:?}").contains("Nightingale"));
}

#[tokio::test]
async fn refusals_are_written_to_the_durable_log_with_their_code() {
    let r = rig().await;
    let id = create(&r, "user:1", "identity", "s", "v").await;
    read(
        &r,
        id,
        &Claims {
            purpose: None,
            ..verifier()
        },
    )
    .await;
    read(&r, id, &claims(&["app-backend"])).await;
    call(
        &r.data,
        Method::GET,
        &format!("/v2/facts/{id}"),
        Some("garbage"),
        None,
    )
    .await;
    let denials: Vec<(String, String)> = audit_rows(&r)
        .await
        .into_iter()
        .filter(|(k, ..)| k == "deny")
        .map(|(_, p, b)| (p, b["denial"].as_str().unwrap().to_owned()))
        .collect();
    assert!(
        denials.contains(&("backend/user:77".into(), "purpose".into())),
        "{denials:?}"
    );
    assert!(
        denials.contains(&("backend/service".into(), "not_allowed".into())),
        "{denials:?}"
    );
    assert!(
        denials.contains(&("unauthenticated".into(), "bad_token".into())),
        "{denials:?}"
    );
}

#[tokio::test]
async fn a_flood_of_bad_tokens_cannot_grow_the_audit_log_without_bound() {
    let r = rig().await;
    create(&r, "u", "identity", "s", "v").await;
    for _ in 0..700 {
        call(
            &r.data,
            Method::GET,
            "/v2/facts/6f1c2a7e-0000-4000-8000-000000000000",
            Some("junk"),
            None,
        )
        .await;
    }
    let bad = audit_rows(&r)
        .await
        .into_iter()
        .filter(|(_, p, _)| p == "unauthenticated")
        .count();
    assert_eq!(bad, 600, "the cap is 600 an hour");
}

#[tokio::test]
async fn admin_actions_are_written_to_the_log_under_the_admins_name() {
    let r = rig().await;
    let id = create(&r, "user:1", "id_number", "s", "v").await;
    let approval = approval_flow(&r, id).await;
    call(
        &r.admin,
        Method::POST,
        "/v2/admin/issuers/1/disable",
        Some(BOB),
        None,
    )
    .await;
    call(
        &r.admin,
        Method::POST,
        "/v2/admin/issuers/1/enable",
        Some(BOB),
        None,
    )
    .await;
    call(
        &r.admin,
        Method::POST,
        "/v2/admin/legal-hold",
        Some(ALICE),
        Some(json!({"fact_id": id, "hold": true})),
    )
    .await;
    let _ = approval;
    let admin_actions: Vec<(String, String)> = audit_rows(&r)
        .await
        .into_iter()
        .filter(|(k, ..)| k == "admin")
        .map(|(_, p, b)| (p, b["action"].as_str().unwrap().to_owned()))
        .collect();
    for want in [
        ("alice", "policy.set"),
        ("alice", "issuer.create"),
        ("alice", "approval.request"),
        ("bob", "approval.approve"),
        ("bob", "issuer.disable"),
        ("bob", "issuer.enable"),
        ("alice", "legal_hold.set"),
    ] {
        assert!(
            admin_actions.contains(&(want.0.to_owned(), want.1.to_owned())),
            "missing {want:?} in {admin_actions:?}"
        );
    }
}

#[tokio::test]
async fn an_admin_can_query_the_log_by_subject_and_a_subjects_own_report_names_who_read_them() {
    let r = rig().await;
    let mine = create(&r, "user:1234", "identity", "kyc-doc:1", "a").await;
    let other = create(&r, "user:9999", "identity", "kyc-doc:2", "b").await;
    read(&r, mine, &verifier()).await;
    read(
        &r,
        mine,
        &Claims {
            caller: Some("user:88".into()),
            ..verifier()
        },
    )
    .await;
    read(&r, other, &verifier()).await;

    let (status, page, _) = call(
        &r.admin,
        Method::GET,
        "/v2/admin/audit?subject=user:1234&kind=read.grant",
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let who: Vec<&str> = page["entries"]
        .as_array()
        .unwrap()
        .iter()
        .map(|e| e["body"]["principal"].as_str().unwrap())
        .collect();
    assert_eq!(who, ["backend/user:77", "backend/user:88"]);
    // Nothing about the other person is in this report, and the plaintext subject is nowhere in the entries.
    assert!(!page.to_string().contains("user:9999") && !page.to_string().contains("user:1234"));

    let (_, by_principal, _) = call(
        &r.admin,
        Method::GET,
        "/v2/admin/audit?principal=backend/user:88",
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(by_principal["entries"].as_array().unwrap().len(), 1);
    // Paging.
    let (_, first, _) = call(
        &r.admin,
        Method::GET,
        "/v2/admin/audit?limit=2",
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(first["entries"].as_array().unwrap().len(), 2);
    let after = first["next_after_seq"].as_u64().unwrap();
    let (_, next, _) = call(
        &r.admin,
        Method::GET,
        &format!("/v2/admin/audit?limit=2&after_seq={after}"),
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(next["entries"][0]["seq"].as_u64().unwrap(), after + 1);
    // The query itself is in the log.
    assert!(
        audit_rows(&r)
            .await
            .iter()
            .any(|(k, p, b)| k == "admin" && p == "alice" && b["action"] == "audit.query")
    );
    // Auth, bad input.
    assert_eq!(
        call(&r.admin, Method::GET, "/v2/admin/audit", None, None)
            .await
            .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &r.admin,
            Method::GET,
            "/v2/admin/audit",
            Some(&token(&r, &verifier())),
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        call(
            &r.admin,
            Method::GET,
            "/v2/admin/audit?subject=",
            Some(ALICE),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        call(
            &r.admin,
            Method::GET,
            "/v2/admin/audit?fact_id=nope",
            Some(ALICE),
            None
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
}

#[tokio::test]
async fn a_truncated_audit_log_stops_reads_and_readiness_until_an_admin_acknowledges_it() {
    let r = rig().await;
    let id = create(&r, "user:1", "identity", "s", "v").await;
    for _ in 0..3 {
        assert_eq!(read(&r, id, &verifier()).await.0, StatusCode::OK);
    }
    let hash = r.app.access().policy_hash;
    r.app.engine.write_checkpoints(&hash).await.unwrap();
    let (status, v, _) = call(
        &r.admin,
        Method::GET,
        "/v2/admin/audit/verify",
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!((status, v["status"].clone()), (StatusCode::OK, json!("ok")));
    assert!(
        call(&r.data, Method::GET, "/readyz", None, None)
            .await
            .2
            .contains("\"audit_ok\":true")
    );

    // A restore from an older backup, as far as the log can tell.
    r.app.engine.store().truncate_audit(&[3; 16], 2);
    r.app.engine.check_audit().await.unwrap();
    let (status, v, _) = call(
        &r.admin,
        Method::GET,
        "/v2/admin/audit/verify",
        Some(ALICE),
        None,
    )
    .await;
    assert_eq!(
        (status, v["status"].clone(), v["reads_blocked"].clone()),
        (StatusCode::OK, json!("truncated"), json!(true))
    );
    let (status, body, _) = read(&r, id, &verifier()).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!("unavailable"))
    );
    let (status, ready, _) = call(&r.data, Method::GET, "/readyz", None, None).await;
    assert_eq!(
        (status, ready["audit_ok"].clone(), ready["ready"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!(false), json!(false))
    );

    // Only an admin can take responsibility.
    assert_eq!(
        call(
            &r.admin,
            Method::POST,
            "/v2/admin/audit/acknowledge-rollback",
            None,
            None
        )
        .await
        .0,
        StatusCode::UNAUTHORIZED
    );
    let (status, ..) = call(
        &r.admin,
        Method::POST,
        "/v2/admin/audit/acknowledge-rollback",
        Some(BOB),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(read(&r, id, &verifier()).await.0, StatusCode::OK);
    // The audit log no longer blocks readiness. (This rig's policy has no compat role, which has its own check.)
    let (_, ready, _) = call(&r.data, Method::GET, "/readyz", None, None).await;
    assert_eq!(ready["audit_ok"], json!(true));
    // And it is on the record, by name.
    assert!(audit_rows(&r).await.iter().any(|(k, p, b)| k == "admin"
        && p == "bob"
        && b["action"] == "audit.rollback_acknowledged"));
}

#[tokio::test]
async fn when_the_audit_log_is_down_a_v2_read_is_a_503_and_never_a_value() {
    let r = rig().await;
    let id = create(&r, "user:1", "identity", "s", SECRET).await;
    r.app.engine.store().set_audit_failure(true);
    let (status, body, text) = read(&r, id, &verifier()).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!("unavailable"))
    );
    assert!(!text.contains(SECRET));
    // The static compat token's reads fail the same way.
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/facts/{id}"))
        .header("X-OPV-GRANT-TOKEN", COMPAT)
        .body(Body::empty())
        .unwrap();
    let res = r.data.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::SERVICE_UNAVAILABLE);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    assert!(!String::from_utf8_lossy(&bytes).contains(SECRET));
    r.app.engine.store().set_audit_failure(false);
    assert_eq!(read(&r, id, &verifier()).await.0, StatusCode::OK);
}

// --- M5: blobs over HTTP --------------------------------------------------------------------------------------

use pvlt_format::blob::{BlobReader, BlobWriter};

async fn raw(
    r: &Router,
    method: Method,
    path: &str,
    bearer: Option<&str>,
    body: Vec<u8>,
) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
    let mut req = Request::builder().method(method).uri(path);
    if let Some(b) = bearer {
        req = req.header("Authorization", format!("Bearer {b}"));
    }
    let res = r
        .clone()
        .oneshot(req.body(Body::from(body)).unwrap())
        .await
        .unwrap();
    let (status, headers) = (res.status(), res.headers().clone());
    let bytes = res
        .into_body()
        .collect()
        .await
        .map(|c| c.to_bytes().to_vec())
        .unwrap_or_default();
    (status, headers, bytes)
}

fn b64(s: &str) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(s).unwrap()
}

/// The browser's part: encrypt with the ticket and return the object.
fn encrypt_ticket(t: &Value, data: &[u8]) -> Vec<u8> {
    let dek: [u8; 32] = b64(t["dek"].as_str().unwrap()).try_into().unwrap();
    let domain: [u8; 16] = hex::decode(t["domain_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let object: [u8; 16] = hex::decode(t["object_id"].as_str().unwrap())
        .unwrap()
        .try_into()
        .unwrap();
    let (mut w, header) = BlobWriter::new(
        &dek,
        pvlt_format::Suite::from_id(u16::try_from(t["suite"].as_u64().unwrap()).unwrap()).unwrap(),
        &domain,
        &object,
        u32::try_from(t["dek_generation"].as_u64().unwrap()).unwrap(),
        u32::try_from(t["chunk_size"].as_u64().unwrap()).unwrap(),
        &[0x42; 24],
        data.len() as u64,
    )
    .unwrap();
    let mut out = header;
    for p in data.chunks(777) {
        out.extend_from_slice(&w.write(p).unwrap());
    }
    out.extend_from_slice(&w.finish().unwrap());
    out
}

fn decrypt_with(dek_b64: &str, object: &[u8]) -> Vec<u8> {
    let dek: [u8; 32] = b64(dek_b64).try_into().unwrap();
    let mut r = BlobReader::new(&dek, object).unwrap();
    let mut out = r.push(&object[104..]).unwrap().to_vec();
    out.extend_from_slice(&r.finish().unwrap());
    out
}

fn service() -> Claims {
    claims(&["app-backend"])
}

async fn new_blob(r: &Rig, fact_type: &str, data: &[u8]) -> Value {
    let t = token(r, &service());
    let (status, ticket, text) = call(
        &r.data,
        Method::POST,
        "/v2/blobs",
        Some(&t),
        Some(json!({"type": fact_type, "scope": "kyc-doc:9", "subject": "user:1234", "size": data.len(), "chunk_size": 1024})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    ticket
}

async fn upload_and_complete(r: &Rig, ticket: &Value, data: &[u8]) {
    let t = token(r, &service());
    let id = ticket["id"].as_str().unwrap();
    let (status, ..) = raw(
        &r.data,
        Method::PUT,
        &format!("/v2/blobs/{id}/object"),
        Some(&t),
        encrypt_ticket(ticket, data),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, body, text) = call(
        &r.data,
        Method::POST,
        &format!("/v2/blobs/{id}/complete"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(
        (status, body["status"].clone()),
        (StatusCode::OK, json!("complete")),
        "{text}"
    );
}

#[tokio::test]
async fn a_document_goes_from_ticket_to_upload_to_completion_to_a_key_to_plaintext() {
    let r = rig().await;
    let data: Vec<u8> = (0..30_000u32).map(|i| (i % 253) as u8).collect();
    let ticket = new_blob(&r, "identity", &data).await;
    assert_eq!(
        ticket["upload"]["via"], "vault",
        "an in-memory bucket cannot presign, so the vault proxies"
    );
    assert_eq!(ticket["size"], 30_000);
    assert_eq!(ticket["suite"], 3);
    let id = ticket["id"].as_str().unwrap().to_owned();

    // Not readable until it is complete.
    let (status, ..) = read_blob(&r, &id, &verifier()).await;
    assert_eq!(status, StatusCode::CONFLICT);
    upload_and_complete(&r, &ticket, &data).await;

    // A verifier opens it: the key, and the address of the ciphertext.
    let (status, access, text) = read_blob(&r, &id, &verifier()).await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(
        access["dek"], ticket["dek"],
        "the key the client used is the key the vault gives back"
    );
    assert_eq!(access["download"]["via"], "vault");
    // The browser fetches the ciphertext and decrypts it itself.
    let vt = token(&r, &verifier());
    let (status, headers, ciphertext) = raw(
        &r.data,
        Method::GET,
        &format!("/v2/blobs/{id}/object"),
        Some(&vt),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        headers["content-length"].to_str().unwrap(),
        ticket["sealed_size"].to_string()
    );
    assert_eq!(
        decrypt_with(access["dek"].as_str().unwrap(), &ciphertext),
        data
    );
    // The ciphertext holds none of the plaintext.
    assert!(!ciphertext.windows(64).any(|w| w == &data[1000..1064]));
}

async fn read_blob(r: &Rig, id: &str, c: &Claims) -> (StatusCode, Value, String) {
    let t = token(r, c);
    call(
        &r.data,
        Method::GET,
        &format!("/v2/blobs/{id}/access"),
        Some(&t),
        None,
    )
    .await
}

#[tokio::test]
async fn the_server_can_decrypt_and_stream_a_blob_and_a_damaged_one_ends_in_a_broken_transfer() {
    let r = rig().await;
    let data: Vec<u8> = (0..50_000u32).map(|i| (i * 31 % 256) as u8).collect();
    let ticket = new_blob(&r, "identity", &data).await;
    upload_and_complete(&r, &ticket, &data).await;
    let id = ticket["id"].as_str().unwrap();
    let vt = token(&r, &verifier());
    let (status, headers, plain) = raw(
        &r.data,
        Method::GET,
        &format!("/v2/blobs/{id}/content"),
        Some(&vt),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(headers["content-length"], "50000");
    assert_eq!(plain, data);

    // Damage the stored object: the response still starts, but it cannot end normally.
    let key = pvlt_core::objects::ObjectKey {
        domain_id: [3; 16],
        object_id: hex::decode(ticket["object_id"].as_str().unwrap())
            .unwrap()
            .try_into()
            .unwrap(),
    };
    let mut bad = r.app.engine.objects().get(&key).await.unwrap().unwrap();
    let at = bad.len() - 900;
    bad[at] ^= 1;
    pvlt_core::objects::ObjectStore::put(r.app.engine.objects(), &key, bad)
        .await
        .unwrap();
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/v2/blobs/{id}/content"))
        .header("Authorization", format!("Bearer {vt}"))
        .body(Body::empty())
        .unwrap();
    let res = r.data.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    assert!(
        res.into_body().collect().await.is_err(),
        "a damaged blob must not look like a complete one"
    );
}

#[tokio::test]
async fn blob_routes_apply_the_same_policy_as_facts() {
    let r = rig().await;
    let ticket = new_blob(&r, "identity", b"scan").await;
    let id = ticket["id"].as_str().unwrap().to_owned();
    // A verifier cannot create blobs, and the service cannot open them.
    let vt = token(&r, &verifier());
    let (status, ..) = call(
        &r.data,
        Method::POST,
        "/v2/blobs",
        Some(&vt),
        Some(json!({"type":"identity","scope":"s","size":4})),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    upload_and_complete(&r, &ticket, b"scan").await;
    assert_eq!(
        read_blob(&r, &id, &service()).await.0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        read_blob(
            &r,
            &id,
            &Claims {
                purpose: None,
                ..verifier()
            }
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    assert_eq!(
        read_blob(&r, &id, &claims(&[])).await.0,
        StatusCode::FORBIDDEN
    );
    // No token at all, on every blob route.
    for (m, p) in [
        (Method::POST, "/v2/blobs".to_owned()),
        (Method::POST, format!("/v2/blobs/{id}/complete")),
        (Method::GET, format!("/v2/blobs/{id}/access")),
        (Method::GET, format!("/v2/blobs/{id}/content")),
        (Method::GET, format!("/v2/blobs/{id}/object")),
        (Method::PUT, format!("/v2/blobs/{id}/object")),
    ] {
        assert_eq!(
            raw(&r.data, m, &p, None, vec![]).await.0,
            StatusCode::UNAUTHORIZED,
            "{p}"
        );
    }
    // A token confined to another blob.
    let other = Claims {
        resource_fact: Some(Uuid::from_bytes([1; 16])),
        ..verifier()
    };
    assert_eq!(read_blob(&r, &id, &other).await.0, StatusCode::FORBIDDEN);
    let confined = Claims {
        resource_fact: Some(Uuid::parse_str(&id).unwrap()),
        ..verifier()
    };
    assert_eq!(read_blob(&r, &id, &confined).await.0, StatusCode::OK);
}

#[tokio::test]
async fn a_restricted_blob_needs_a_second_admins_approval_for_the_key_and_for_the_content() {
    let r = rig().await;
    let ticket = new_blob(&r, "id_number", b"X-123").await;
    upload_and_complete(&r, &ticket, b"X-123").await;
    let id = Uuid::parse_str(ticket["id"].as_str().unwrap()).unwrap();
    let (status, body, _) = read_blob(&r, &id.to_string(), &verifier()).await;
    assert_eq!(
        (status, body["message"].clone()),
        (StatusCode::FORBIDDEN, json!("approval_required"))
    );
    let approval = approval_flow(&r, id).await;
    let with = Claims {
        approval: Some(approval.to_string()),
        ..verifier()
    };
    assert_eq!(
        read_blob(&r, &id.to_string(), &with).await.0,
        StatusCode::OK
    );
    // Spent: the content route cannot reuse it.
    let (status, ..) = raw(
        &r.data,
        Method::GET,
        &format!("/v2/blobs/{id}/content"),
        Some(&token(&r, &with)),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let second = approval_flow(&r, id).await;
    let again = Claims {
        approval: Some(second.to_string()),
        ..verifier()
    };
    let (status, _, plain) = raw(
        &r.data,
        Method::GET,
        &format!("/v2/blobs/{id}/content"),
        Some(&token(&r, &again)),
        vec![],
    )
    .await;
    assert_eq!((status, plain.as_slice()), (StatusCode::OK, &b"X-123"[..]));
}

#[tokio::test]
async fn uploads_are_checked_and_cannot_overwrite_a_completed_blob() {
    let r = rig().await;
    let data = vec![5u8; 4000];
    let ticket = new_blob(&r, "identity", &data).await;
    let id = ticket["id"].as_str().unwrap();
    let t = token(&r, &service());
    let good = encrypt_ticket(&ticket, &data);
    // Wrong sizes are refused at upload, before anything is stored.
    for bad in [
        good[..good.len() - 1].to_vec(),
        [good.clone(), vec![0]].concat(),
        vec![],
    ] {
        let (status, ..) = raw(
            &r.data,
            Method::PUT,
            &format!("/v2/blobs/{id}/object"),
            Some(&t),
            bad,
        )
        .await;
        assert_eq!(status, StatusCode::CONFLICT);
    }
    assert_eq!(r.app.engine.objects().object_count(), 0);
    // Completing before an upload.
    let (status, ..) = call(
        &r.data,
        Method::POST,
        &format!("/v2/blobs/{id}/complete"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // A right-sized object encrypted under the wrong key is stored but refused at completion.
    let mut wrong = ticket.clone();
    wrong["dek"] = json!(base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        [9u8; 32]
    ));
    let (status, ..) = raw(
        &r.data,
        Method::PUT,
        &format!("/v2/blobs/{id}/object"),
        Some(&t),
        encrypt_ticket(&wrong, &data),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, ..) = call(
        &r.data,
        Method::POST,
        &format!("/v2/blobs/{id}/complete"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // The real one replaces it and completes. After that the object cannot be replaced.
    let (status, ..) = raw(
        &r.data,
        Method::PUT,
        &format!("/v2/blobs/{id}/object"),
        Some(&t),
        good.clone(),
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, ..) = call(
        &r.data,
        Method::POST,
        &format!("/v2/blobs/{id}/complete"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, ..) = raw(
        &r.data,
        Method::PUT,
        &format!("/v2/blobs/{id}/object"),
        Some(&t),
        good,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    let (status, ..) = call(
        &r.data,
        Method::POST,
        &format!("/v2/blobs/{id}/complete"),
        Some(&t),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
}

#[tokio::test]
async fn blob_requests_are_validated() {
    let r = rig().await;
    let t = token(&r, &service());
    for bad in [
        json!({"type":"identity","scope":"s"}),
        json!({"type":"identity","scope":"","size":1}),
        json!({"type":"identity","scope":"s","size":1,"chunk_size":1000}),
        json!({"type":"identity","scope":"s","size":99_999_999_999u64}),
        json!({"type":"identity","scope":"s","size":1,"retain_days":0}),
        json!({"type":"identity","scope":"s","size":1,"extra":true}),
    ] {
        let (status, _, text) = call(&r.data, Method::POST, "/v2/blobs", Some(&t), Some(bad)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    }
    assert_eq!(
        raw(
            &r.data,
            Method::GET,
            "/v2/blobs/not-a-uuid/access",
            Some(&t),
            vec![]
        )
        .await
        .0,
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        read_blob(&r, "6f1c2a7e-0000-4000-8000-000000000000", &verifier())
            .await
            .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn the_key_is_not_released_when_the_audit_log_is_down_and_shredding_a_blob_ends_it() {
    let r = rig().await;
    let data = b"passport".to_vec();
    let ticket = new_blob(&r, "identity", &data).await;
    upload_and_complete(&r, &ticket, &data).await;
    let id = ticket["id"].as_str().unwrap().to_owned();

    r.app.engine.store().set_audit_failure(true);
    let (status, body, text) = read_blob(&r, &id, &verifier()).await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!("unavailable"))
    );
    assert!(
        !text.contains(ticket["dek"].as_str().unwrap()),
        "the key was in an error response"
    );
    let (status, ..) = raw(
        &r.data,
        Method::GET,
        &format!("/v2/blobs/{id}/content"),
        Some(&token(&r, &verifier())),
        vec![],
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    r.app.engine.store().set_audit_failure(false);

    assert_eq!(read_blob(&r, &id, &verifier()).await.0, StatusCode::OK);
    let rows = audit_rows(&r).await;
    assert!(rows.iter().any(|(k, p, b)| k == "read.grant"
        && p == "backend/user:77"
        && b["action"] == "blob.access"));
    // Shredding it through the facts route ends it, and the object goes.
    let (status, body, _) = call(
        &r.data,
        Method::DELETE,
        &format!("/v2/facts/{id}"),
        Some(&token(&r, &service())),
        None,
    )
    .await;
    assert_eq!(
        (status, body["outcome"].clone()),
        (StatusCode::OK, json!("shredded"))
    );
    assert_eq!(read_blob(&r, &id, &verifier()).await.0, StatusCode::GONE);
    assert_eq!(r.app.engine.objects().object_count(), 0);
}

#[tokio::test]
async fn a_blob_is_not_a_fact_over_http_either() {
    let r = rig().await;
    let ticket = new_blob(&r, "identity", b"x").await;
    let id = Uuid::parse_str(ticket["id"].as_str().unwrap()).unwrap();
    upload_and_complete(&r, &ticket, b"x").await;
    let (status, ..) = read(&r, id, &verifier()).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "the facts route does not return a blob's ciphertext as a value"
    );
    let fact = create(&r, "u", "identity", "s", "v").await;
    assert_eq!(
        read_blob(&r, &fact.to_string(), &verifier()).await.0,
        StatusCode::CONFLICT
    );
}

async fn admin_post(r: &Rig, path: &str, body: Value) -> (StatusCode, Value, String) {
    call(&r.admin, Method::POST, path, Some(ALICE), Some(body)).await
}

// --- M6: importing under a kept id ---------------------------------------------------------------------------------

#[tokio::test]
async fn an_admin_import_keeps_the_id_and_the_compat_route_reads_it_back() {
    let r = rig().await;
    let id = "6f1c2a7e-1111-4222-8333-444455556666";
    let body = json!({"id": id, "subject": "user:7", "scope": "kyc-doc:7", "type": "ascii", "value": SECRET});
    let (status, got, text) = admin_post(&r, "/v2/admin/import/fact", body.clone()).await;
    assert_eq!(
        (status, got["id"].clone()),
        (StatusCode::CREATED, json!(id)),
        "{text}"
    );

    // The application's stored id works unchanged through the OPV-compatible route.
    let req = Request::builder()
        .method(Method::GET)
        .uri(format!("/api/v1/facts/{id}"))
        .header("X-OPV-GRANT-TOKEN", COMPAT)
        .body(Body::empty())
        .unwrap();
    let res = r.data.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let v: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(
        (v["id"].clone(), v["value"].clone()),
        (json!(id), json!(SECRET))
    );

    // A second import of the same id is a 409, and nothing changed.
    let (status, ..) = admin_post(
        &r,
        "/v2/admin/import/fact",
        json!({"id": id, "scope": "other", "type": "ascii", "value": "different"}),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    // It is filed under its subject, so a subject shred reaches it, and the import is in the audit log by name.
    let (_, shred, _) = admin_post(
        &r,
        "/v2/admin/shred/subject",
        json!({"subject": "user:7", "reason": "migration"}),
    )
    .await;
    assert_eq!(shred["outcome"], "shredded");
    assert!(
        audit_rows(&r)
            .await
            .iter()
            .any(|(k, p, b)| k == "create" && p == "alice" && b["fact_id"] == json!(id))
    );
}

#[tokio::test]
async fn an_admin_import_is_validated_and_needs_the_admin_credential() {
    let r = rig().await;
    let ok = json!({"id": "6f1c2a7e-1111-4222-8333-444455556667", "scope": "s", "type": "ascii", "value": "v"});
    for bearer in [None, Some("nope"), Some(COMPAT)] {
        let (status, ..) = call(
            &r.admin,
            Method::POST,
            "/v2/admin/import/fact",
            bearer,
            Some(ok.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    for bad in [
        json!({"id": "not-a-uuid", "scope": "s", "type": "ascii", "value": "v"}),
        json!({"id": "6f1c2a7e-1111-4222-8333-444455556667", "scope": "s", "type": "ssn", "value": "v"}),
        json!({"id": "6f1c2a7e-1111-4222-8333-444455556667", "scope": "s", "type": "ascii", "value": "caf\u{e9}"}),
        json!({"id": "6f1c2a7e-1111-4222-8333-444455556667", "scope": "", "type": "ascii", "value": "v"}),
        json!({"id": "6f1c2a7e-1111-4222-8333-444455556667", "scope": "s", "type": "ascii"}),
    ] {
        let (status, _, text) = admin_post(&r, "/v2/admin/import/fact", bad).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
        assert!(!text.contains("caf"), "{text}");
    }
    assert_eq!(
        admin_post(&r, "/v2/admin/import/fact", ok).await.0,
        StatusCode::CREATED
    );
}
