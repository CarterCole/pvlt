//! GDPR mode: the data subject's access and export routes, the admin inventory, and the switches that turn the
//! intrusive parts off.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use http_body_util::BodyExt;
use pvlt_core::audit::Auditor;
use pvlt_core::engine::{Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::memory::{MemKeyStore, MemObjectStore};
use pvlt_core::seal::init_shamir;
use pvlt_core::store::KeyStore;
use pvlt_mem::{Arena, LockPolicy};
use pvlt_server::app::{Admin, App, GdprMode, Token};
use pvlt_server::tokens::{Claims, generate_issuer_key, mint};
use pvlt_server::{admin, routes};
use serde_json::{Value, json};
use time::OffsetDateTime;
use tower::ServiceExt;
use uuid::Uuid;

const ALICE: &str = "alice-admin-token-0123456789";
const DOMAIN: [u8; 16] = [3; 16];

const POLICY: &str = r#"{
  "version": 1,
  "restricted_types": ["id_number"],
  "roles": {
    "verifier": {
      "allow": [{ "types": ["identity"], "actions": ["read"] }],
      "require": { "purposes": ["kyc-review"], "reason": true }
    },
    "data-subject": { "allow": [{ "types": ["*"], "actions": ["read", "shred"], "when": ["self"] }] },
    "app-backend": { "allow": [{ "types": ["*"], "actions": ["create", "shred"] }] }
  }
}"#;

#[derive(Default, Clone)]
struct Quiet;

impl Auditor for Quiet {
    fn record(&self, _: &pvlt_core::audit::AuditEvent<'_>) {}
}

type TestApp = App<MemKeyStore, MemObjectStore, Quiet>;

struct Rig {
    app: Arc<TestApp>,
    data: Router,
    admin: Router,
    seed: [u8; 32],
}

async fn call(
    router: &Router,
    path: &str,
    bearer: Option<&str>,
    body: Value,
) -> (StatusCode, Value, String) {
    let mut req = Request::builder().method(Method::POST).uri(path);
    if let Some(b) = bearer {
        req = req.header("Authorization", format!("Bearer {b}"));
    }
    let res = router
        .clone()
        .oneshot(req.body(Body::from(body.to_string())).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let text = String::from_utf8_lossy(&bytes).into_owned();
    (
        status,
        serde_json::from_str(&text).unwrap_or(Value::Null),
        text,
    )
}

async fn rig(gdpr: GdprMode) -> Rig {
    let a = Arena::new(256, LockPolicy::BestEffort).unwrap();
    let init = init_shamir(&a, 2, 3).unwrap();
    let ring = Keyring::new(a);
    ring.unseal(init.root);
    let engine = Engine::new(
        ring,
        MemKeyStore::new(),
        MemObjectStore::new(),
        Quiet,
        Limits::default(),
    );
    let app = Arc::new(
        App::new(engine, DOMAIN, None, None, init.config)
            .with_admins(vec![Admin {
                name: "alice".into(),
                token: Token::new(ALICE),
            }])
            .with_gdpr(gdpr),
    );
    app.reload_access().await.unwrap();
    let (seed, public) = generate_issuer_key();
    let r = Rig {
        data: routes::data_router(Arc::clone(&app)),
        admin: admin::router(Arc::clone(&app)),
        app,
        seed,
    };
    let (status, ..) = call(
        &r.admin,
        "/v2/admin/issuers",
        Some(ALICE),
        json!({"name":"backend","public_key":hex::encode(public),"roles":["verifier","data-subject","app-backend"]}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/v2/admin/policy")
        .header("Authorization", format!("Bearer {ALICE}"))
        .body(Body::from(POLICY))
        .unwrap();
    assert_eq!(
        r.admin.clone().oneshot(req).await.unwrap().status(),
        StatusCode::OK
    );
    r
}

fn claims(roles: &[&str]) -> Claims {
    Claims {
        issuer_key_id: 1,
        roles: roles.iter().map(|r| (*r).to_owned()).collect(),
        request_id: "req-1".into(),
        expires: OffsetDateTime::now_utc().unix_timestamp() + 60,
        ..Claims::default()
    }
}

/// The data subject's own token.
fn me(r: &Rig, subject: &str) -> String {
    mint(
        &r.seed,
        &Claims {
            caller: Some(subject.into()),
            subject: Some(subject.into()),
            ..claims(&["data-subject"])
        },
    )
    .unwrap()
}

async fn create(r: &Rig, subject: &str, fact_type: &str, value: &str) -> Uuid {
    let t = mint(&r.seed, &claims(&["app-backend"])).unwrap();
    let (status, body, text) = call(
        &r.data,
        "/v2/facts",
        Some(&t),
        json!({"type":fact_type,"scope":"kyc","subject":subject,"value":value}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    Uuid::parse_str(body["id"].as_str().unwrap()).unwrap()
}

/// Three facts for `user:1`, one of them a restricted type, and one for `user:2`.
async fn seed(r: &Rig) -> (Uuid, Uuid, Uuid, Uuid) {
    (
        create(r, "user:1", "identity", "Ada Lovelace").await,
        create(r, "user:1", "address", "12 St James's Sq").await,
        create(r, "user:1", "id_number", "AB123456C").await,
        create(r, "user:2", "identity", "Charles Babbage").await,
    )
}

fn by_id(report: &Value, id: Uuid) -> Value {
    report["facts"]
        .as_array()
        .unwrap()
        .iter()
        .find(|f| f["id"] == json!(id))
        .cloned()
        .unwrap_or(Value::Null)
}

async fn audit_kinds(r: &Rig) -> Vec<(String, String, Value)> {
    r.app
        .engine
        .store()
        .audit_records(&DOMAIN, 0, 10_000)
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
async fn with_the_mode_off_none_of_the_routes_exist() {
    let r = rig(GdprMode::default()).await;
    seed(&r).await;
    let t = me(&r, "user:1");
    for path in ["/v2/subject/facts", "/v2/subject/export"] {
        let (status, ..) = call(&r.data, path, Some(&t), json!({"subject":"user:1"})).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{path}");
    }
    let (status, ..) = call(
        &r.admin,
        "/v2/admin/subject/facts",
        Some(ALICE),
        json!({"subject":"user:1"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn a_subject_lists_their_own_facts_without_values_and_the_list_is_audited() {
    let r = rig(GdprMode::on()).await;
    let (identity, address, id_number, other) = seed(&r).await;
    let (status, body, text) = call(
        &r.data,
        "/v2/subject/facts",
        Some(&me(&r, "user:1")),
        json!({"subject":"user:1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(body["complete"], json!(true));
    assert_eq!(body["facts"].as_array().unwrap().len(), 3);
    for (id, ty) in [
        (identity, "identity"),
        (address, "address"),
        (id_number, "id_number"),
    ] {
        let f = by_id(&body, id);
        assert_eq!(
            (f["type"].as_str(), f["status"].as_str(), f["kind"].as_str()),
            (Some(ty), Some("active"), Some("fact"))
        );
    }
    assert_eq!(by_id(&body, other), Value::Null);
    for secret in ["Ada Lovelace", "St James", "AB123456C", "Babbage", "user:1"] {
        assert!(!text.contains(secret), "{secret} leaked into {text}");
    }
    let rows = audit_kinds(&r).await;
    let (_, principal, entry) = rows.iter().find(|(k, ..)| k == "inventory").unwrap();
    assert_eq!(principal, "backend/user:1");
    assert_eq!(entry["action"], json!("subject.facts"));
    assert!(entry["subject_hmac"].is_string());
    // No value was opened to make the list.
    assert!(!rows.iter().any(|(k, ..)| k == "read.grant"));
}

#[tokio::test]
async fn an_export_has_every_readable_value_withholds_restricted_types_and_audits_each_read() {
    let r = rig(GdprMode::on()).await;
    let (identity, address, id_number, other) = seed(&r).await;
    let (status, body, text) = call(
        &r.data,
        "/v2/subject/export",
        Some(&me(&r, "user:1")),
        json!({"subject":"user:1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    let f = by_id(&body, identity);
    assert_eq!(
        (f["status"].as_str(), f["value"].as_str()),
        (Some("exported"), Some("Ada Lovelace"))
    );
    assert_eq!(by_id(&body, address)["value"], json!("12 St James's Sq"));
    let f = by_id(&body, id_number);
    assert_eq!(
        (f["status"].as_str(), f["withheld"].as_str(), f.get("value")),
        (Some("withheld"), Some("approval_required"), None)
    );
    assert_eq!(by_id(&body, other), Value::Null);
    assert!(!text.contains("Babbage") && !text.contains("AB123456C"));

    let rows = audit_kinds(&r).await;
    let grants: Vec<_> = rows
        .iter()
        .filter(|(k, ..)| k == "read.grant")
        .map(|(_, _, b)| b["fact_id"].clone())
        .collect();
    assert_eq!(grants.len(), 2);
    assert!(grants.contains(&json!(identity)) && grants.contains(&json!(address)));
    assert!(
        rows.iter()
            .any(|(k, _, b)| k == "inventory" && b["action"] == json!("subject.export"))
    );
}

#[tokio::test]
async fn nobody_else_can_list_or_export_a_subject() {
    let r = rig(GdprMode::on()).await;
    seed(&r).await;
    let someone_else = me(&r, "user:2");
    let verifier = mint(
        &r.seed,
        &Claims {
            caller: Some("staff:9".into()),
            purpose: Some("kyc-review".into()),
            reason: Some("ticket 1".into()),
            ..claims(&["verifier"])
        },
    )
    .unwrap();
    for path in ["/v2/subject/facts", "/v2/subject/export"] {
        for t in [&someone_else, &verifier] {
            let (status, _, text) = call(&r.data, path, Some(t), json!({"subject":"user:1"})).await;
            assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
            assert!(!text.contains("Ada"));
        }
        let (status, ..) = call(&r.data, path, None, json!({"subject":"user:1"})).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert!(audit_kinds(&r).await.iter().all(|(k, ..)| k != "inventory"));
}

#[tokio::test]
async fn after_the_subject_erases_themselves_the_list_shows_everything_shredded_and_exports_nothing()
 {
    let r = rig(GdprMode::on()).await;
    let (identity, ..) = seed(&r).await;
    let t = me(&r, "user:1");
    let (status, body, _) = call(
        &r.data,
        "/v2/shred/subject",
        Some(&t),
        json!({"subject":"user:1"}),
    )
    .await;
    assert_eq!(
        (status, body["outcome"].as_str()),
        (StatusCode::OK, Some("shredded"))
    );

    let (_, list, _) = call(
        &r.data,
        "/v2/subject/facts",
        Some(&t),
        json!({"subject":"user:1"}),
    )
    .await;
    let facts = list["facts"].as_array().unwrap();
    assert_eq!(facts.len(), 3);
    assert!(facts.iter().all(|f| f["status"] == json!("shredded")));

    let (status, export, text) = call(
        &r.data,
        "/v2/subject/export",
        Some(&t),
        json!({"subject":"user:1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(by_id(&export, identity)["status"], json!("shredded"));
    assert!(!text.contains("Ada") && !text.contains("value"));
}

#[tokio::test]
async fn the_admin_inventory_needs_the_admin_token_lists_no_values_and_is_audited() {
    let r = rig(GdprMode::on()).await;
    let (identity, ..) = seed(&r).await;
    let (status, ..) = call(
        &r.admin,
        "/v2/admin/subject/facts",
        Some("wrong-token-0123456789"),
        json!({"subject":"user:1"}),
    )
    .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    // A data token is not an admin token, and the route is not on the data listener.
    let (status, ..) = call(
        &r.data,
        "/v2/admin/subject/facts",
        Some(&me(&r, "user:1")),
        json!({"subject":"user:1"}),
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, body, text) = call(
        &r.admin,
        "/v2/admin/subject/facts",
        Some(ALICE),
        json!({"subject":"user:1"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{text}");
    assert_eq!(body["facts"].as_array().unwrap().len(), 3);
    assert_eq!(by_id(&body, identity)["status"], json!("active"));
    assert!(!text.contains("Ada") && !text.contains("\"value"));
    let rows = audit_kinds(&r).await;
    assert!(rows.iter().any(|(k, p, b)| k == "inventory"
        && p == "alice"
        && b["action"] == json!("admin.subject.facts")));
    assert!(!rows.iter().any(|(k, ..)| k == "read.grant"));
}

#[tokio::test]
async fn export_and_the_admin_inventory_can_each_be_turned_off() {
    let r = rig(GdprMode {
        enabled: true,
        export: false,
        admin_inventory: false,
    })
    .await;
    seed(&r).await;
    let t = me(&r, "user:1");
    assert_eq!(
        call(
            &r.data,
            "/v2/subject/facts",
            Some(&t),
            json!({"subject":"user:1"})
        )
        .await
        .0,
        StatusCode::OK
    );
    assert_eq!(
        call(
            &r.data,
            "/v2/subject/export",
            Some(&t),
            json!({"subject":"user:1"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &r.admin,
            "/v2/admin/subject/facts",
            Some(ALICE),
            json!({"subject":"user:1"})
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn a_bad_body_or_subject_is_refused_without_echoing_it() {
    let r = rig(GdprMode::on()).await;
    let long = "u".repeat(257);
    let (status, _, text) = call(
        &r.admin,
        "/v2/admin/subject/facts",
        Some(ALICE),
        json!({"subject": long}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!text.contains(&long));
    let (status, _, text) = call(
        &r.admin,
        "/v2/admin/subject/facts",
        Some(ALICE),
        json!({"subject":"user:1","extra":"hunter2"}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!text.contains("hunter2"));
    // A subject the vault has never seen is an empty list, not an error.
    let (status, body, _) = call(
        &r.admin,
        "/v2/admin/subject/facts",
        Some(ALICE),
        json!({"subject":"user:404"}),
    )
    .await;
    assert_eq!((status, body["facts"].clone()), (StatusCode::OK, json!([])));
}
