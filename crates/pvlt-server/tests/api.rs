//! The HTTP surface, driven in-process with the same requests an OPV client sends, over in-memory stores.

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
use pvlt_core::audit::NullAuditor;
use pvlt_core::engine::{Engine, Limits};
use pvlt_core::keyring::Keyring;
use pvlt_core::memory::{MemKeyStore, MemObjectStore};
use pvlt_core::seal::init_shamir;
use pvlt_mem::{Arena, LockPolicy};
use pvlt_server::app::{App, Token};
use pvlt_server::{admin, routes};
use serde_json::{Value, json};
use tower::ServiceExt;

const TOKEN: &str = "compat-token-for-tests";
const ADMIN: &str = "admin-token-for-tests";
const SECRET: &str = "Quentin-Nightingale-1987-03-09";

type TestApp = App<MemKeyStore, MemObjectStore, NullAuditor>;

struct Rig {
    app: Arc<TestApp>,
    data: Router,
    admin: Router,
    shares: Vec<String>,
}

fn arena() -> Arena {
    Arena::new(256, LockPolicy::BestEffort).unwrap()
}

/// A rig with no policy at all, so the compat token, if set, is refused everything.
fn bare_rig(unsealed: bool, compat: bool, max_value_len: usize) -> Rig {
    let a = arena();
    let init = init_shamir(&a, 2, 3).unwrap();
    let shares: Vec<String> = init
        .shares
        .iter()
        .map(|s| s.to_text().as_str().to_owned())
        .collect();
    let ring = Keyring::new(a);
    if unsealed {
        ring.unseal(init.root);
    }
    let engine = Engine::new(
        ring,
        MemKeyStore::new(),
        MemObjectStore::new(),
        NullAuditor,
        Limits { max_value_len },
    );
    let app = Arc::new(App::new(
        engine,
        [3; 16],
        compat.then(|| Token::new(TOKEN)),
        Some(Token::new(ADMIN)),
        init.config,
    ));
    Rig {
        data: routes::data_router(Arc::clone(&app)),
        admin: admin::router(Arc::clone(&app)),
        app,
        shares,
    }
}

/// A rig whose policy lets the compat token do everything to the types OPV clients use, as a deployment that
/// serves `/api/v1` sets it up. Installed straight into the key store, so it works on a sealed vault too.
async fn rig(unsealed: bool, compat: bool, max_value_len: usize) -> Rig {
    let r = bare_rig(unsealed, compat, max_value_len);
    if compat {
        install_policy(&r, COMPAT_ALL).await;
    }
    r
}

async fn default_rig() -> Rig {
    rig(true, true, 1_048_576).await
}

const COMPAT_ALL: &str = r#"{"version":1,"roles":{"compat":{"allow":[{"types":["*"],"actions":["create","read","shred"]}]}}}"#;

async fn install_policy(r: &Rig, json: &str) {
    use pvlt_core::store::KeyStore;
    let p = pvlt_policy::policy::Policy::from_json(json.as_bytes()).unwrap();
    r.app
        .engine
        .store()
        .put_policy(&p.canonical_json().unwrap(), &p.hash().unwrap(), "admin")
        .await
        .unwrap();
    r.app.reload_access().await.unwrap();
}

async fn call(
    router: &Router,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<Value>,
) -> (StatusCode, Value, String) {
    call_raw(
        router,
        method,
        path,
        headers,
        body.map(|b| b.to_string()).unwrap_or_default(),
    )
    .await
}

async fn call_raw(
    router: &Router,
    method: Method,
    path: &str,
    headers: &[(&str, &str)],
    body: String,
) -> (StatusCode, Value, String) {
    let mut req = Request::builder().method(method).uri(path);
    for (k, v) in headers {
        req = req.header(*k, *v);
    }
    let req = req.body(Body::from(body)).unwrap();
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

fn auth() -> [(&'static str, &'static str); 1] {
    [("X-OPV-GRANT-TOKEN", TOKEN)]
}

/// The request shape an OPV client sends.
async fn store(r: &Rig, fact_type: &str, scope: &str, value: &str) -> (StatusCode, Value, String) {
    call(
        &r.data,
        Method::POST,
        "/api/v1/facts",
        &[
            ("X-OPV-GRANT-TOKEN", TOKEN),
            ("Content-Type", "application/json"),
        ],
        Some(json!({"fact_type_slug": fact_type, "scope_custom_id": scope, "value": value})),
    )
    .await
}

#[tokio::test]
async fn the_three_calls_an_opv_client_makes_work_end_to_end() {
    let r = default_rig().await;
    let (status, body, _) = store(&r, "ascii", "kyc-doc:42", SECRET).await;
    assert_eq!(status, StatusCode::OK);
    let id = body["id"].as_str().unwrap().to_owned();
    uuid::Uuid::parse_str(&id).unwrap();

    let (status, body, _) = call(
        &r.data,
        Method::GET,
        &format!("/api/v1/facts/{id}"),
        &auth(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["value"], SECRET);
    assert_eq!(body["id"], id);
    assert_eq!(body["fact_type_slug"], "ascii");

    let (status, ..) = call(
        &r.data,
        Method::DELETE,
        &format!("/api/v1/facts/{id}"),
        &auth(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    // Gone for good, and distinguishable from "never existed".
    let (status, body, _) = call(
        &r.data,
        Method::GET,
        &format!("/api/v1/facts/{id}"),
        &auth(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::GONE);
    assert_eq!(body["error"], "shredded");
    // Deleting again is a success, which an OPV client counts as one.
    let (status, ..) = call(
        &r.data,
        Method::DELETE,
        &format!("/api/v1/facts/{id}"),
        &auth(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn deleting_a_fact_that_never_existed_is_a_404_which_clients_also_count_as_success() {
    let r = default_rig().await;
    let (status, ..) = call(
        &r.data,
        Method::DELETE,
        "/api/v1/facts/6f1c2a7e-0000-4000-8000-000000000000",
        &auth(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, ..) = call(
        &r.data,
        Method::GET,
        "/api/v1/facts/6f1c2a7e-0000-4000-8000-000000000000",
        &auth(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn every_fact_type_clients_use_round_trips() {
    let r = default_rig().await;
    for (kind, value) in [
        ("ascii", "plain ascii"),
        ("printableascii", "Printable-ASCII 123"),
        ("base64", "aGVsbG8gd29ybGQ="),
        (
            "json",
            r#"{"address":{"line1":"1 Main St","zip":"02134"},"n":[1,2,3]}"#,
        ),
    ] {
        let (status, body, _) = store(&r, kind, "scope", value).await;
        assert_eq!(status, StatusCode::OK, "{kind}");
        let id = body["id"].as_str().unwrap();
        let (_, got, _) = call(
            &r.data,
            Method::GET,
            &format!("/api/v1/facts/{id}"),
            &auth(),
            None,
        )
        .await;
        assert_eq!(got["value"], value, "{kind}");
        assert_eq!(got["fact_type_slug"], kind);
    }
}

#[tokio::test]
async fn a_random_uuid_scope_and_a_meaningful_scope_both_work() {
    let r = default_rig().await;
    for scope in [
        "8d3e1c58-6b8f-4d0a-9b53-5a8a1d0f6a11",
        "model-release:77",
        "physical-order:9",
    ] {
        assert_eq!(
            store(&r, "ascii", scope, "v").await.0,
            StatusCode::OK,
            "{scope}"
        );
    }
}

#[tokio::test]
async fn requests_without_the_right_token_are_refused() {
    let r = default_rig().await;
    let body = json!({"fact_type_slug":"ascii","scope_custom_id":"s","value":"v"});
    for headers in [
        vec![],
        vec![("X-OPV-GRANT-TOKEN", "wrong")],
        vec![("X-OPV-GRANT-TOKEN", "")],
        // The admin token is not the compat token.
        vec![("X-OPV-GRANT-TOKEN", ADMIN)],
        vec![("Authorization", "Bearer compat-token-for-tests")],
    ] {
        let (status, ..) = call(
            &r.data,
            Method::POST,
            "/api/v1/facts",
            &headers,
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{headers:?}");
        let (status, ..) = call(
            &r.data,
            Method::GET,
            "/api/v1/facts/6f1c2a7e-0000-4000-8000-000000000000",
            &headers,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let (status, ..) = call(
            &r.data,
            Method::DELETE,
            "/api/v1/facts/6f1c2a7e-0000-4000-8000-000000000000",
            &headers,
            None,
        )
        .await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    assert!(r.app.engine.objects().is_empty());
}

#[tokio::test]
async fn with_no_compat_token_configured_every_request_is_refused() {
    let r = rig(true, false, 1_048_576).await;
    let (status, ..) = store(&r, "ascii", "s", "v").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn bad_values_and_types_are_400_and_never_echoed() {
    let r = default_rig().await;
    let cases = [
        ("unknown type", "ssn", "ok-value"),
        ("non-ascii in ascii", "ascii", "caf\u{e9}-SECRETVALUE"),
        (
            "control in printable",
            "printableascii",
            "tab\there-SECRETVALUE",
        ),
        ("bad base64", "base64", "not base64!!-SECRETVALUE"),
        ("bad json", "json", "{SECRETVALUE"),
    ];
    for (name, kind, value) in cases {
        let (status, body, text) = store(&r, kind, "s", value).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{name}");
        assert_eq!(body["error"], "invalid", "{name}");
        assert!(
            !text.contains("SECRETVALUE"),
            "{name} echoed the value: {text}"
        );
    }
    assert!(r.app.engine.objects().is_empty());
}

#[tokio::test]
async fn malformed_requests_are_400_without_an_echo() {
    let r = default_rig().await;
    let headers = [("X-OPV-GRANT-TOKEN", TOKEN)];
    for body in [
        String::new(),
        "not json SECRETVALUE".to_owned(),
        r#"{"fact_type_slug":"ascii","scope_custom_id":"s","value":12345}"#.to_owned(),
        r#"{"fact_type_slug":"ascii","value":"SECRETVALUE"}"#.to_owned(),
    ] {
        let (status, _, text) =
            call_raw(&r.data, Method::POST, "/api/v1/facts", &headers, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(
            !text.contains("SECRETVALUE") && !text.contains("12345"),
            "{text}"
        );
    }
    let (status, ..) = call(
        &r.data,
        Method::GET,
        "/api/v1/facts/not-a-uuid",
        &auth(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    // An empty scope is refused by the engine.
    let (status, ..) = store(&r, "ascii", "", "v").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn an_oversized_request_is_refused() {
    let r = rig(true, true, 100).await;
    let (status, ..) = store(&r, "ascii", "s", &"x".repeat(101)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(
        store(&r, "ascii", "s", &"x".repeat(100)).await.0,
        StatusCode::OK
    );

    let huge = "x".repeat(9 * 1024 * 1024);
    let (status, ..) = store(&r, "ascii", "s", &huge).await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn neither_store_holds_the_value_or_scope_after_http_calls() {
    let r = default_rig().await;
    let (_, body, _) = store(&r, "ascii", "scope-of-quentin", SECRET).await;
    let id = body["id"].as_str().unwrap();
    let (_, got, _) = call(
        &r.data,
        Method::GET,
        &format!("/api/v1/facts/{id}"),
        &auth(),
        None,
    )
    .await;
    assert_eq!(got["value"], SECRET);
    for bytes in [r.app.engine.store().dump(), r.app.engine.objects().dump()] {
        assert!(!bytes.is_empty());
        for needle in [SECRET, "Nightingale", "scope-of-quentin"] {
            assert!(
                !bytes.windows(needle.len()).any(|w| w == needle.as_bytes()),
                "{needle}"
            );
        }
    }
}

#[tokio::test]
async fn a_sealed_vault_says_so_and_unsealing_needs_enough_distinct_good_shares() {
    // The rig installs the compat policy straight into the key store: over the admin route it would be refused
    // while sealed, because the change's audit entry cannot be written before the domain exists.
    let r = rig(false, true, 1_048_576).await;

    let (status, body, _) = store(&r, "ascii", "s", "v").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["error"], "sealed");
    let (status, body, _) = call(&r.data, Method::GET, "/readyz", &[], None).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        (body["sealed"].clone(), body["ready"].clone()),
        (json!(true), json!(false))
    );
    // Liveness does not depend on being unsealed.
    assert_eq!(
        call(&r.data, Method::GET, "/healthz", &[], None).await.0,
        StatusCode::OK
    );

    let submit = |share: String| {
        let admin = r.admin.clone();
        async move {
            call(
                &admin,
                Method::POST,
                "/v2/sys/unseal",
                &[],
                Some(json!({"share": share})),
            )
            .await
        }
    };
    let (status, body, _) = submit(r.shares[0].clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (
            body["sealed"].clone(),
            body["submitted"].clone(),
            body["threshold"].clone()
        ),
        (json!(true), json!(1), json!(2))
    );
    // The same share again does not count twice.
    let (_, body, _) = submit(r.shares[0].clone()).await;
    assert_eq!(
        (body["sealed"].clone(), body["submitted"].clone()),
        (json!(true), json!(1))
    );
    // Garbage and a share from another vault are refused and not held.
    for bad in ["nonsense".to_owned(), "pvlt-share-v1:00".to_owned()] {
        assert_eq!(submit(bad).await.0, StatusCode::BAD_REQUEST);
    }
    let other = bare_rig(false, true, 1_048_576).shares[0].clone();
    let (status, _, text) = submit(other).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(!text.contains("pvlt-share"));
    assert_eq!(r.app.unseal_status().submitted, 1);

    let (status, body, _) = submit(r.shares[2].clone()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        (body["sealed"].clone(), body["submitted"].clone()),
        (json!(false), json!(0))
    );

    assert_eq!(store(&r, "ascii", "s", "v").await.0, StatusCode::OK);
    assert_eq!(
        call(&r.data, Method::GET, "/readyz", &[], None).await.0,
        StatusCode::OK
    );
}

/// A share with one secret byte changed and its checksum made good again: it looks valid in every way a holder
/// could check, which is what someone who wants to spoil an unseal would send.
fn forged(share: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut bytes = hex::decode(share.strip_prefix("pvlt-share-v1:").unwrap()).unwrap();
    bytes.truncate(bytes.len() - 4);
    bytes[1 + 1 + 16 + 1] ^= 0x01;
    let check: [u8; 32] = Sha256::new()
        .chain_update(pvlt_format::PREFIX)
        .chain_update(b"share-check\0")
        .chain_update(&bytes)
        .finalize()
        .into();
    bytes.extend_from_slice(&check[..4]);
    format!("pvlt-share-v1:{}", hex::encode(bytes))
}

#[tokio::test]
async fn a_forged_share_sent_first_is_refused_and_cannot_spoil_the_unseal() {
    let r = rig(false, true, 1_048_576).await;
    let submit = |share: String| {
        let admin = r.admin.clone();
        async move {
            call(
                &admin,
                Method::POST,
                "/v2/sys/unseal",
                &[],
                Some(json!({"share": share})),
            )
            .await
        }
    };
    let (status, _, text) = submit(forged(&r.shares[0])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{text}");
    assert!(!text.contains("pvlt-share"));
    assert_eq!(
        r.app.unseal_status().submitted,
        0,
        "the forgery is not held"
    );
    // The real holders unseal as if nothing had happened.
    assert_eq!(submit(r.shares[0].clone()).await.1["sealed"], json!(true));
    assert_eq!(submit(r.shares[1].clone()).await.1["sealed"], json!(false));
}

#[tokio::test]
async fn sealing_needs_the_admin_token_and_wipes_the_keys() {
    let r = default_rig().await;
    let (_, body, _) = store(&r, "ascii", "s", SECRET).await;
    let id = body["id"].as_str().unwrap().to_owned();

    for headers in [
        vec![],
        vec![("Authorization", "Bearer nope")],
        vec![("Authorization", "Bearer compat-token-for-tests")],
        vec![("X-OPV-GRANT-TOKEN", ADMIN)],
    ] {
        let (status, ..) = call(&r.admin, Method::POST, "/v2/sys/seal", &headers, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{headers:?}");
        assert!(!r.app.engine.keyring().is_sealed());
    }
    let admin_header = format!("Bearer {ADMIN}");
    let (status, body, _) = call(
        &r.admin,
        Method::POST,
        "/v2/sys/seal",
        &[("Authorization", admin_header.as_str())],
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["sealed"], true);
    let (status, ..) = call(
        &r.data,
        Method::GET,
        &format!("/api/v1/facts/{id}"),
        &auth(),
        None,
    )
    .await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    // Erasure writes a signed ledger entry, which needs the root key, so it waits for an unseal.
    let (status, body, _) = call(
        &r.data,
        Method::DELETE,
        &format!("/api/v1/facts/{id}"),
        &auth(),
        None,
    )
    .await;
    assert_eq!(
        (status, &body["error"]),
        (StatusCode::SERVICE_UNAVAILABLE, &json!("sealed"))
    );
}

#[tokio::test]
async fn the_admin_routes_are_not_on_the_data_router_and_the_data_routes_not_on_the_admin_one() {
    let r = default_rig().await;
    assert_eq!(
        call(&r.data, Method::GET, "/v2/sys/status", &[], None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&r.data, Method::POST, "/v2/sys/seal", &[], None)
            .await
            .0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(&r.admin, Method::GET, "/healthz", &[], None).await.0,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        call(
            &r.admin,
            Method::POST,
            "/api/v1/facts",
            &auth(),
            Some(json!({}))
        )
        .await
        .0,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn readyz_reports_the_memory_protections_and_the_build() {
    let r = default_rig().await;
    allow_compat(&r).await;
    let (status, body, _) = call(&r.data, Method::GET, "/readyz", &[], None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["ready"], true);
    assert_eq!(body["key_store"], true);
    assert_eq!(body["object_store"], true);
    assert_eq!(body["ledger_in_sync"], true);
    assert!(body["memory"]["locked"].is_boolean());
    assert_eq!(body["insecure"], cfg!(feature = "dev-insecure"));
}

#[tokio::test]
async fn error_responses_carry_only_a_code_and_a_fixed_message() {
    let r = default_rig().await;
    let (_, body, _) = call(&r.data, Method::GET, "/api/v1/facts/x", &auth(), None).await;
    let keys: Vec<_> = body.as_object().unwrap().keys().cloned().collect();
    assert_eq!(keys, ["error", "message"]);
}

// --- The M2 admin routes -------------------------------------------------------------------------------------

fn admin_auth() -> [(&'static str, String); 1] {
    [("Authorization", format!("Bearer {ADMIN}"))]
}

const COMPAT_POLICY: &str = r#"{"version":1,"roles":{"compat":{"allow":[{"types":["ascii","base64","json"],"actions":["create","read","shred"]}]}}}"#;

/// Installs a policy with a `compat` role. A compat token with no such role makes `/readyz` report not ready.
async fn allow_compat(r: &Rig) {
    let h = admin_auth();
    let req = Request::builder()
        .method(Method::PUT)
        .uri("/v2/admin/policy")
        .header(h[0].0, h[0].1.as_str())
        .body(Body::from(COMPAT_POLICY))
        .unwrap();
    let res = r.admin.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::OK);
}

#[tokio::test]
async fn a_compat_token_without_a_compat_role_is_refused_and_not_ready_and_the_role_fixes_both() {
    let r = bare_rig(true, true, 1_048_576);
    let (status, body, _) = call(&r.data, Method::GET, "/readyz", &[], None).await;
    assert_eq!(
        (status, body["compat_policy"].clone(), body["ready"].clone()),
        (StatusCode::SERVICE_UNAVAILABLE, json!(false), json!(false))
    );
    // Refused, not waved through: a token the policy does not mention may do nothing.
    let (status, body, _) = store(&r, "ascii", "s", "v").await;
    assert_eq!(
        (status, body["message"].clone()),
        (StatusCode::FORBIDDEN, json!("no_usable_role"))
    );
    allow_compat(&r).await;
    let (status, body, _) = call(&r.data, Method::GET, "/readyz", &[], None).await;
    assert_eq!(
        (status, body["compat_policy"].clone(), body["ready"].clone()),
        (StatusCode::OK, json!(true), json!(true))
    );
    assert_eq!(store(&r, "ascii", "s", "v").await.0, StatusCode::OK);
    // No compat token configured: nothing to narrow, so no policy is needed.
    let none = rig(true, false, 1_048_576).await;
    assert_eq!(
        call(&none.data, Method::GET, "/readyz", &[], None).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_compat_token_cannot_read_a_restricted_type_because_it_cannot_present_an_approval() {
    let r = bare_rig(true, true, 1_048_576);
    install_policy(
        &r,
        r#"{"version":1,"restricted_types":["base64"],"roles":{"compat":{"allow":[{"types":["*"],"actions":["create","read","shred"]}]}}}"#,
    )
    .await;
    let (status, body, _) = store(&r, "base64", "kyc-doc:1", "a2V5LWJ5dGVz").await;
    assert_eq!(status, StatusCode::OK);
    let id = body["id"].as_str().unwrap().to_owned();
    let (status, body, text) = call(
        &r.data,
        Method::GET,
        &format!("/api/v1/facts/{id}"),
        &auth(),
        None,
    )
    .await;
    assert_eq!(
        (status, body["message"].clone()),
        (StatusCode::FORBIDDEN, json!("approval_required"))
    );
    assert!(!text.contains("a2V5LWJ5dGVz"));
    // A type that is not restricted still reads.
    let (_, body, _) = store(&r, "ascii", "s", "plain").await;
    let id = body["id"].as_str().unwrap().to_owned();
    let (status, body, _) = call(
        &r.data,
        Method::GET,
        &format!("/api/v1/facts/{id}"),
        &auth(),
        None,
    )
    .await;
    assert_eq!(
        (status, body["value"].clone()),
        (StatusCode::OK, json!("plain"))
    );
}

async fn admin_post(r: &Rig, path: &str, body: Value) -> (StatusCode, Value, String) {
    let h = admin_auth();
    let headers: Vec<(&str, &str)> = h.iter().map(|(k, v)| (*k, v.as_str())).collect();
    call(&r.admin, Method::POST, path, &headers, Some(body)).await
}

#[tokio::test]
async fn the_admin_shred_routes_need_the_admin_token_and_nothing_else_works_as_a_substitute() {
    let r = default_rig().await;
    for path in [
        "/v2/admin/shred/subject",
        "/v2/admin/shred/scope",
        "/v2/admin/legal-hold",
        "/v2/admin/rebind",
    ] {
        for headers in [
            vec![],
            vec![("Authorization", "Bearer nope")],
            vec![("X-OPV-GRANT-TOKEN", TOKEN)],
            vec![("Authorization", "Bearer compat-token-for-tests")],
        ] {
            let (status, ..) = call(&r.admin, Method::POST, path, &headers, Some(json!({}))).await;
            assert_eq!(status, StatusCode::UNAUTHORIZED, "{path} {headers:?}");
        }
    }
}

#[tokio::test]
async fn compat_subjects_may_be_colon_ids_with_a_length_cap_and_one_subject_shred_covers_only_its_facts()
 {
    let r = default_rig().await;
    let create = |subject: String| {
        let data = r.data.clone();
        async move {
            call(
                &data,
                Method::POST,
                "/api/v1/facts",
                &[("X-OPV-GRANT-TOKEN", TOKEN)],
                Some(json!({"fact_type_slug":"ascii","scope_custom_id":"kyc","value":"v","subject_custom_id":subject})),
            )
            .await
        }
    };
    let (s1, b1, _) = create("user:123".to_owned()).await;
    let (s2, b2, _) = create("performer:456".to_owned()).await;
    assert_eq!((s1, s2), (StatusCode::OK, StatusCode::OK));
    let (id_user, id_performer) = (b1["id"].as_str().unwrap(), b2["id"].as_str().unwrap());

    // 256 bytes is allowed, 257 is refused with a fixed message and nothing is stored.
    assert_eq!(create("u".repeat(256)).await.0, StatusCode::OK);
    let (status, body, raw) = create("u".repeat(257)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert!(!raw.contains(&"u".repeat(257)));

    let (status, body, _) = admin_post(
        &r,
        "/v2/admin/shred/subject",
        json!({"subject":"user:123","reason":"subject_request"}),
    )
    .await;
    assert_eq!(
        (status, body["outcome"].clone()),
        (StatusCode::OK, json!("shredded"))
    );
    let get = |id: &str| {
        let data = r.data.clone();
        let path = format!("/api/v1/facts/{id}");
        async move { call(&data, Method::GET, &path, &auth(), None).await.0 }
    };
    assert_eq!(get(id_user).await, StatusCode::GONE);
    assert_eq!(get(id_performer).await, StatusCode::OK);
    let (status, ..) = admin_post(
        &r,
        "/v2/admin/shred/subject",
        json!({"subject": "u".repeat(257)}),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn a_subject_shred_through_the_admin_route_destroys_the_subjects_facts_and_writes_the_ledger()
{
    let r = default_rig().await;
    allow_compat(&r).await;
    let create = |subject: &'static str, scope: &'static str, value: &'static str| {
        let data = r.data.clone();
        async move {
            let (_, body, _) = call(
                &data,
                Method::POST,
                "/api/v1/facts",
                &[("X-OPV-GRANT-TOKEN", TOKEN)],
                Some(json!({"fact_type_slug":"ascii","scope_custom_id":scope,"value":value,"subject_custom_id":subject})),
            )
            .await;
            body["id"].as_str().unwrap().to_owned()
        }
    };
    let alice = create("alice", "kyc", SECRET).await;
    let bob = create("bob", "kyc", "bob-value").await;

    let (status, body, _) = admin_post(
        &r,
        "/v2/admin/shred/subject",
        json!({"subject":"alice","reason":"subject_request"}),
    )
    .await;
    assert_eq!(
        (status, body["outcome"].clone()),
        (StatusCode::OK, json!("shredded"))
    );
    assert_eq!(
        call(
            &r.data,
            Method::GET,
            &format!("/api/v1/facts/{alice}"),
            &auth(),
            None
        )
        .await
        .0,
        StatusCode::GONE
    );
    assert_eq!(
        call(
            &r.data,
            Method::GET,
            &format!("/api/v1/facts/{bob}"),
            &auth(),
            None
        )
        .await
        .0,
        StatusCode::OK
    );
    let (_, again, _) = admin_post(&r, "/v2/admin/shred/subject", json!({"subject":"alice"})).await;
    assert_eq!(again["outcome"], "already_shredded");
    let (_, none, _) = admin_post(&r, "/v2/admin/shred/subject", json!({"subject":"nobody"})).await;
    assert_eq!(none["outcome"], "not_found");

    let (status, body, _) = admin_post(
        &r,
        "/v2/admin/shred/scope",
        json!({"scope":"kyc","reason":"legal"}),
    )
    .await;
    assert_eq!((status, body["count"].clone()), (StatusCode::OK, json!(1)));
    assert_eq!(
        call(
            &r.data,
            Method::GET,
            &format!("/api/v1/facts/{bob}"),
            &auth(),
            None
        )
        .await
        .0,
        StatusCode::GONE
    );
    // Two shreds, two ledger files, and readiness agrees the bucket has them.
    let files = pvlt_core::objects::ObjectStore::list_prefix(r.app.engine.objects(), "ledger/")
        .await
        .unwrap();
    assert_eq!(files.len(), 2);
    assert_eq!(
        call(&r.data, Method::GET, "/readyz", &[], None).await.0,
        StatusCode::OK
    );
}

#[tokio::test]
async fn the_admin_routes_refuse_bad_input_without_echoing_it() {
    let r = default_rig().await;
    for (path, body) in [
        ("/v2/admin/shred/subject", json!({})),
        (
            "/v2/admin/shred/subject",
            json!({"subject":"x","reason":"because alice asked"}),
        ),
        ("/v2/admin/shred/scope", json!({"scope":""})),
        (
            "/v2/admin/legal-hold",
            json!({"fact_id":"not-a-uuid","hold":true}),
        ),
        (
            "/v2/admin/rebind",
            json!({"fact_id":"6f1c2a7e-0000-4000-8000-000000000000"}),
        ),
    ] {
        let (status, _, text) = admin_post(&r, path, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{path}");
        assert!(
            !text.contains("alice") && !text.contains("not-a-uuid"),
            "{text}"
        );
    }
}

#[tokio::test]
async fn legal_hold_and_rebind_work_over_the_admin_route() {
    let r = default_rig().await;
    let (_, body, _) = store(&r, "ascii", "draft", "v").await;
    let id = body["id"].as_str().unwrap().to_owned();
    let (status, body, _) = admin_post(
        &r,
        "/v2/admin/legal-hold",
        json!({"fact_id": id, "hold": true}),
    )
    .await;
    assert_eq!(
        (status, body["outcome"].clone()),
        (StatusCode::OK, json!("held"))
    );
    // The held fact cannot be erased, by a compat delete or a scope shred.
    let (status, body, _) = call(
        &r.data,
        Method::DELETE,
        &format!("/api/v1/facts/{id}"),
        &auth(),
        None,
    )
    .await;
    assert_eq!(
        (status, body["error"].clone()),
        (StatusCode::CONFLICT, json!("conflict"))
    );
    let (status, ..) = admin_post(&r, "/v2/admin/shred/scope", json!({"scope":"draft"})).await;
    assert_eq!(status, StatusCode::CONFLICT);
    admin_post(
        &r,
        "/v2/admin/legal-hold",
        json!({"fact_id": id, "hold": false}),
    )
    .await;

    let (status, ..) = admin_post(
        &r,
        "/v2/admin/rebind",
        json!({"fact_id": id, "scope": "approved"}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, body, _) = admin_post(&r, "/v2/admin/shred/scope", json!({"scope":"draft"})).await;
    assert_eq!(body["count"], 0);
    let (_, body, _) = admin_post(&r, "/v2/admin/shred/scope", json!({"scope":"approved"})).await;
    assert_eq!(body["count"], 1);
}
