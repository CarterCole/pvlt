//! The data listener's router: health, readiness and the compat routes.

use std::sync::Arc;

use axum::extract::{DefaultBodyLimit, State};
use axum::http::StatusCode;
use axum::routing::get;
use axum::{Json, Router};
use pvlt_core::audit::Auditor;
use pvlt_core::objects::ObjectStore;
use pvlt_core::store::KeyStore;
use serde_json::{Value, json};

use crate::app::App;
use crate::{INSECURE_BUILD, blobs, compat, gdpr, v2};

/// The largest request body. A value is at most 4 MiB, and JSON escaping can grow it.
const BODY_LIMIT: usize = 8 * 1024 * 1024;

/// The data router.
pub fn data_router<K, O, A>(app: Arc<App<K, O, A>>) -> Router
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz::<K, O, A>))
        .with_state(Arc::clone(&app))
        .merge(compat::router(Arc::clone(&app)))
        .merge(v2::router(Arc::clone(&app)))
        .merge(gdpr::data_router(Arc::clone(&app)))
        .merge(blobs::router(app))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
}

/// Liveness: the process answers. Touches nothing.
async fn healthz() -> &'static str {
    "ok"
}

/// Readiness: unsealed, the key store answers and the bucket answers. Never writes a fact. 503 otherwise, and the
/// body says which part failed (a caller must be able to tell "sealed" from "database down").
async fn readyz<K, O, A>(State(app): State<Arc<App<K, O, A>>>) -> (StatusCode, Json<Value>)
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let sealed = app.engine.keyring().is_sealed();
    let key_store = app.engine.store().ping().await.is_ok();
    let objects = app.engine.objects().ping().await.is_ok();
    // The key store's ledger head must be the bucket's head. If this fails, either the bucket lost an entry or
    // the key store is behind it, and shreds may not survive a restore until it is fixed.
    let ledger = key_store && objects && app.engine.ledger_in_sync().await.unwrap_or(false);
    // Reads stop while the audit log has lost entries nobody has acknowledged (REQUIREMENTS 3.9).
    let audit = !app.engine.audit_blocked();
    // A compat token with no `compat` role in the policy may do anything, so the safe configuration is the only
    // one that reports ready: set a policy with that role, or unset the token.
    let compat_policy = app.compat_token.is_none() || app.access().policy.has_compat_role();
    let ready = !sealed && key_store && objects && ledger && audit && compat_policy;
    let report = app.engine.keyring().arena().report();
    let body = json!({
        "ready": ready,
        "sealed": sealed,
        "key_store": key_store,
        "object_store": objects,
        "ledger_in_sync": ledger,
        "audit_ok": audit,
        "compat_policy": compat_policy,
        "memory": {
            "locked": report.locked,
            "excluded_from_dumps": report.excluded_from_dumps,
            "wiped_on_fork": report.wiped_on_fork,
        },
        "insecure": INSECURE_BUILD,
    });
    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (status, Json(body))
}
