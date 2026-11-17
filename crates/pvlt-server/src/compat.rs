//! The OPV-compatible routes (REQUIREMENTS 1.2 and C1 to C4): the three calls an OPV client makes.
//!
//! | Call | Request | Response |
//! |---|---|---|
//! | store | `POST /api/v1/facts` `{fact_type_slug, scope_custom_id, value}` | `{"id": "<uuid>"}` |
//! | get | `GET /api/v1/facts/{id}` | `{"id", "fact_type_slug", "value"}` |
//! | delete | `DELETE /api/v1/facts/{id}` | 204, or 404 if there was no such fact |
//!
//! Authentication is the `X-OPV-GRANT-TOKEN` header against one static token. It maps to one principal,
//! `compat`, and one domain. This is deprecated from day one and is the M1 access model.
//!
//! Differences from OPV, on purpose:
//! * a fact type other than `ascii`, `printableascii`, `base64` or `json` is a 400 (OPV ships about 55);
//! * a fact without `subject_custom_id` has no subject, so a subject shred does not cover it (REQUIREMENTS C4);
//! * a shredded fact is 410 Gone, not 404, so a caller can tell destroyed from never existed;
//! * `DELETE` writes a signed ledger entry, which needs the vault unsealed: sealed, it is a 503.

use std::sync::Arc;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use pvlt_core::VaultError;
use pvlt_core::audit::Action as AuditAction;
use pvlt_core::audit::Auditor;
use pvlt_core::audit_log::{Caller, Kind};
use pvlt_core::engine::CreateFact;
use pvlt_core::ledger::Reason;
use pvlt_core::objects::ObjectStore;
use pvlt_core::policy::{Action, Decision, Request};
use pvlt_core::store::{KeyStore, ShredFact};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::app::App;
use crate::error::ApiError;

/// The header OPV clients send.
pub const TOKEN_HEADER: &str = "x-opv-grant-token";
/// The principal every compat request runs as.
pub const PRINCIPAL: &str = "compat";

/// The routes.
pub fn router<K, O, A>(app: Arc<App<K, O, A>>) -> Router
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    Router::new()
        .route("/api/v1/facts", post(create::<K, O, A>))
        .route(
            "/api/v1/facts/{id}",
            get(read::<K, O, A>).delete(delete::<K, O, A>),
        )
        .with_state(app)
}

fn authorize<K, O, A>(app: &App<K, O, A>, headers: &HeaderMap) -> Result<(), ApiError> {
    let presented = headers
        .get(TOKEN_HEADER)
        .and_then(|v| v.to_str().ok())
        .ok_or(ApiError::Unauthorized)?;
    match &app.compat_token {
        Some(token) if token.matches(presented) => Ok(()),
        _ => Err(ApiError::Unauthorized),
    }
}

/// Reports a refusal to the log lines and, durably and best effort, to the audit log.
async fn refuse<K: KeyStore, O: ObjectStore, A: Auditor>(
    app: &App<K, O, A>,
    audit_action: AuditAction,
    fact_id: Option<Uuid>,
    code: &'static str,
) {
    app.engine.report(PRINCIPAL, audit_action, fact_id, code);
    let _ = app
        .engine
        .audit_event(
            &app.domain,
            Kind::Deny,
            &Caller::from(PRINCIPAL),
            audit_action.name(),
            fact_id,
            None,
            Some(code),
        )
        .await;
}

/// The static token runs as the policy's `compat` role if it has one, and is allowed everything if not.
async fn compat_authorize<K: KeyStore, O: ObjectStore, A: Auditor>(
    app: &App<K, O, A>,
    action: Action,
    audit_action: AuditAction,
    fact_type: &str,
    fact_id: Option<Uuid>,
) -> Result<(), ApiError> {
    let access = app.access();
    match access.policy.decide_compat(&Request {
        action,
        fact_type: Some(fact_type),
        subject_matches: false,
    }) {
        Decision::Allow(allowed) => {
            if let Err(e) = crate::v2::rate_limit(app, &allowed, PRINCIPAL, action) {
                refuse(app, audit_action, fact_id, "rate_limited").await;
                return Err(e);
            }
            Ok(())
        }
        Decision::Deny(d) => {
            refuse(app, audit_action, fact_id, d.code()).await;
            Err(ApiError::Forbidden(d.code()))
        }
    }
}

fn parse_id(text: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(text).map_err(|_| ApiError::BadRequest("id is not a UUID"))
}

/// Checks a value against its fact type. The four types clients use.
pub fn validate(slug: &str, value: &[u8]) -> Result<(), ApiError> {
    let ok = match slug {
        "ascii" => value.is_ascii(),
        "printableascii" => value.iter().all(|b| (0x20..=0x7e).contains(b)),
        "base64" => {
            let mut sink = Zeroizing::new(Vec::new());
            STANDARD.decode_vec(value, &mut sink).is_ok()
        }
        "json" => serde_json::from_slice::<serde::de::IgnoredAny>(value).is_ok(),
        _ => return Err(ApiError::BadRequest("unknown fact_type_slug")),
    };
    if ok {
        Ok(())
    } else {
        Err(ApiError::BadRequest("value does not match fact_type_slug"))
    }
}

#[derive(Deserialize)]
struct CreateBody {
    fact_type_slug: String,
    scope_custom_id: String,
    value: String,
    /// Not in OPV. Lets a caller file the fact under a person so that person can be shredded.
    #[serde(default)]
    subject_custom_id: Option<String>,
}

#[derive(Serialize)]
struct Created {
    id: Uuid,
}

async fn create<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Created>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    authorize(&app, &headers)?;
    // By hand, so that a parse error is a fixed message: serde's text can quote the value it choked on.
    let body: CreateBody = serde_json::from_slice(&body).map_err(|_| {
        ApiError::BadRequest("expected {fact_type_slug, scope_custom_id, value} as strings")
    })?;
    validate(&body.fact_type_slug, body.value.as_bytes())?;
    compat_authorize(
        &app,
        Action::Create,
        AuditAction::Create,
        &body.fact_type_slug,
        None,
    )
    .await?;
    app.ensure_domain().await?;
    let id = app
        .engine
        .create_fact(
            PRINCIPAL,
            &app.domain,
            &CreateFact {
                fact_id: None,
                subject: body.subject_custom_id.as_deref(),
                scope: &body.scope_custom_id,
                fact_type: &body.fact_type_slug,
                value: body.value.as_bytes(),
                expires_at: None,
            },
        )
        .await?;
    Ok(Json(Created { id }))
}

#[derive(Serialize)]
struct Fact {
    id: Uuid,
    fact_type_slug: String,
    value: String,
}

async fn read<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Fact>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    authorize(&app, &headers)?;
    let id = parse_id(&id)?;
    let meta = app.engine.fact_meta(&app.domain, &id).await?;
    compat_authorize(
        &app,
        Action::Read,
        AuditAction::Read,
        &meta.fact_type,
        Some(id),
    )
    .await?;
    let fact = app.engine.read_fact(PRINCIPAL, &app.domain, &id).await?;
    // Every value was a JSON string when it went in, so this holds unless the bucket was tampered with.
    let value = String::from_utf8(fact.value.to_vec())
        .map_err(|_| ApiError::Vault(VaultError::OpenFailed))?;
    Ok(Json(Fact {
        id: fact.fact_id,
        fact_type_slug: fact.fact_type,
        value,
    }))
}

async fn delete<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    authorize(&app, &headers)?;
    let id = parse_id(&id)?;
    match app.engine.fact_meta(&app.domain, &id).await {
        Err(VaultError::NotFound) => return Ok(StatusCode::NOT_FOUND),
        Err(e) => return Err(e.into()),
        Ok(meta) => {
            compat_authorize(
                &app,
                Action::Shred,
                AuditAction::ShredFact,
                &meta.fact_type,
                Some(id),
            )
            .await?;
        }
    }
    match app
        .engine
        .shred_fact(PRINCIPAL, &app.domain, &id, Reason::SubjectRequest)
        .await?
    {
        ShredFact::NotFound => Ok(StatusCode::NOT_FOUND),
        ShredFact::Shredded { .. } | ShredFact::AlreadyShredded => Ok(StatusCode::NO_CONTENT),
    }
}
