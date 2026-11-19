//! The admin routes: status, unseal and seal. They are served on their own listener (PLAN.md 3.5), which
//! defaults to the loopback interface, so they are not on the address the application talks to.
//!
//! Unsealing needs no token: the shares are the credential, and each is checked (version, checksum, which vault)
//! before it is held. Everything else needs the admin token (`Authorization: Bearer`).
//!
//! The `/v2/admin` routes reach subject and scope shred, legal hold, re-bind, the audit log, dual-control
//! approvals, and the policy and issuers.
//!
//! **Changes to who may do what need two admins.** Setting a policy, registering an issuer and re-enabling one
//! decide who can read, so when two or more admins are configured each is only a request
//! (`202 {"change_id": ...}`) until a *different* admin approves it with `POST /v2/admin/changes/{id}/approve`.
//! `GET /v2/admin/changes/{id}` shows the approver exactly what they are approving. Disabling an issuer only
//! narrows access and takes effect at once. With a single admin there is nobody to ask, so changes apply
//! immediately and the server warns at every start (threat T6 cannot be met by one person).
//!
//! Every admin action that changes access, or reads the audit log, is written to the audit log **before** it
//! happens, and does not happen if that write fails.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::HeaderMap;
use axum::routing::{get, post};
use axum::{Json, Router};
use pvlt_core::audit::Auditor;
use pvlt_core::audit_log::{Caller, Kind};
use pvlt_core::engine::AuditStatus;
use pvlt_core::ledger::Reason;
use pvlt_core::objects::ObjectStore;
use pvlt_core::store::AuditFilter;
use pvlt_core::store::KeyStore;
use pvlt_core::store::{NewAdminChange, NewApproval};
use pvlt_policy::policy::Policy;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::{App, UnsealStatus};
use crate::error::ApiError;

/// The routes.
pub fn router<K, O, A>(app: Arc<App<K, O, A>>) -> Router
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let gdpr = crate::gdpr::admin_router(Arc::clone(&app));
    Router::new()
        .route("/v2/sys/status", get(status::<K, O, A>))
        .route("/v2/sys/unseal", post(unseal::<K, O, A>))
        .route("/v2/sys/seal", post(seal::<K, O, A>))
        .route("/v2/admin/shred/subject", post(shred_subject::<K, O, A>))
        .route("/v2/admin/shred/scope", post(shred_scope::<K, O, A>))
        .route("/v2/admin/legal-hold", post(legal_hold::<K, O, A>))
        .route("/v2/admin/rebind", post(rebind::<K, O, A>))
        .route(
            "/v2/admin/policy",
            get(get_policy::<K, O, A>).put(put_policy::<K, O, A>),
        )
        .route(
            "/v2/admin/issuers",
            get(list_issuers::<K, O, A>).post(create_issuer::<K, O, A>),
        )
        .route(
            "/v2/admin/issuers/{id}/enable",
            post(enable_issuer::<K, O, A>),
        )
        .route(
            "/v2/admin/issuers/{id}/disable",
            post(disable_issuer::<K, O, A>),
        )
        .route("/v2/admin/import/fact", post(import_fact::<K, O, A>))
        .route("/v2/admin/audit", get(audit_query::<K, O, A>))
        .route("/v2/admin/audit/verify", get(audit_verify::<K, O, A>))
        .route(
            "/v2/admin/audit/acknowledge-rollback",
            post(audit_acknowledge::<K, O, A>),
        )
        .route("/v2/admin/approvals", post(request_approval::<K, O, A>))
        .route("/v2/admin/approvals/{id}/approve", post(approve::<K, O, A>))
        .route("/v2/admin/changes/{id}", get(get_change::<K, O, A>))
        .route(
            "/v2/admin/changes/{id}/approve",
            post(approve_change::<K, O, A>),
        )
        .with_state(app)
        .merge(gdpr)
}

#[derive(Serialize)]
struct StatusBody {
    sealed: bool,
    threshold: u8,
    submitted: usize,
}

impl From<UnsealStatus> for StatusBody {
    fn from(s: UnsealStatus) -> Self {
        Self {
            sealed: s.sealed,
            threshold: s.threshold,
            submitted: s.submitted,
        }
    }
}

async fn status<K, O, A>(State(app): State<Arc<App<K, O, A>>>) -> Json<StatusBody>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    Json(app.unseal_status().into())
}

#[derive(Deserialize)]
struct UnsealBody {
    share: String,
}

async fn unseal<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    body: axum::body::Bytes,
) -> Result<Json<StatusBody>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    // Parsed by hand so that a malformed body is a fixed message and never an echo of what was sent.
    let body: UnsealBody = serde_json::from_slice(&body)
        .map_err(|_| ApiError::BadRequest("expected {\"share\": \"...\"}"))?;
    Ok(Json(app.submit_share(&body.share)?.into()))
}

async fn seal<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
) -> Result<Json<StatusBody>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    require_admin(&app, &headers)?;
    app.seal();
    Ok(Json(app.unseal_status().into()))
}

/// Authenticates an admin credential and returns the admin's name.
pub(crate) fn require_admin<'a, K: KeyStore, O: ObjectStore, A: Auditor>(
    app: &'a App<K, O, A>,
    headers: &HeaderMap,
) -> Result<&'a str, ApiError> {
    let presented = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    app.admin_named_by(presented)
        .map(|a| a.name.as_str())
        .ok_or(ApiError::Unauthorized)
}

fn reason_of(code: Option<&str>) -> Result<Reason, ApiError> {
    Ok(match code.unwrap_or("admin") {
        "subject_request" => Reason::SubjectRequest,
        "retention" => Reason::Retention,
        "legal" => Reason::Legal,
        "admin" => Reason::Admin,
        "migration" => Reason::Migration,
        _ => {
            return Err(ApiError::BadRequest(
                "reason must be one of the listed codes",
            ));
        }
    })
}

pub(crate) fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    // By hand, so a malformed body is a fixed message and never an echo of what was sent.
    serde_json::from_slice(body).map_err(|_| ApiError::BadRequest("malformed request body"))
}

#[derive(Deserialize)]
struct ShredBody {
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    scope: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Serialize)]
struct ShredReply {
    outcome: &'static str,
    count: usize,
}

async fn shred_subject<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<ShredReply>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let b: ShredBody = parse(&body)?;
    let subject = b
        .subject
        .ok_or(ApiError::BadRequest("subject is required"))?;
    let reason = reason_of(b.reason.as_deref())?;
    app.ensure_domain().await?;
    let outcome = app
        .engine
        .shred_subject(admin, &app.domain, &subject, reason)
        .await?;
    use pvlt_core::store::ShredSubject as S;
    Ok(Json(ShredReply {
        outcome: match outcome {
            S::Shredded => "shredded",
            S::AlreadyShredded => "already_shredded",
            S::NotFound => "not_found",
        },
        count: usize::from(outcome == S::Shredded),
    }))
}

async fn shred_scope<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<ShredReply>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let b: ShredBody = parse(&body)?;
    let scope = b.scope.ok_or(ApiError::BadRequest("scope is required"))?;
    let reason = reason_of(b.reason.as_deref())?;
    app.ensure_domain().await?;
    let count = app
        .engine
        .shred_scope(admin, &app.domain, &scope, reason)
        .await?;
    Ok(Json(ShredReply {
        outcome: if count > 0 {
            "shredded"
        } else {
            "nothing_in_scope"
        },
        count,
    }))
}

#[derive(Deserialize)]
struct HoldBody {
    fact_id: uuid::Uuid,
    hold: bool,
}

async fn legal_hold<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<ShredReply>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let b: HoldBody = parse(&body)?;
    app.engine
        .set_legal_hold(admin, &app.domain, &b.fact_id, b.hold)
        .await?;
    Ok(Json(ShredReply {
        outcome: if b.hold { "held" } else { "released" },
        count: 1,
    }))
}

#[derive(Deserialize)]
struct RebindBody {
    fact_id: uuid::Uuid,
    scope: String,
}

async fn rebind<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<ShredReply>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let b: RebindBody = parse(&body)?;
    app.engine
        .rebind_scope(admin, &app.domain, &b.fact_id, &b.scope)
        .await?;
    Ok(Json(ShredReply {
        outcome: "rebound",
        count: 1,
    }))
}

// --- Policy, issuers and approvals ------------------------------------------------------------------------

#[derive(Serialize)]
struct PolicyOut {
    version: i64,
    hash: String,
    policy: serde_json::Value,
}

async fn get_policy<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
) -> Result<Json<PolicyOut>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    require_admin(&app, &headers)?;
    let access = app.access();
    let json = access
        .policy
        .canonical_json()
        .map_err(|_| ApiError::BadRequest("the policy cannot be encoded"))?;
    Ok(Json(PolicyOut {
        version: access.policy_version,
        hash: hex::encode(access.policy_hash),
        policy: serde_json::from_slice(&json).unwrap_or(serde_json::Value::Null),
    }))
}

/// How long a requested change waits for its second admin.
const CHANGE_TTL_SECS: i64 = 24 * 3600;

/// A change to who may do what, validated when it is asked for and again when it is applied.
enum Change {
    /// Replace the policy. `based_on` is the version in force when it was asked for: if another change landed
    /// first, this one is refused rather than silently undoing it.
    Policy { based_on: i64, policy: Policy },
    /// Register an issuer.
    IssuerCreate {
        name: String,
        public_key: [u8; 32],
        roles: Vec<String>,
    },
    /// Re-enable an issuer.
    IssuerEnable { key_id: u32 },
}

fn plain_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct NewIssuerBody {
    name: String,
    public_key: String,
    roles: Vec<String>,
}

impl NewIssuerBody {
    fn validate(self) -> Result<Change, ApiError> {
        let key: [u8; 32] = hex::decode(&self.public_key)
            .ok()
            .and_then(|v| v.try_into().ok())
            .ok_or(ApiError::BadRequest("public_key must be 64 hex characters"))?;
        if !plain_name(&self.name)
            || self.roles.len() > 64
            || !self.roles.iter().all(|r| plain_name(r))
        {
            return Err(ApiError::BadRequest("name and roles must be plain names"));
        }
        Ok(Change::IssuerCreate {
            name: self.name,
            public_key: key,
            roles: self.roles,
        })
    }
}

impl Change {
    fn kind(&self) -> &'static str {
        match self {
            Change::Policy { .. } => "policy.set",
            Change::IssuerCreate { .. } => "issuer.create",
            Change::IssuerEnable { .. } => "issuer.enable",
        }
    }

    /// The stored form, which is also what an approver is shown.
    fn payload(&self) -> Result<serde_json::Value, ApiError> {
        Ok(match self {
            Change::Policy { based_on, policy } => {
                let json = policy
                    .canonical_json()
                    .map_err(|_| ApiError::BadRequest("the policy cannot be encoded"))?;
                serde_json::json!({
                    "based_on": based_on,
                    "policy": serde_json::from_slice::<serde_json::Value>(&json)
                        .map_err(|_| ApiError::BadRequest("the policy cannot be encoded"))?,
                })
            }
            Change::IssuerCreate {
                name,
                public_key,
                roles,
            } => serde_json::to_value(NewIssuerBody {
                name: name.clone(),
                public_key: hex::encode(public_key),
                roles: roles.clone(),
            })
            .map_err(|_| ApiError::BadRequest("the issuer cannot be encoded"))?,
            Change::IssuerEnable { key_id } => serde_json::json!({ "key_id": key_id }),
        })
    }

    /// Reads a stored change back, checking it as strictly as when it was asked for.
    fn from_stored(kind: &str, payload: &[u8]) -> Result<Self, ApiError> {
        let bad = || {
            ApiError::Vault(pvlt_core::VaultError::Integrity(
                "a stored admin change does not parse",
            ))
        };
        let v: serde_json::Value = serde_json::from_slice(payload).map_err(|_| bad())?;
        match kind {
            "policy.set" => {
                let based_on = v
                    .get("based_on")
                    .and_then(serde_json::Value::as_i64)
                    .ok_or_else(bad)?;
                let doc = v.get("policy").ok_or_else(bad)?;
                let policy = Policy::from_json(doc.to_string().as_bytes()).map_err(|_| bad())?;
                Ok(Change::Policy { based_on, policy })
            }
            "issuer.create" => serde_json::from_value::<NewIssuerBody>(v)
                .map_err(|_| bad())?
                .validate(),
            "issuer.enable" => {
                let key_id = v
                    .get("key_id")
                    .and_then(serde_json::Value::as_u64)
                    .and_then(|k| u32::try_from(k).ok())
                    .ok_or_else(bad)?;
                Ok(Change::IssuerEnable { key_id })
            }
            _ => Err(bad()),
        }
    }
}

/// The version of the policy the key store holds now, 0 if none. Read from the store, not this replica's copy,
/// so a change another replica applied counts.
async fn stored_policy_version<K: KeyStore, O: ObjectStore, A: Auditor>(
    app: &App<K, O, A>,
) -> Result<i64, ApiError> {
    Ok(app
        .engine
        .store()
        .current_policy()
        .await
        .map_err(pvlt_core::VaultError::from)?
        .map_or(0, |p| p.version))
}

/// Makes a change take effect: writes the audit entry first, then the change, then reloads. Returns what the
/// direct route returns.
async fn apply<K, O, A>(
    app: &App<K, O, A>,
    caller: &Caller<'_>,
    change: Change,
) -> Result<serde_json::Value, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = caller.principal;
    match change {
        Change::Policy { based_on, policy } => {
            if stored_policy_version(app).await? != based_on {
                return Err(ApiError::Vault(pvlt_core::VaultError::Conflict(
                    "the policy changed since this change was asked for; ask again",
                )));
            }
            let json = policy
                .canonical_json()
                .map_err(|_| ApiError::BadRequest("the policy cannot be encoded"))?;
            let hash = policy
                .hash()
                .map_err(|_| ApiError::BadRequest("the policy cannot be hashed"))?;
            admin_audit(app, caller, "policy.set", None).await?;
            let rec = app
                .engine
                .store()
                .put_policy(&json, &hash, admin)
                .await
                .map_err(pvlt_core::VaultError::from)?;
            app.reload_access().await?;
            tracing::info!(admin, version = rec.version, hash = %hex::encode(hash), "policy set");
            let unlimited = policy.roles_without_totals();
            if !unlimited.is_empty() {
                tracing::warn!(
                    roles = ?unlimited,
                    "these roles limit each caller but set no total, so an issuer that varies the caller is not held"
                );
            }
            serde_json::to_value(PolicyOut {
                version: rec.version,
                hash: hex::encode(hash),
                policy: serde_json::from_slice(&json).unwrap_or(serde_json::Value::Null),
            })
            .map_err(|_| ApiError::BadRequest("the policy cannot be encoded"))
        }
        Change::IssuerCreate {
            name,
            public_key,
            roles,
        } => {
            admin_audit(app, caller, "issuer.create", None).await?;
            let rec = app
                .engine
                .store()
                .create_issuer(&name, &public_key, &roles)
                .await
                .map_err(pvlt_core::VaultError::from)?;
            app.reload_access().await?;
            tracing::info!(admin, issuer = %rec.name, key_id = rec.key_id, "issuer registered");
            serde_json::to_value(IssuerOut::from(rec))
                .map_err(|_| ApiError::BadRequest("the issuer cannot be encoded"))
        }
        Change::IssuerEnable { key_id } => {
            set_issuer_now(app, caller, key_id, true).await?;
            serde_json::to_value(ShredReply {
                outcome: "enabled",
                count: 1,
            })
            .map_err(|_| ApiError::BadRequest("cannot encode"))
        }
    }
}

#[derive(Serialize)]
struct Requested {
    change_id: Uuid,
    kind: &'static str,
    status: &'static str,
    requested_by: String,
    expires_at_unix: i64,
}

/// Applies a change at once when one admin is all there is, and otherwise records it for a second admin.
async fn request_or_apply<K, O, A>(
    app: &App<K, O, A>,
    admin: &str,
    change: Change,
) -> Result<axum::response::Response, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    use axum::response::IntoResponse;
    if !app.changes_need_two_admins() {
        let body = apply(app, &Caller::from(admin), change).await?;
        return Ok(Json(body).into_response());
    }
    let id = random_id()?;
    let id_text = id.to_string();
    let kind = change.kind();
    let payload = serde_json::to_vec(&change.payload()?)
        .map_err(|_| ApiError::BadRequest("the change cannot be encoded"))?;
    admin_audit(
        app,
        &Caller {
            request_id: Some(&id_text),
            ..Caller::from(admin)
        },
        &format!("change.request:{kind}"),
        None,
    )
    .await?;
    let rec = app
        .engine
        .store()
        .create_admin_change(&NewAdminChange {
            id,
            kind: kind.to_owned(),
            payload,
            requested_by: admin.to_owned(),
            expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(CHANGE_TTL_SECS),
        })
        .await
        .map_err(pvlt_core::VaultError::from)?;
    tracing::info!(admin, change = %id, kind, "change requested; a second admin must approve it");
    Ok((
        axum::http::StatusCode::ACCEPTED,
        Json(Requested {
            change_id: rec.id,
            kind,
            status: "pending",
            requested_by: rec.requested_by,
            expires_at_unix: rec.expires_at.unix_timestamp(),
        }),
    )
        .into_response())
}

fn random_id() -> Result<Uuid, ApiError> {
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| ApiError::Vault(pvlt_core::VaultError::Unavailable("random")))?;
    // A well-formed version-4 UUID.
    Ok(uuid::Builder::from_random_bytes(random).into_uuid())
}

/// Asks for a new policy version. The body is validated strictly; an invalid policy changes nothing. Once
/// applied it takes effect at once on this replica and within the reload interval on others.
async fn put_policy<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let policy = Policy::from_json(&body).map_err(|e| ApiError::BadRequest(e.0))?;
    let based_on = stored_policy_version(&app).await?;
    request_or_apply(&app, admin, Change::Policy { based_on, policy }).await
}

#[derive(Serialize)]
struct ChangeOut {
    id: Uuid,
    kind: String,
    status: &'static str,
    requested_by: String,
    approved_by: Option<String>,
    expires_at_unix: i64,
    /// What it does, exactly as it will be applied.
    change: serde_json::Value,
}

/// Shows a requested change, so the second admin sees what they approve.
async fn get_change<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ChangeOut>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    require_admin(&app, &headers)?;
    let id = Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("id is not a UUID"))?;
    let rec = app
        .engine
        .store()
        .admin_change(&id)
        .await
        .map_err(pvlt_core::VaultError::from)?;
    let status = if rec.approved_by.is_some() {
        "approved"
    } else if rec.expires_at <= OffsetDateTime::now_utc() {
        "expired"
    } else {
        "pending"
    };
    Ok(Json(ChangeOut {
        id: rec.id,
        kind: rec.kind,
        status,
        requested_by: rec.requested_by,
        approved_by: rec.approved_by,
        expires_at_unix: rec.expires_at.unix_timestamp(),
        change: serde_json::from_slice(&rec.payload).unwrap_or(serde_json::Value::Null),
    }))
}

#[derive(Serialize)]
struct Applied {
    id: Uuid,
    kind: String,
    status: &'static str,
    requested_by: String,
    approved_by: String,
    result: serde_json::Value,
}

/// A second admin approves a requested change, which then takes effect. The approver must not be the requester
/// (the key store enforces it too), and a change is approved once.
async fn approve_change<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Applied>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let id = Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("id is not a UUID"))?;
    let id_text = id.to_string();
    let caller = Caller {
        request_id: Some(&id_text),
        ..Caller::from(admin)
    };
    let pending = app
        .engine
        .store()
        .admin_change(&id)
        .await
        .map_err(pvlt_core::VaultError::from)?;
    if pending.requested_by == admin {
        return Err(ApiError::Forbidden("approver_is_requester"));
    }
    // Parse before approving, so a change that could not be applied is not spent.
    let change = Change::from_stored(&pending.kind, &pending.payload)?;
    if let Change::Policy { based_on, .. } = &change
        && stored_policy_version(&app).await? != *based_on
    {
        return Err(ApiError::Vault(pvlt_core::VaultError::Conflict(
            "the policy changed since this change was asked for; ask again",
        )));
    }
    admin_audit(
        &app,
        &caller,
        &format!("change.approve:{}", pending.kind),
        None,
    )
    .await?;
    let rec = app
        .engine
        .store()
        .approve_admin_change(&id, admin, OffsetDateTime::now_utc())
        .await
        .map_err(pvlt_core::VaultError::from)?;
    tracing::info!(admin, change = %id, kind = %rec.kind, requested_by = %rec.requested_by, "change approved");
    let result = apply(&app, &caller, change).await?;
    Ok(Json(Applied {
        id: rec.id,
        kind: rec.kind,
        status: "applied",
        requested_by: rec.requested_by,
        approved_by: admin.to_owned(),
        result,
    }))
}

#[derive(Serialize)]
struct IssuerOut {
    key_id: u32,
    name: String,
    public_key: String,
    roles: Vec<String>,
    enabled: bool,
}

impl From<pvlt_core::store::IssuerRecord> for IssuerOut {
    fn from(i: pvlt_core::store::IssuerRecord) -> Self {
        Self {
            key_id: i.key_id,
            name: i.name,
            public_key: hex::encode(i.public_key),
            roles: i.roles,
            enabled: i.enabled,
        }
    }
}

async fn list_issuers<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
) -> Result<Json<Vec<IssuerOut>>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    require_admin(&app, &headers)?;
    let all = app
        .engine
        .store()
        .issuers()
        .await
        .map_err(pvlt_core::VaultError::from)?;
    Ok(Json(all.into_iter().map(IssuerOut::from).collect()))
}

/// Asks to register an issuer.
async fn create_issuer<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<axum::response::Response, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let b: NewIssuerBody = parse(&body)?;
    let change = b.validate()?;
    request_or_apply(&app, admin, change).await
}

fn parse_key_id(id: &str) -> Result<u32, ApiError> {
    id.parse()
        .map_err(|_| ApiError::BadRequest("issuer id is not a number"))
}

/// Enables or disables an issuer now, after writing the audit entry.
async fn set_issuer_now<K, O, A>(
    app: &App<K, O, A>,
    caller: &Caller<'_>,
    key_id: u32,
    enabled: bool,
) -> Result<(), ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let action = if enabled {
        "issuer.enable"
    } else {
        "issuer.disable"
    };
    admin_audit(app, caller, action, None).await?;
    app.engine
        .store()
        .set_issuer_enabled(key_id, enabled)
        .await
        .map_err(pvlt_core::VaultError::from)?;
    app.reload_access().await?;
    tracing::info!(admin = caller.principal, key_id, enabled, "issuer changed");
    Ok(())
}

/// Asks to re-enable an issuer: it widens who can act, so it needs a second admin like a new issuer.
async fn enable_issuer<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<axum::response::Response, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let key_id = parse_key_id(&id)?;
    request_or_apply(&app, admin, Change::IssuerEnable { key_id }).await
}

/// Disables an issuer at once: it only narrows who can act, so it needs no second admin.
async fn disable_issuer<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ShredReply>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let key_id = parse_key_id(&id)?;
    set_issuer_now(&app, &Caller::from(admin), key_id, false).await?;
    Ok(Json(ShredReply {
        outcome: "disabled",
        count: 1,
    }))
}

/// The longest an approval may live: 15 minutes, or 5 for break-glass.
const MAX_APPROVAL_SECS: i64 = 900;
const MAX_BREAK_GLASS_SECS: i64 = 300;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalBody {
    fact_id: Uuid,
    /// The caller (a token's `caller` claim) who will read. Only a token naming this caller can spend it.
    caller: String,
    #[serde(default)]
    ttl_secs: Option<i64>,
    #[serde(default)]
    break_glass: bool,
}

#[derive(Serialize)]
struct ApprovalOut {
    id: Uuid,
    expires_at_unix: i64,
    approved: bool,
    break_glass: bool,
    caller: Option<String>,
}

/// An admin asks for one caller to read one fact once. A different admin must approve before it works. With
/// break-glass enabled in the configuration the requester may approve it alone, for at most five minutes; it is
/// logged at warning level every time.
async fn request_approval<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<ApprovalOut>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let b: ApprovalBody = parse(&body)?;
    if b.break_glass && !app.break_glass {
        return Err(ApiError::Forbidden("break_glass_disabled"));
    }
    if b.caller.is_empty() || b.caller.len() > crate::tokens::MAX_CLAIM_LEN {
        return Err(ApiError::BadRequest("caller is empty or too long"));
    }
    let cap = if b.break_glass {
        MAX_BREAK_GLASS_SECS
    } else {
        MAX_APPROVAL_SECS
    };
    let ttl = b.ttl_secs.unwrap_or(cap);
    if ttl <= 0 || ttl > cap {
        return Err(ApiError::BadRequest("ttl_secs is out of range"));
    }
    let id = random_id()?;
    let action = if b.break_glass {
        "approval.break_glass"
    } else {
        "approval.request"
    };
    let id_text = id.to_string();
    admin_audit(
        &app,
        &Caller {
            request_id: Some(&id_text),
            caller: Some(&b.caller),
            ..Caller::from(admin)
        },
        action,
        Some(b.fact_id),
    )
    .await?;
    let rec = app
        .engine
        .store()
        .create_approval(&NewApproval {
            id,
            domain_id: app.domain,
            fact_id: b.fact_id,
            requested_by: admin.to_owned(),
            break_glass: b.break_glass,
            expires_at: OffsetDateTime::now_utc() + time::Duration::seconds(ttl),
            reader: b.caller.clone(),
        })
        .await
        .map_err(pvlt_core::VaultError::from)?;
    if b.break_glass {
        tracing::warn!(admin, fact_id = %b.fact_id, approval = %id, "BREAK-GLASS read approved by its requester");
    } else {
        tracing::info!(admin, fact_id = %b.fact_id, approval = %id, "read approval requested");
    }
    Ok(Json(ApprovalOut {
        id: rec.id,
        expires_at_unix: rec.expires_at.unix_timestamp(),
        approved: rec.approved_by.is_some(),
        break_glass: rec.break_glass,
        caller: rec.reader,
    }))
}

async fn approve<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ApprovalOut>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let id = Uuid::parse_str(&id).map_err(|_| ApiError::BadRequest("id is not a UUID"))?;
    let id_text = id.to_string();
    admin_audit(
        &app,
        &Caller {
            request_id: Some(&id_text),
            ..Caller::from(admin)
        },
        "approval.approve",
        None,
    )
    .await?;
    let rec = app
        .engine
        .store()
        .approve(&id, admin, OffsetDateTime::now_utc())
        .await
        .map_err(pvlt_core::VaultError::from)?;
    tracing::info!(admin, approval = %id, fact_id = %rec.fact_id, "read approval granted");
    Ok(Json(ApprovalOut {
        id: rec.id,
        expires_at_unix: rec.expires_at.unix_timestamp(),
        approved: true,
        break_glass: rec.break_glass,
        caller: rec.reader,
    }))
}

// --- The audit log ------------------------------------------------------------------------------------------

/// Writes an `admin` entry for an administrative action, **before** the action. If the entry cannot be made
/// durable the action must not happen: an admin is not trusted to act unrecorded (threat T6).
async fn admin_audit<K, O, A>(
    app: &App<K, O, A>,
    caller: &Caller<'_>,
    action: &str,
    fact_id: Option<Uuid>,
) -> Result<(), ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    app.ensure_domain().await?;
    app.engine
        .audit_event(
            &app.domain,
            Kind::Admin,
            caller,
            action,
            fact_id,
            None,
            None,
        )
        .await
        .map_err(|e| {
            tracing::warn!(admin = caller.principal, action, error = %e, "admin action refused: the audit log cannot be written");
            ApiError::Vault(pvlt_core::VaultError::Unavailable("audit log"))
        })
}

#[derive(Deserialize, Default)]
struct AuditParams {
    subject: Option<String>,
    principal: Option<String>,
    fact_id: Option<Uuid>,
    kind: Option<String>,
    from: Option<i64>,
    to: Option<i64>,
    after_seq: Option<u64>,
    limit: Option<u32>,
}

#[derive(Serialize)]
struct AuditPage {
    entries: Vec<serde_json::Value>,
    next_after_seq: Option<u64>,
}

/// Queries the audit log: who touched which fact, by subject, principal, fact, type or time. A subject is given
/// in the clear and blinded here. The query is itself written to the log. This is also how a data subject's own
/// access report is produced: filter by their subject.
async fn audit_query<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Query(p): Query<AuditParams>,
) -> Result<Json<AuditPage>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let limit = p.limit.unwrap_or(100).clamp(1, 1000);
    let ts = |t: Option<i64>| -> Result<Option<OffsetDateTime>, ApiError> {
        t.map(|v| {
            OffsetDateTime::from_unix_timestamp(v)
                .map_err(|_| ApiError::BadRequest("time is out of range"))
        })
        .transpose()
    };
    let subject_hmac = match p.subject.as_deref() {
        Some(s) if !s.is_empty() => Some(app.engine.subject_hmac(&app.domain, s).await?),
        Some(_) => return Err(ApiError::BadRequest("subject is empty")),
        None => None,
    };
    let filter = AuditFilter {
        subject_hmac,
        principal: p.principal,
        fact_id: p.fact_id,
        kind: p.kind,
        from: ts(p.from)?,
        to: ts(p.to)?,
        after_seq: p.after_seq,
        limit,
    };
    admin_audit(&app, &Caller::from(admin), "audit.query", filter.fact_id).await?;
    let rows = app.engine.audit_query(&app.domain, &filter).await?;
    let next = (rows.len() == usize::try_from(limit).unwrap_or(usize::MAX))
        .then(|| rows.last().map(|r| r.seq))
        .flatten();
    let entries = rows
        .iter()
        .filter_map(|r| serde_json::from_slice(&r.line).ok())
        .collect();
    Ok(Json(AuditPage {
        entries,
        next_after_seq: next,
    }))
}

#[derive(Serialize)]
struct VerifyOut {
    status: &'static str,
    detail: Option<&'static str>,
    entries: u64,
    checkpoints: usize,
    lost_checkpoint_seq: Option<u64>,
    reads_blocked: bool,
}

async fn audit_verify<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
) -> Result<Json<VerifyOut>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    require_admin(&app, &headers)?;
    let v = app.engine.verify_audit(&app.domain).await?;
    let (status, detail, lost) = match v.status {
        AuditStatus::Ok => ("ok", None, None),
        AuditStatus::Truncated { checkpoint_seq, .. } => ("truncated", None, Some(checkpoint_seq)),
        AuditStatus::Tampered(why) => ("tampered", Some(why), None),
    };
    Ok(Json(VerifyOut {
        status,
        detail,
        entries: v.entries,
        checkpoints: v.checkpoints,
        lost_checkpoint_seq: lost,
        reads_blocked: app.engine.audit_blocked(),
    }))
}

/// Takes responsibility for audit entries lost since a backup was restored, so reads can resume. Needs the vault
/// unsealed, because the acknowledgement is signed.
async fn audit_acknowledge<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
) -> Result<Json<ShredReply>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let hash = app.access().policy_hash;
    let (from, through) = app
        .engine
        .acknowledge_audit_rollback(&Caller::from(admin), &app.domain, &hash)
        .await?;
    tracing::warn!(admin, from, through, "audit rollback acknowledged");
    Ok(Json(ShredReply {
        outcome: "acknowledged",
        count: usize::try_from(through.saturating_sub(from) + 1).unwrap_or(usize::MAX),
    }))
}

// --- Import ---------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ImportBody {
    /// The id to keep: a client's stored fact-id column must not need rewriting (REQUIREMENTS C3).
    id: Uuid,
    #[serde(default)]
    subject: Option<String>,
    scope: String,
    #[serde(rename = "type")]
    fact_type: String,
    value: String,
}

#[derive(Serialize)]
struct Imported {
    id: Uuid,
}

/// Stores a fact under an id the caller chose, for moving data in from another vault (`pvlt import-opv`). The
/// value is checked against its type like any other. An id that is already taken is a 409, which an importer
/// resumes past after checking the stored value matches. The action is written to the audit log under the
/// admin's name, and nothing in this route reads a value back: an admin can write but still cannot read.
async fn import_fact<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<(axum::http::StatusCode, Json<Imported>), ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let b: ImportBody = parse(&body)?;
    crate::compat::validate(&b.fact_type, b.value.as_bytes())?;
    app.ensure_domain().await?;
    let id = app
        .engine
        .create_fact(
            admin,
            &app.domain,
            &pvlt_core::engine::CreateFact {
                fact_id: Some(b.id),
                subject: b.subject.as_deref(),
                scope: &b.scope,
                fact_type: &b.fact_type,
                value: b.value.as_bytes(),
                expires_at: None,
            },
        )
        .await?;
    Ok((axum::http::StatusCode::CREATED, Json(Imported { id })))
}
