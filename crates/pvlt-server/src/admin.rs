//! The admin routes: status, unseal and seal. They are served on their own listener (PLAN.md 3.5), which
//! defaults to the loopback interface, so they are not on the address the application talks to.
//!
//! Unsealing needs no token: the shares are the credential, and each is checked (version, checksum, which vault)
//! before it is held. Everything else needs the admin token (`Authorization: Bearer`).
//!
//! The `/v2/admin` routes are the M2 way to reach subject and scope shred, legal hold and re-bind. They are a
//! single admin credential with no policy, no dual control and no durable audit entry: M3 and M4 replace them.

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
use pvlt_core::policy::Policy;
use pvlt_core::store::AuditFilter;
use pvlt_core::store::KeyStore;
use pvlt_core::store::NewApproval;
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
        .with_state(app)
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
fn require_admin<'a, K: KeyStore, O: ObjectStore, A: Auditor>(
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

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
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

/// Stores a new policy version. The body is validated strictly and stored in canonical form; an invalid policy
/// changes nothing. The new version applies at once on this replica and within the reload interval on others.
async fn put_policy<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<PolicyOut>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let policy = Policy::from_json(&body).map_err(|e| ApiError::BadRequest(e.0))?;
    let json = policy
        .canonical_json()
        .map_err(|_| ApiError::BadRequest("the policy cannot be encoded"))?;
    let hash = policy
        .hash()
        .map_err(|_| ApiError::BadRequest("the policy cannot be hashed"))?;
    let rec = app
        .engine
        .store()
        .put_policy(&json, &hash, admin)
        .await
        .map_err(pvlt_core::VaultError::from)?;
    app.reload_access().await?;
    tracing::info!(admin, version = rec.version, hash = %hex::encode(hash), "policy set");
    admin_audit(&app, admin, "policy.set", None).await;
    Ok(Json(PolicyOut {
        version: rec.version,
        hash: hex::encode(hash),
        policy: serde_json::from_slice(&json).unwrap_or(serde_json::Value::Null),
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

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewIssuerBody {
    name: String,
    public_key: String,
    roles: Vec<String>,
}

async fn create_issuer<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<IssuerOut>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(&app, &headers)?;
    let b: NewIssuerBody = parse(&body)?;
    let key: [u8; 32] = hex::decode(&b.public_key)
        .ok()
        .and_then(|v| v.try_into().ok())
        .ok_or(ApiError::BadRequest("public_key must be 64 hex characters"))?;
    let name_ok = !b.name.is_empty()
        && b.name.len() <= 64
        && b.name
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'));
    let roles_ok = b.roles.len() <= 64
        && b.roles.iter().all(|r| {
            !r.is_empty()
                && r.len() <= 64
                && r.bytes()
                    .all(|c| c.is_ascii_alphanumeric() || matches!(c, b'-' | b'_' | b'.'))
        });
    if !name_ok || !roles_ok {
        return Err(ApiError::BadRequest("name and roles must be plain names"));
    }
    let rec = app
        .engine
        .store()
        .create_issuer(&b.name, &key, &b.roles)
        .await
        .map_err(pvlt_core::VaultError::from)?;
    app.reload_access().await?;
    tracing::info!(admin, issuer = %rec.name, key_id = rec.key_id, "issuer registered");
    admin_audit(&app, admin, "issuer.create", None).await;
    Ok(Json(rec.into()))
}

async fn set_issuer<K, O, A>(
    app: &App<K, O, A>,
    headers: &HeaderMap,
    id: &str,
    enabled: bool,
) -> Result<Json<ShredReply>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = require_admin(app, headers)?;
    let key_id: u32 = id
        .parse()
        .map_err(|_| ApiError::BadRequest("issuer id is not a number"))?;
    app.engine
        .store()
        .set_issuer_enabled(key_id, enabled)
        .await
        .map_err(pvlt_core::VaultError::from)?;
    app.reload_access().await?;
    tracing::info!(admin, key_id, enabled, "issuer changed");
    admin_audit(
        app,
        admin,
        if enabled {
            "issuer.enable"
        } else {
            "issuer.disable"
        },
        None,
    )
    .await;
    Ok(Json(ShredReply {
        outcome: if enabled { "enabled" } else { "disabled" },
        count: 1,
    }))
}

async fn enable_issuer<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<ShredReply>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    set_issuer(&app, &headers, &id, true).await
}

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
    set_issuer(&app, &headers, &id, false).await
}

/// The longest an approval may live: 15 minutes, or 5 for break-glass.
const MAX_APPROVAL_SECS: i64 = 900;
const MAX_BREAK_GLASS_SECS: i64 = 300;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApprovalBody {
    fact_id: Uuid,
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
}

/// An admin asks to read one fact once. A different admin must approve before it works. With break-glass
/// enabled in the configuration the requester may approve it alone, for at most five minutes; it is logged at
/// warning level every time.
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
    let cap = if b.break_glass {
        MAX_BREAK_GLASS_SECS
    } else {
        MAX_APPROVAL_SECS
    };
    let ttl = b.ttl_secs.unwrap_or(cap);
    if ttl <= 0 || ttl > cap {
        return Err(ApiError::BadRequest("ttl_secs is out of range"));
    }
    let mut random = [0u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| ApiError::Vault(pvlt_core::VaultError::Unavailable("random")))?;
    // A well-formed version-4 UUID.
    let id = uuid::Builder::from_random_bytes(random).into_uuid();
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
        })
        .await
        .map_err(pvlt_core::VaultError::from)?;
    if b.break_glass {
        tracing::warn!(admin, fact_id = %b.fact_id, approval = %id, "BREAK-GLASS read approved by its requester");
        admin_audit(&app, admin, "approval.break_glass", Some(b.fact_id)).await;
    } else {
        tracing::info!(admin, fact_id = %b.fact_id, approval = %id, "read approval requested");
        admin_audit(&app, admin, "approval.request", Some(b.fact_id)).await;
    }
    Ok(Json(ApprovalOut {
        id: rec.id,
        expires_at_unix: rec.expires_at.unix_timestamp(),
        approved: rec.approved_by.is_some(),
        break_glass: rec.break_glass,
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
    let rec = app
        .engine
        .store()
        .approve(&id, admin, OffsetDateTime::now_utc())
        .await
        .map_err(pvlt_core::VaultError::from)?;
    tracing::info!(admin, approval = %id, "read approval granted");
    admin_audit(&app, admin, "approval.approve", Some(rec.fact_id)).await;
    Ok(Json(ApprovalOut {
        id: rec.id,
        expires_at_unix: rec.expires_at.unix_timestamp(),
        approved: true,
        break_glass: rec.break_glass,
    }))
}

// --- The audit log ------------------------------------------------------------------------------------------

/// Writes an `admin` entry for an administrative action. Best effort: an admin action is not refused because the
/// log is down, but the failure is logged.
async fn admin_audit<K, O, A>(app: &App<K, O, A>, admin: &str, action: &str, fact_id: Option<Uuid>)
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    if app.ensure_domain().await.is_err() {
        tracing::warn!(
            admin,
            action,
            "admin action not written to the audit log: no domain yet"
        );
        return;
    }
    if let Err(e) = app
        .engine
        .audit_event(
            &app.domain,
            Kind::Admin,
            &Caller::from(admin),
            action,
            fact_id,
            None,
            None,
        )
        .await
    {
        tracing::warn!(admin, action, error = %e, "admin action not written to the audit log");
    }
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
    let rows = app.engine.audit_query(&app.domain, &filter).await?;
    admin_audit(&app, admin, "audit.query", filter.fact_id).await;
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
