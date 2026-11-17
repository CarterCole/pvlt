//! The native API, `/v2`, driven by delegated request tokens (REQUIREMENTS 3.7, 3.10).
//!
//! A trusted service mints a short-lived [Biscuit](pvlt_tokens) token per operation and sends it as
//! `Authorization: Bearer <token>`. For each request the vault
//!
//! 1. verifies the token against the issuer registry (signature, expiry, a lifetime no longer than the
//!    configured maximum);
//! 2. keeps only the roles the issuer is registered to assert;
//! 3. applies the token's own limits (an action list, one fact, one scope, one subject);
//! 4. asks the policy, which denies by default;
//! 5. applies the role's rate limit;
//! 6. for a read of a *restricted* fact type, spends a dual-control approval.
//!
//! Every refusal is reported to the auditor with a stable code, and a caller sees only a status and a code.
//! **Reads are not yet durably audited** (that is M4): the auditor in this build writes log lines.
//!
//! A caller who holds any valid token can tell whether a fact id exists (404 versus the policy's answer): fact
//! ids are unguessable UUIDs and the token issuer is trusted, so this is accepted.

use std::sync::Arc;
use std::time::Instant;

use axum::extract::{Path, State};
use axum::http::HeaderMap;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use pvlt_core::VaultError;
use pvlt_core::audit::{Action as AuditAction, Auditor};
use pvlt_core::audit_log::{Caller, Kind};
use pvlt_core::engine::CreateFact;
use pvlt_core::ledger::Reason;
use pvlt_core::limits::Verdict;
use pvlt_core::objects::ObjectStore;
use pvlt_core::policy::{Action, Allowed, Context, Decision, Request};
use pvlt_core::store::{FactId, KeyStore, State as FactState};
use pvlt_tokens::Claims;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::{Access, App};
use crate::error::ApiError;

/// The longest retention a caller may ask for, in days (100 years).
const MAX_RETAIN_DAYS: u32 = 36_500;

/// The routes.
pub fn router<K, O, A>(app: Arc<App<K, O, A>>) -> Router
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    Router::new()
        .route("/v2/facts", post(create::<K, O, A>))
        .route("/v2/facts/batch", post(create_batch::<K, O, A>))
        .route(
            "/v2/facts/{id}",
            get(read::<K, O, A>).merge(delete(shred_fact::<K, O, A>)),
        )
        .route("/v2/shred/subject", post(shred_subject::<K, O, A>))
        .route("/v2/shred/scope", post(shred_scope::<K, O, A>))
        .with_state(app)
}

// --- Authentication and authorization ---------------------------------------------------------------------

/// A verified token and what the registry says about its issuer.
pub(crate) struct Authn {
    pub(crate) claims: Claims,
    issuer: String,
    pub(crate) issuer_roles: Vec<String>,
    pub(crate) access: Arc<Access>,
}

impl Authn {
    /// Who this is, for audit entries and rate limits. Never contains a token.
    pub(crate) fn principal(&self) -> String {
        format!(
            "{}/{}",
            self.issuer,
            self.claims.caller.as_deref().unwrap_or("service")
        )
    }

    /// The roles the vault would accept from this token: those it asserts that its issuer may assert.
    pub(crate) fn accepted_roles(&self) -> Vec<String> {
        self.claims
            .roles
            .iter()
            .filter(|r| self.issuer_roles.contains(r))
            .cloned()
            .collect()
    }

    /// The audit context for this request.
    pub(crate) fn caller<'a>(&'a self, principal: &'a str, roles: &'a [String]) -> Caller<'a> {
        Caller {
            principal,
            caller: self.claims.caller.as_deref(),
            roles,
            purpose: self.claims.purpose.as_deref(),
            reason: self.claims.reason.as_deref(),
            request_id: Some(self.claims.request_id.as_str()),
            policy_hash: Some(self.access.policy_hash),
        }
    }
}

/// Reports a refusal to the log lines and, durably, to the audit log (best effort: a refusal is a refusal even
/// if it cannot be written down), and returns the error to send.
pub(crate) async fn refuse<K: KeyStore, O: ObjectStore, A: Auditor>(
    app: &App<K, O, A>,
    authn: &Authn,
    audit_action: AuditAction,
    fact_id: Option<FactId>,
    code: &'static str,
) -> ApiError {
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    app.engine.report(&principal, audit_action, fact_id, code);
    let _ = app
        .engine
        .audit_event(
            &app.domain,
            Kind::Deny,
            &authn.caller(&principal, &roles),
            audit_action.name(),
            fact_id,
            None,
            Some(code),
        )
        .await;
    ApiError::Forbidden(code)
}

/// How many refused tokens an hour are written to the audit log. Past this they are counted in the log lines
/// only, so a flood of junk cannot grow the audit log without bound.
const UNAUTHENTICATED_AUDITED_PER_HOUR: u32 = 600;

pub(crate) async fn authenticate<K: KeyStore, O: ObjectStore, A: Auditor>(
    app: &App<K, O, A>,
    headers: &HeaderMap,
) -> Result<Authn, ApiError> {
    let token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(ApiError::Unauthorized)?;
    let access = app.access();
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let claims = match pvlt_tokens::verify(token, access.as_ref(), now, app.max_token_ttl) {
        Ok(c) => c,
        Err(e) => {
            // Why a token failed is for the operator, not the caller.
            app.engine
                .report("unauthenticated", AuditAction::Read, None, "bad_token");
            tracing::debug!(reason = %e, "token refused");
            let audited = app.limiter.check(
                "unauthenticated",
                Action::Read,
                UNAUTHENTICATED_AUDITED_PER_HOUR,
                Instant::now(),
            ) == Verdict::Allowed;
            if audited && app.ensure_domain().await.is_ok() {
                let _ = app
                    .engine
                    .audit_event(
                        &app.domain,
                        Kind::Deny,
                        &Caller::from("unauthenticated"),
                        "authenticate",
                        None,
                        None,
                        Some("bad_token"),
                    )
                    .await;
            }
            return Err(ApiError::Unauthorized);
        }
    };
    let issuer = access
        .issuers
        .get(&claims.issuer_key_id)
        .ok_or(ApiError::Unauthorized)?;
    Ok(Authn {
        issuer: issuer.name.clone(),
        issuer_roles: issuer.roles.clone(),
        claims,
        access: Arc::clone(&access),
    })
}

/// What a request touches, for the token's own limits.
pub(crate) struct Target<'a> {
    pub(crate) fact_id: Option<&'a FactId>,
    pub(crate) scope_hmac: Option<[u8; 32]>,
    pub(crate) subject_hmac: Option<[u8; 32]>,
    pub(crate) scope: Option<&'a str>,
    pub(crate) subject: Option<&'a str>,
}

/// Applies the limits a token carries: the actions it is for, and the one fact, scope or subject it may touch.
async fn within_token<K: KeyStore, O: ObjectStore, A: Auditor>(
    app: &App<K, O, A>,
    c: &Claims,
    action: Action,
    t: &Target<'_>,
) -> Result<(), &'static str> {
    if !c.actions.is_empty() && !c.actions.iter().any(|a| a == action.name()) {
        return Err("token_action");
    }
    if let Some(only) = c.resource_fact
        && t.fact_id != Some(&only)
    {
        return Err("token_resource");
    }
    if let Some(only) = &c.resource_scope {
        let same = match (t.scope, t.scope_hmac) {
            (Some(s), _) => s == only,
            (None, Some(h)) => app.engine.scope_hmac(&app.domain, only).await.ok() == Some(h),
            (None, None) => false,
        };
        if !same {
            return Err("token_resource");
        }
    }
    if let Some(only) = &c.resource_subject {
        let same = match (t.subject, t.subject_hmac) {
            (Some(s), _) => s == only,
            (None, Some(h)) => app.engine.subject_hmac(&app.domain, only).await.ok() == Some(h),
            (None, None) => false,
        };
        if !same {
            return Err("token_resource");
        }
    }
    Ok(())
}

/// Checks token limits, policy and rate limit, and reports a refusal to the auditor.
pub(crate) async fn authorize<K: KeyStore, O: ObjectStore, A: Auditor>(
    app: &App<K, O, A>,
    authn: &Authn,
    action: Action,
    audit_action: AuditAction,
    fact_type: Option<&str>,
    target: &Target<'_>,
    fact_id: Option<FactId>,
) -> Result<Allowed, ApiError> {
    let principal = authn.principal();
    if let Err(code) = within_token(app, &authn.claims, action, target).await {
        return Err(refuse(app, authn, audit_action, fact_id, code).await);
    }
    let subject_matches = match (&authn.claims.subject, target.subject_hmac, target.subject) {
        (Some(claimed), Some(h), _) => {
            app.engine.subject_hmac(&app.domain, claimed).await.ok() == Some(h)
        }
        (Some(claimed), None, Some(s)) => claimed == s,
        _ => false,
    };
    let ctx = Context {
        roles: &authn.claims.roles,
        issuer_roles: &authn.issuer_roles,
        caller: authn.claims.caller.as_deref(),
        subject: authn.claims.subject.as_deref(),
        purpose: authn.claims.purpose.as_deref(),
        reason: authn.claims.reason.as_deref(),
        grants: &authn.claims.grants,
    };
    let decision = authn.access.policy.decide(
        &ctx,
        &Request {
            action,
            fact_type,
            subject_matches,
        },
    );
    let allowed = match decision {
        Decision::Allow(a) => a,
        Decision::Deny(d) => return Err(refuse(app, authn, audit_action, fact_id, d.code()).await),
    };
    if let Err(e) = rate_limit(app, &allowed, &principal, action) {
        // A rate-limited caller is refused and the refusal is recorded, like any other.
        let _ = refuse(app, authn, audit_action, fact_id, "rate_limited").await;
        return Err(e);
    }
    Ok(allowed)
}

/// Applies the role's limit for an action to this caller.
pub fn rate_limit<K: KeyStore, O: ObjectStore, A: Auditor>(
    app: &App<K, O, A>,
    allowed: &Allowed,
    caller: &str,
    action: Action,
) -> Result<(), ApiError> {
    let Some(limit) = allowed.limits.for_action(action) else {
        return Ok(());
    };
    // Counted per role as well as per caller, so one role cannot be multiplied by minting many caller names.
    let key = format!("{}|{}", allowed.role, caller);
    match app.limiter.check(&key, action, limit, Instant::now()) {
        Verdict::Allowed => Ok(()),
        Verdict::Limited { retry_after } => {
            Err(ApiError::RateLimited(retry_after.as_secs().max(1)))
        }
    }
}

// --- Request bodies ----------------------------------------------------------------------------------------

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    // By hand: serde's message can quote the value it choked on.
    serde_json::from_slice(body).map_err(|_| ApiError::BadRequest("malformed request body"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewFactBody {
    #[serde(rename = "type")]
    fact_type: String,
    scope: String,
    #[serde(default)]
    subject: Option<String>,
    #[serde(default)]
    value: Option<String>,
    #[serde(default)]
    value_b64: Option<String>,
    #[serde(default)]
    retain_days: Option<u32>,
}

struct Decoded {
    value: zeroize::Zeroizing<Vec<u8>>,
}

impl NewFactBody {
    fn decode(&self) -> Result<Decoded, ApiError> {
        let value = match (&self.value, &self.value_b64) {
            (Some(v), None) => zeroize::Zeroizing::new(v.as_bytes().to_vec()),
            (None, Some(b)) => {
                let mut out = zeroize::Zeroizing::new(Vec::new());
                STANDARD
                    .decode_vec(b.as_bytes(), &mut out)
                    .map_err(|_| ApiError::BadRequest("value_b64 is not base64"))?;
                out
            }
            _ => {
                return Err(ApiError::BadRequest(
                    "give exactly one of value and value_b64",
                ));
            }
        };
        if self
            .retain_days
            .is_some_and(|d| d == 0 || d > MAX_RETAIN_DAYS)
        {
            return Err(ApiError::BadRequest("retain_days is out of range"));
        }
        Ok(Decoded { value })
    }

    fn expires_at(&self) -> Option<OffsetDateTime> {
        self.retain_days
            .map(|d| OffsetDateTime::now_utc() + time::Duration::days(i64::from(d)))
    }
}

#[derive(Serialize)]
struct Created {
    id: Uuid,
}

#[derive(Serialize)]
struct CreatedMany {
    ids: Vec<Uuid>,
}

// --- Handlers ---------------------------------------------------------------------------------------------

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
    let authn = authenticate(&app, &headers).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let caller = authn.caller(&principal, &roles);
    let b: NewFactBody = parse(&body)?;
    let decoded = b.decode()?;
    authorize(
        &app,
        &authn,
        Action::Create,
        AuditAction::Create,
        Some(&b.fact_type),
        &Target {
            fact_id: None,
            scope_hmac: None,
            subject_hmac: None,
            scope: Some(&b.scope),
            subject: b.subject.as_deref(),
        },
        None,
    )
    .await?;
    app.ensure_domain().await?;
    let id = app
        .engine
        .create_fact(
            caller,
            &app.domain,
            &CreateFact {
                fact_id: None,
                subject: b.subject.as_deref(),
                scope: &b.scope,
                fact_type: &b.fact_type,
                value: &decoded.value,
                expires_at: b.expires_at(),
            },
        )
        .await?;
    Ok(Json(Created { id }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BatchBody {
    facts: Vec<NewFactBody>,
}

async fn create_batch<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<CreatedMany>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let authn = authenticate(&app, &headers).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let caller = authn.caller(&principal, &roles);
    let b: BatchBody = parse(&body)?;
    let mut decoded = Vec::with_capacity(b.facts.len());
    for f in &b.facts {
        decoded.push(f.decode()?);
    }
    // Every fact is authorized, and counted against the rate limit, before any is created.
    for f in &b.facts {
        authorize(
            &app,
            &authn,
            Action::Create,
            AuditAction::Create,
            Some(&f.fact_type),
            &Target {
                fact_id: None,
                scope_hmac: None,
                subject_hmac: None,
                scope: Some(&f.scope),
                subject: f.subject.as_deref(),
            },
            None,
        )
        .await?;
    }
    app.ensure_domain().await?;
    let requests: Vec<CreateFact<'_>> = b
        .facts
        .iter()
        .zip(&decoded)
        .map(|(f, d)| CreateFact {
            fact_id: None,
            subject: f.subject.as_deref(),
            scope: &f.scope,
            fact_type: &f.fact_type,
            value: &d.value,
            expires_at: f.expires_at(),
        })
        .collect();
    let ids = app
        .engine
        .create_facts(caller, &app.domain, &requests)
        .await?;
    Ok(Json(CreatedMany { ids }))
}

/// For a read of a restricted fact type: dual control. A second admin approved this read, once, and the token
/// names the approval. The approval is spent before the value is opened, so a read that then fails cannot be
/// retried on the same approval.
pub(crate) async fn spend_approval<K: KeyStore, O: ObjectStore, A: Auditor>(
    app: &App<K, O, A>,
    authn: &Authn,
    allowed: &Allowed,
    id: FactId,
) -> Result<(), ApiError> {
    if !allowed.restricted {
        return Ok(());
    }
    let Some(approval) = authn
        .claims
        .approval
        .as_deref()
        .and_then(|a| Uuid::parse_str(a).ok())
    else {
        return Err(refuse(app, authn, AuditAction::Read, Some(id), "approval_required").await);
    };
    if app
        .engine
        .consume_approval(&app.domain, &approval, &id)
        .await
        .is_err()
    {
        return Err(refuse(app, authn, AuditAction::Read, Some(id), "approval_invalid").await);
    }
    Ok(())
}

#[derive(Serialize)]
struct FactOut {
    id: Uuid,
    #[serde(rename = "type")]
    fact_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_b64: Option<String>,
}

pub(crate) fn parse_id(text: &str) -> Result<Uuid, ApiError> {
    Uuid::parse_str(text).map_err(|_| ApiError::BadRequest("id is not a UUID"))
}

async fn read<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<FactOut>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let authn = authenticate(&app, &headers).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let caller = authn.caller(&principal, &roles);
    let id = parse_id(&id)?;
    let meta = app.engine.fact_meta(&app.domain, &id).await?;
    let allowed = authorize(
        &app,
        &authn,
        Action::Read,
        AuditAction::Read,
        Some(&meta.fact_type),
        &Target {
            fact_id: Some(&id),
            scope_hmac: Some(meta.scope_hmac),
            subject_hmac: Some(meta.subject_hmac),
            scope: None,
            subject: None,
        },
        Some(id),
    )
    .await?;
    if meta.state == FactState::Shredded {
        return Err(ApiError::Vault(VaultError::Shredded));
    }
    spend_approval(&app, &authn, &allowed, id).await?;
    let fact = app.engine.read_fact(caller, &app.domain, &id).await?;
    let (value, value_b64) = match String::from_utf8(fact.value.to_vec()) {
        Ok(text) => (Some(text), None),
        Err(_) => (None, Some(STANDARD.encode(fact.value.as_slice()))),
    };
    Ok(Json(FactOut {
        id: fact.fact_id,
        fact_type: fact.fact_type,
        value,
        value_b64,
    }))
}

#[derive(Serialize)]
struct Shredded {
    outcome: &'static str,
    count: usize,
}

async fn shred_fact<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Shredded>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    use pvlt_core::store::ShredFact as S;
    let authn = authenticate(&app, &headers).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let caller = authn.caller(&principal, &roles);
    let id = parse_id(&id)?;
    let meta = app.engine.fact_meta(&app.domain, &id).await?;
    authorize(
        &app,
        &authn,
        Action::Shred,
        AuditAction::ShredFact,
        Some(&meta.fact_type),
        &Target {
            fact_id: Some(&id),
            scope_hmac: Some(meta.scope_hmac),
            subject_hmac: Some(meta.subject_hmac),
            scope: None,
            subject: None,
        },
        Some(id),
    )
    .await?;
    let outcome = app
        .engine
        .shred_fact(caller, &app.domain, &id, Reason::SubjectRequest)
        .await?;
    Ok(Json(Shredded {
        outcome: match outcome {
            S::Shredded { .. } => "shredded",
            S::AlreadyShredded => "already_shredded",
            S::NotFound => "not_found",
        },
        count: usize::from(matches!(outcome, S::Shredded { .. })),
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShredSubjectBody {
    subject: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ShredScopeBody {
    scope: String,
    #[serde(default)]
    reason: Option<String>,
}

fn reason_of(code: Option<&str>) -> Result<Reason, ApiError> {
    Ok(match code.unwrap_or("subject_request") {
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

async fn shred_subject<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Shredded>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    use pvlt_core::store::ShredSubject as S;
    let authn = authenticate(&app, &headers).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let caller = authn.caller(&principal, &roles);
    let b: ShredSubjectBody = parse(&body)?;
    let reason = reason_of(b.reason.as_deref())?;
    // A whole subject has no single fact type, so only a rule that covers every type (`*`) can allow it.
    authorize(
        &app,
        &authn,
        Action::Shred,
        AuditAction::ShredSubject,
        None,
        &Target {
            fact_id: None,
            scope_hmac: None,
            subject_hmac: None,
            scope: None,
            subject: Some(&b.subject),
        },
        None,
    )
    .await?;
    app.ensure_domain().await?;
    let outcome = app
        .engine
        .shred_subject(caller, &app.domain, &b.subject, reason)
        .await?;
    Ok(Json(Shredded {
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
) -> Result<Json<Shredded>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let authn = authenticate(&app, &headers).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let caller = authn.caller(&principal, &roles);
    let b: ShredScopeBody = parse(&body)?;
    let reason = reason_of(b.reason.as_deref())?;
    authorize(
        &app,
        &authn,
        Action::Shred,
        AuditAction::ShredScope,
        None,
        &Target {
            fact_id: None,
            scope_hmac: None,
            subject_hmac: None,
            scope: Some(&b.scope),
            subject: None,
        },
        None,
    )
    .await?;
    app.ensure_domain().await?;
    let count = app
        .engine
        .shred_scope(caller, &app.domain, &b.scope, reason)
        .await?;
    Ok(Json(Shredded {
        outcome: if count > 0 {
            "shredded"
        } else {
            "nothing_in_scope"
        },
        count,
    }))
}
