//! GDPR mode: the data subject's rights of access (art. 15) and portability (art. 20), over HTTP.
//!
//! Erasure (art. 17) needs nothing new: a subject shred destroys the subject key, the ledger makes it survive a
//! restore, and `/v2/shred/subject` lets the subject's own token do it when the policy has a `self` shred rule.
//! What the vault could not do before this mode is say *what it holds* about a person. These routes do, and are
//! only served when `PVLT_GDPR_MODE=true`:
//!
//! | Route | Listener | Gives | Switch |
//! |---|---|---|---|
//! | `POST /v2/subject/facts` | data | the subject's fact list: ids, types, dates, hold, state, **no values** | the mode |
//! | `POST /v2/subject/export` | data | the list plus every value the caller may read, as JSON | `PVLT_GDPR_EXPORT` |
//! | `POST /v2/admin/subject/facts` | admin | the fact list, **no values** | `PVLT_GDPR_ADMIN_INVENTORY` |
//!
//! The subject goes in the body (`{"subject": "user:123"}`), never the path, so it is not in access logs.
//!
//! **Authorization is the policy's.** On the data listener the list needs a `read` rule over every type (`*`),
//! as a subject shred needs a `*` shred rule; the usual one is the data subject's own
//! `{"types": ["*"], "actions": ["read"], "when": ["self"]}`. The export then authorizes each fact as an ordinary
//! read, so per-type rules, purposes and rate limits still apply. A fact the policy will not release is listed
//! as `withheld` with the refusal code; a restricted type is always withheld, because a dual-control approval
//! covers one fact and an export must not spend it. Every value released is a normal, durably audited read.
//!
//! **An admin still cannot read.** The admin inventory lists facts without opening any. There is deliberately no
//! admin export: a value leaves the vault only through a token the policy accepts.
//!
//! Each list is written to the audit log (`inventory`) before it is sent, and the send fails if that write does.

use std::sync::Arc;

use axum::extract::State;
use axum::http::HeaderMap;
use axum::routing::post;
use axum::{Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use pvlt_core::VaultError;
use pvlt_core::audit::{Action as AuditAction, Auditor};
use pvlt_core::audit_log::{Caller, Kind};
use pvlt_core::engine::MAX_SUBJECT_FACTS;
use pvlt_core::objects::ObjectStore;
use pvlt_core::store::{FactKind, KeyStore, State as FactState, SubjectFact};
use pvlt_policy::policy::Action;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::App;
use crate::error::ApiError;
use crate::v2::{Target, authenticate, authorize};

/// The data-listener routes. Empty unless GDPR mode is on.
pub fn data_router<K, O, A>(app: Arc<App<K, O, A>>) -> Router
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let mut r = Router::new();
    if app.gdpr.enabled {
        r = r.route("/v2/subject/facts", post(subject_facts::<K, O, A>));
    }
    if app.gdpr.export_enabled() {
        r = r.route("/v2/subject/export", post(subject_export::<K, O, A>));
    }
    r.with_state(app)
}

/// The admin-listener route. Empty unless GDPR mode and its admin inventory are on.
pub fn admin_router<K, O, A>(app: Arc<App<K, O, A>>) -> Router
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let mut r = Router::new();
    if app.gdpr.admin_inventory_enabled() {
        r = r.route(
            "/v2/admin/subject/facts",
            post(admin_subject_facts::<K, O, A>),
        );
    }
    r.with_state(app)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SubjectBody {
    subject: String,
}

/// One fact in a list or export.
#[derive(Serialize)]
struct Entry {
    id: Uuid,
    #[serde(rename = "type")]
    fact_type: String,
    kind: &'static str,
    /// `active` or `shredded` in a list. An export can also say `exported`, `withheld`, `expired`, or `blob`
    /// (fetch it through the blob routes).
    status: &'static str,
    created_at_unix: i64,
    expires_at_unix: Option<i64>,
    legal_hold: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    shredded_at_unix: Option<i64>,
    /// Why a fact was withheld from an export: the policy's refusal code.
    #[serde(skip_serializing_if = "Option::is_none")]
    withheld: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_b64: Option<String>,
}

impl From<&SubjectFact> for Entry {
    fn from(f: &SubjectFact) -> Self {
        Self {
            id: f.fact_id,
            fact_type: f.fact_type.clone(),
            kind: match f.kind {
                FactKind::Fact => "fact",
                FactKind::Blob => "blob",
            },
            status: match f.state {
                FactState::Active => "active",
                FactState::Shredded => "shredded",
            },
            created_at_unix: f.created_at.unix_timestamp(),
            expires_at_unix: f.expires_at.map(OffsetDateTime::unix_timestamp),
            legal_hold: f.legal_hold,
            shredded_at_unix: f.shredded_at.map(OffsetDateTime::unix_timestamp),
            withheld: None,
            value: None,
            value_b64: None,
        }
    }
}

/// A list or an export: structured, machine-readable JSON (art. 20).
#[derive(Serialize)]
struct Report {
    generated_at_unix: i64,
    /// False if the subject has more than [`MAX_SUBJECT_FACTS`] facts and the list stops there.
    complete: bool,
    facts: Vec<Entry>,
}

fn report(entries: Vec<Entry>, listed: usize) -> Report {
    Report {
        generated_at_unix: OffsetDateTime::now_utc().unix_timestamp(),
        complete: listed < usize::try_from(MAX_SUBJECT_FACTS).unwrap_or(usize::MAX),
        facts: entries,
    }
}

/// Lists a subject's facts after writing the disclosure to the audit log. Fails closed if it cannot be written.
async fn inventory<K, O, A>(
    app: &App<K, O, A>,
    caller: &Caller<'_>,
    action: &str,
    subject: &str,
) -> Result<Vec<SubjectFact>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    app.ensure_domain().await?;
    if app.engine.audit_blocked() {
        return Err(VaultError::Unavailable("the audit log needs attention").into());
    }
    let (hmac, facts) = app.engine.subject_facts(&app.domain, subject).await?;
    app.engine
        .audit_event(
            &app.domain,
            Kind::Inventory,
            caller,
            action,
            None,
            Some(hmac),
            None,
        )
        .await
        .map_err(|_| VaultError::Unavailable("audit log"))?;
    Ok(facts)
}

/// Checks that the token may list this subject: a `read` rule over every type, and the token's own limits.
async fn authorize_list<K, O, A>(
    app: &App<K, O, A>,
    authn: &crate::v2::Authn,
    subject: &str,
) -> Result<(), ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    authorize(
        app,
        authn,
        Action::Read,
        AuditAction::Read,
        None,
        &Target {
            fact_id: None,
            scope_hmac: None,
            subject_hmac: None,
            scope: None,
            subject: Some(subject),
        },
        None,
    )
    .await
    .map(|_| ())
}

/// `POST /v2/subject/facts`: what the vault holds about a subject, without values.
async fn subject_facts<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Report>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let authn = authenticate(&app, &headers).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let b: SubjectBody = crate::admin::parse(&body)?;
    authorize_list(&app, &authn, &b.subject).await?;
    let facts = inventory(
        &app,
        &authn.caller(&principal, &roles),
        "subject.facts",
        &b.subject,
    )
    .await?;
    Ok(Json(report(
        facts.iter().map(Entry::from).collect(),
        facts.len(),
    )))
}

/// `POST /v2/subject/export`: the list, with every value the caller may read.
async fn subject_export<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Report>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let authn = authenticate(&app, &headers).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let caller = authn.caller(&principal, &roles);
    let b: SubjectBody = crate::admin::parse(&body)?;
    authorize_list(&app, &authn, &b.subject).await?;
    let facts = inventory(&app, &caller, "subject.export", &b.subject).await?;
    let subject_hmac = app.engine.subject_hmac(&app.domain, &b.subject).await?;

    let mut out = Vec::with_capacity(facts.len());
    for f in &facts {
        let mut e = Entry::from(f);
        if f.state == FactState::Shredded {
            out.push(e);
            continue;
        }
        if f.kind == FactKind::Blob {
            e.status = "blob";
            out.push(e);
            continue;
        }
        let allowed = authorize(
            &app,
            &authn,
            Action::Read,
            AuditAction::Read,
            Some(&f.fact_type),
            &Target {
                fact_id: Some(&f.fact_id),
                scope_hmac: None,
                subject_hmac: Some(subject_hmac),
                scope: None,
                subject: None,
            },
            Some(f.fact_id),
        )
        .await;
        let allowed = match allowed {
            Ok(a) => a,
            Err(ApiError::Forbidden(code)) => {
                e.status = "withheld";
                e.withheld = Some(code);
                out.push(e);
                continue;
            }
            // A rate limit or an outage stops the whole export: a partial one would read as complete.
            Err(other) => return Err(other),
        };
        if allowed.restricted {
            e.status = "withheld";
            e.withheld = Some("approval_required");
            out.push(e);
            continue;
        }
        match app.engine.read_fact(caller, &app.domain, &f.fact_id).await {
            Ok(v) => {
                match String::from_utf8(v.value.to_vec()) {
                    Ok(text) => e.value = Some(text),
                    Err(_) => e.value_b64 = Some(STANDARD.encode(v.value.as_slice())),
                }
                e.status = "exported";
            }
            Err(VaultError::NotFound) => e.status = "expired",
            Err(VaultError::Shredded) => e.status = "shredded",
            Err(other) => return Err(other.into()),
        }
        out.push(e);
    }
    Ok(Json(report(out, facts.len())))
}

/// `POST /v2/admin/subject/facts`: the fact list for an admin answering an access request. No values.
async fn admin_subject_facts<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<Report>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let admin = crate::admin::require_admin(&app, &headers)?;
    let b: SubjectBody = crate::admin::parse(&body)?;
    let facts = inventory(
        &app,
        &Caller::from(admin),
        "admin.subject.facts",
        &b.subject,
    )
    .await?;
    tracing::info!(admin, count = facts.len(), "subject inventory listed");
    Ok(Json(report(
        facts.iter().map(Entry::from).collect(),
        facts.len(),
    )))
}
