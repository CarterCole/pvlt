//! Blobs over HTTP (REQUIREMENTS 3.8): the vault never sees the document and the server never decrypts, unless a
//! caller asks it to.
//!
//! ```text
//! POST /v2/blobs                 → a ticket: the blob id, the key (shown once), the layout, and where to upload
//! (client encrypts, uploads the object straight to the bucket, or PUTs it to /v2/blobs/{id}/object)
//! POST /v2/blobs/{id}/complete   → the vault checks the object's size and header, and the blob becomes readable
//! GET  /v2/blobs/{id}/access     → the disclosure is written, then the key and a download address
//! GET  /v2/blobs/{id}/content    → the same, but the server decrypts and streams the plaintext
//! DELETE /v2/facts/{id}          → shreds a blob like any fact
//! ```
//!
//! Every route needs a request token and is authorized by policy (`create` to make and complete, `read` to open),
//! with the same token limits, rate limits and dual control as facts. The upload and download addresses are
//! presigned bucket URLs when the bucket can make them, and routes through the vault otherwise (a local
//! directory, memory).

use std::sync::Arc;

use axum::Json;
use axum::body::{Body, Bytes};
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::Response;
use axum::routing::{get, post, put};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use futures_util::stream;
use pvlt_core::VaultError;
use pvlt_core::audit::{Action as AuditAction, Auditor};
use pvlt_core::engine::CreateBlob;
use pvlt_core::objects::ObjectStore;
use pvlt_core::store::KeyStore;
use pvlt_format::blob;
use pvlt_policy::policy::Action;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::app::App;
use crate::error::ApiError;
use crate::v2::{Target, authenticate, authorize, parse_id, spend_approval};

/// Extra room above the sealed size for a proxied upload, for nothing but safety against a miscounted limit.
const UPLOAD_SLACK: usize = 4096;
/// How much of the object a proxied download reads at a time.
const DOWNLOAD_STEP: u64 = 1024 * 1024;
/// The longest retention a caller may ask for, in days.
const MAX_RETAIN_DAYS: u32 = 36_500;

/// The routes.
pub fn router<K, O, A>(app: Arc<App<K, O, A>>) -> axum::Router
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    // A proxied upload is a whole object in memory, so its body limit is the largest sealed blob plus slack, not
    // the small default of the JSON routes.
    let upload_limit = usize::try_from(app.max_blob_bytes)
        .unwrap_or(usize::MAX)
        .saturating_add(app.max_blob_bytes.div_ceil(1024) as usize * 17)
        .saturating_add(UPLOAD_SLACK)
        .saturating_add(256 * 1024);
    axum::Router::new()
        .route("/v2/blobs", post(create::<K, O, A>))
        .route("/v2/blobs/{id}/complete", post(complete::<K, O, A>))
        .route("/v2/blobs/{id}/access", get(access::<K, O, A>))
        .route("/v2/blobs/{id}/content", get(content::<K, O, A>))
        .route("/v2/blobs/{id}/object", get(download::<K, O, A>))
        .route(
            "/v2/blobs/{id}/object",
            put(upload::<K, O, A>).layer(DefaultBodyLimit::max(upload_limit)),
        )
        .with_state(app)
}

fn parse<T: serde::de::DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(body).map_err(|_| ApiError::BadRequest("malformed request body"))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewBlobBody {
    #[serde(rename = "type")]
    fact_type: String,
    scope: String,
    #[serde(default)]
    subject: Option<String>,
    /// The plaintext length in bytes.
    size: u64,
    #[serde(default)]
    chunk_size: Option<u32>,
    #[serde(default)]
    retain_days: Option<u32>,
}

#[derive(Serialize)]
struct Location {
    method: &'static str,
    /// An absolute URL when the bucket presigned it, or a path on this server when it did not.
    url: String,
    /// `bucket` or `vault`.
    via: &'static str,
    expires_in: u64,
}

#[derive(Serialize)]
struct Ticket {
    id: Uuid,
    suite: u16,
    chunk_size: u32,
    domain_id: String,
    object_id: String,
    dek_generation: u32,
    /// The data key, base64. Shown once.
    dek: String,
    /// The plaintext length that was declared.
    size: u64,
    /// The exact size of the object the client must upload.
    sealed_size: u64,
    upload: Location,
}

fn path_of(key: &pvlt_core::objects::ObjectKey) -> String {
    key.path()
}

/// Makes an address for the bucket object, presigned if the bucket can, or this server's own route if not.
async fn address<K, O, A>(
    app: &App<K, O, A>,
    key: &pvlt_core::objects::ObjectKey,
    id: Uuid,
    upload: bool,
) -> Result<Location, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let ttl = app.presign_ttl;
    let signed = if upload {
        app.engine.objects().presign_put(&path_of(key), ttl).await
    } else {
        app.engine.objects().presign_get(&path_of(key), ttl).await
    }
    .map_err(|_| ApiError::Vault(VaultError::Unavailable("object store")))?;
    Ok(match signed {
        Some(url) => Location {
            method: if upload { "PUT" } else { "GET" },
            url,
            via: "bucket",
            expires_in: ttl.as_secs(),
        },
        None => Location {
            method: if upload { "PUT" } else { "GET" },
            url: format!("/v2/blobs/{id}/object"),
            via: "vault",
            expires_in: ttl.as_secs(),
        },
    })
}

async fn create<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<Json<Ticket>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let authn = authenticate(&app, &headers).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let caller = authn.caller(&principal, &roles);
    let b: NewBlobBody = parse(&body)?;
    if b.retain_days.is_some_and(|d| d == 0 || d > MAX_RETAIN_DAYS) {
        return Err(ApiError::BadRequest("retain_days is out of range"));
    }
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
    let ticket = app
        .engine
        .create_blob(
            caller,
            &app.domain,
            &CreateBlob {
                subject: b.subject.as_deref(),
                scope: &b.scope,
                fact_type: &b.fact_type,
                len: b.size,
                chunk_size: b.chunk_size.unwrap_or(0),
                expires_at: b
                    .retain_days
                    .map(|d| OffsetDateTime::now_utc() + time::Duration::days(i64::from(d))),
            },
        )
        .await?;
    let key = pvlt_core::objects::ObjectKey {
        domain_id: ticket.domain_id,
        object_id: ticket.object_id,
    };
    let sealed_size = blob::sealed_len(b.size, ticket.chunk_size)
        .ok_or(ApiError::BadRequest("bad size or chunk size"))?;
    let upload = address(&app, &key, ticket.blob_id, true).await?;
    Ok(Json(Ticket {
        id: ticket.blob_id,
        suite: ticket.suite.id(),
        chunk_size: ticket.chunk_size,
        domain_id: hex::encode(ticket.domain_id),
        object_id: hex::encode(ticket.object_id),
        dek_generation: ticket.dek_generation,
        dek: STANDARD.encode(ticket.dek.as_slice()),
        size: b.size,
        sealed_size,
        upload,
    }))
}

/// Authorizes an operation on an existing blob and returns what is needed to carry it out.
async fn gate<K, O, A>(
    app: &App<K, O, A>,
    headers: &HeaderMap,
    id: &str,
    action: Action,
    audit_action: AuditAction,
) -> Result<(crate::v2::Authn, Uuid, pvlt_policy::policy::Allowed), ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let authn = authenticate(app, headers).await?;
    let id = parse_id(id)?;
    let meta = app.engine.fact_meta(&app.domain, &id).await?;
    let allowed = authorize(
        app,
        &authn,
        action,
        audit_action,
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
    Ok((authn, id, allowed))
}

/// The proxied upload, for a bucket that cannot presign. Needs the same `create` authorization as the blob.
async fn upload<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
    body: Bytes,
) -> Result<StatusCode, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let (_authn, id, _) = gate(&app, &headers, &id, Action::Create, AuditAction::Create).await?;
    let (key, size) = app.engine.blob_upload_target(&app.domain, &id).await?;
    if u64::try_from(body.len()).ok() != Some(size) {
        return Err(ApiError::Vault(VaultError::Conflict(
            "the object is not the size that was declared",
        )));
    }
    app.engine
        .objects()
        .put(&key, body.to_vec())
        .await
        .map_err(|_| ApiError::Vault(VaultError::Unavailable("object store")))?;
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Serialize)]
struct Done {
    id: Uuid,
    status: &'static str,
}

async fn complete<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Done>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let (authn, id, _) = gate(&app, &headers, &id, Action::Create, AuditAction::Create).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    app.engine
        .complete_blob(authn.caller(&principal, &roles), &app.domain, &id)
        .await?;
    Ok(Json(Done {
        id,
        status: "complete",
    }))
}

#[derive(Serialize)]
struct Access {
    id: Uuid,
    #[serde(rename = "type")]
    fact_type: String,
    suite: u16,
    chunk_size: u32,
    domain_id: String,
    object_id: String,
    dek_generation: u32,
    /// The data key, base64. Its release is on the audit log before this response is made.
    dek: String,
    size: u64,
    download: Location,
}

async fn access<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Json<Access>, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let (authn, id, allowed) = gate(&app, &headers, &id, Action::Read, AuditAction::Read).await?;
    spend_approval(&app, &authn, &allowed, id).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let a = app
        .engine
        .open_blob(authn.caller(&principal, &roles), &app.domain, &id)
        .await?;
    let key = pvlt_core::objects::ObjectKey {
        domain_id: a.domain_id,
        object_id: a.object_id,
    };
    let download = address(&app, &key, id, false).await?;
    Ok(Json(Access {
        id,
        fact_type: a.fact_type.clone(),
        suite: pvlt_format::Suite::Aes256Gcm.id(),
        chunk_size: a.chunk_size,
        domain_id: hex::encode(a.domain_id),
        object_id: hex::encode(a.object_id),
        dek_generation: a.dek_generation,
        dek: STANDARD.encode(a.dek.as_slice()),
        size: a.len,
        download,
    }))
}

/// The ciphertext through the vault, for a bucket that cannot presign. It is not secret on its own, but it
/// needs the same `read` authorization as the key.
async fn download<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let (_authn, id, _) = gate(&app, &headers, &id, Action::Read, AuditAction::Read).await?;
    let (key, size) = app.engine.blob_download_target(&app.domain, &id).await?;
    let path = key.path();
    let body = stream::unfold((app, path, 0u64), move |(app, path, pos)| async move {
        if pos >= size {
            return None;
        }
        match app
            .engine
            .objects()
            .get_range(&path, pos, DOWNLOAD_STEP)
            .await
        {
            Ok(Some(bytes)) if !bytes.is_empty() => {
                let next = pos + u64::try_from(bytes.len()).unwrap_or(u64::MAX);
                Some((
                    Ok::<_, std::io::Error>(Bytes::from(bytes)),
                    (app, path, next),
                ))
            }
            _ => Some((
                Err(std::io::Error::other("object read failed")),
                (app, path, size),
            )),
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, size)
        .body(Body::from_stream(body))
        .map_err(|_| ApiError::Vault(VaultError::Unavailable("response")))
}

/// The server decrypts and streams the plaintext, for a caller that cannot decrypt (a backend that needs the
/// document). The disclosure is written first. If a chunk fails to verify the stream ends in an error and the
/// caller must discard what it received.
async fn content<K, O, A>(
    State(app): State<Arc<App<K, O, A>>>,
    headers: HeaderMap,
    Path(id): Path<String>,
) -> Result<Response, ApiError>
where
    K: KeyStore + 'static,
    O: ObjectStore + 'static,
    A: Auditor + 'static,
{
    let (authn, id, allowed) = gate(&app, &headers, &id, Action::Read, AuditAction::Read).await?;
    spend_approval(&app, &authn, &allowed, id).await?;
    let principal = authn.principal();
    let roles = authn.accepted_roles();
    let access = app
        .engine
        .open_blob(authn.caller(&principal, &roles), &app.domain, &id)
        .await?;
    let stream_state = app.engine.blob_stream(&access).await?;
    let len = access.len;
    // The key now lives only inside the stream state. Drop the access record (and its copy) before streaming.
    drop(access);
    let body = stream::unfold(Some((app, stream_state)), |state| async move {
        let (app, mut s) = state?;
        match app.engine.next_blob_chunk(&mut s).await {
            Ok(Some(chunk)) => Some((
                Ok::<_, std::io::Error>(Bytes::from(chunk.to_vec())),
                Some((app, s)),
            )),
            Ok(None) => None,
            // Ends the response in an error: a client sees a broken transfer, never a normal end.
            Err(_) => Some((
                Err(std::io::Error::other("the blob failed verification")),
                None,
            )),
        }
    });
    Response::builder()
        .header(header::CONTENT_TYPE, "application/octet-stream")
        .header(header::CONTENT_LENGTH, len)
        .body(Body::from_stream(body))
        .map_err(|_| ApiError::Vault(VaultError::Unavailable("response")))
}
