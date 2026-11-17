//! One place that turns an engine error into an HTTP response (PLAN.md 3.8).
//!
//! The body is `{"error": "<code>", "message": "<static text>"}`. A message is always a fixed string chosen in
//! the code, never text from a driver or from the request, so an error cannot echo a value, a key or a subject.

use axum::Json;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use pvlt_core::VaultError;
use serde_json::json;

/// Why a request failed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApiError {
    /// The engine refused or failed.
    Vault(VaultError),
    /// No token, or a wrong one.
    Unauthorized,
    /// The request is malformed. The string is a fixed message.
    BadRequest(&'static str),
    /// Authenticated, but not allowed. The string is a stable code (`not_allowed`, `approval_required`, ...), safe
    /// to return: it says which kind of refusal, not why in detail.
    Forbidden(&'static str),
    /// Over a rate limit. Try again after this many seconds.
    RateLimited(u64),
}

impl From<VaultError> for ApiError {
    fn from(e: VaultError) -> Self {
        ApiError::Vault(e)
    }
}

impl ApiError {
    /// The status, the stable code and the message.
    pub fn parts(&self) -> (StatusCode, &'static str, &'static str) {
        match self {
            ApiError::Unauthorized => (StatusCode::UNAUTHORIZED, "denied", "credentials required"),
            ApiError::BadRequest(m) => (StatusCode::BAD_REQUEST, "invalid", m),
            ApiError::Forbidden(code) => (StatusCode::FORBIDDEN, "denied", code),
            ApiError::RateLimited(_) => (
                StatusCode::TOO_MANY_REQUESTS,
                "rate_limited",
                "too many requests",
            ),
            ApiError::Vault(e) => match e {
                VaultError::Sealed => {
                    (StatusCode::SERVICE_UNAVAILABLE, "sealed", "vault is sealed")
                }
                VaultError::NotFound => (StatusCode::NOT_FOUND, "not_found", "not found"),
                // 410: gone for good. A caller must not retry this.
                VaultError::Shredded => (StatusCode::GONE, "shredded", "destroyed on purpose"),
                VaultError::Conflict(m) => (StatusCode::CONFLICT, "conflict", m),
                VaultError::Invalid(m) => (StatusCode::BAD_REQUEST, "invalid", m),
                VaultError::Unavailable(_) => (
                    StatusCode::SERVICE_UNAVAILABLE,
                    "unavailable",
                    "a required service is unavailable",
                ),
                // Wrong key, wrong context or tampering. Not distinguished, and not the caller's fault.
                _ => (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "internal",
                    "internal error",
                ),
            },
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, code, message) = self.parts();
        let mut response =
            (status, Json(json!({ "error": code, "message": message }))).into_response();
        if let ApiError::RateLimited(secs) = self
            && let Ok(v) = axum::http::HeaderValue::from_str(&secs.to_string())
        {
            response
                .headers_mut()
                .insert(axum::http::header::RETRY_AFTER, v);
        }
        response
    }
}
