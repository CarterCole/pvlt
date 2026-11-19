//! Responses that carry a value or a key.
//!
//! An ordinary `Json` response is serialized into a buffer that is freed, not wiped, so the value would stay in
//! freed heap memory until it is reused. These helpers serialize into a buffer that is zeroed when the HTTP
//! stack drops it, and stream plaintext chunks the same way. What happens after the bytes leave this process's
//! buffers (the TLS library's own record buffers, the kernel) is out of reach, so this narrows the window; it
//! does not close it.

use axum::body::{Body, Bytes};
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use zeroize::Zeroizing;

/// A buffer that is wiped when the last `Bytes` that points into it is dropped.
struct Wiped(Zeroizing<Vec<u8>>);

impl AsRef<[u8]> for Wiped {
    fn as_ref(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// Bytes backed by a buffer that is wiped when dropped. Takes ownership, so nothing is copied.
pub fn wiped_bytes(buf: Zeroizing<Vec<u8>>) -> Bytes {
    Bytes::from_owner(Wiped(buf))
}

/// A `200 OK` JSON response whose body buffer is wiped when the response has been sent.
pub fn json<T: Serialize>(value: &T) -> Response {
    let mut buf = Zeroizing::new(Vec::with_capacity(256));
    if serde_json::to_writer(&mut *buf, value).is_err() {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let mut response = Response::new(Body::from(wiped_bytes(buf)));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    // A value must not sit in a shared cache or the browser's.
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]

    use super::*;
    use http_body_util::BodyExt;

    #[tokio::test]
    async fn a_secret_response_is_json_and_not_cached() {
        let r = json(&serde_json::json!({"value": "x"}));
        assert_eq!(r.headers()[header::CONTENT_TYPE], "application/json");
        assert_eq!(r.headers()[header::CACHE_CONTROL], "no-store");
        let body = r.into_body().collect().await.unwrap().to_bytes();
        assert_eq!(&body[..], br#"{"value":"x"}"#);
    }
}
