//! The listener: TLS 1.3 only, and a plaintext client gets no HTTP answer.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::time::Duration;

use axum::Router;
use axum::routing::get;
use pvlt_server::tls::{Transport, acceptor, serve};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

struct Running {
    addr: std::net::SocketAddr,
    cert_pem: String,
    stop: watch::Sender<bool>,
}

async fn start() -> Running {
    let generated =
        rcgen::generate_simple_self_signed(vec!["localhost".to_owned(), "127.0.0.1".to_owned()])
            .unwrap();
    let cert_pem = generated.cert.pem();
    let der = CertificateDer::from(generated.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(
        generated.signing_key.serialize_der(),
    ));
    let acceptor = acceptor(vec![der], key).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (stop, rx) = watch::channel(false);
    let router = Router::new().route("/healthz", get(|| async { "ok" }));
    tokio::spawn(serve(listener, Transport::Tls(acceptor), router, rx));
    Running {
        addr,
        cert_pem,
        stop,
    }
}

fn client(cert_pem: &str, max: Option<reqwest::tls::Version>) -> reqwest::Client {
    let mut b = reqwest::Client::builder()
        .tls_certs_only([reqwest::Certificate::from_pem(cert_pem.as_bytes()).unwrap()])
        .timeout(Duration::from_secs(10));
    if let Some(v) = max {
        b = b.tls_version_max(v);
    }
    b.build().unwrap()
}

#[tokio::test]
async fn a_tls_13_client_is_served() {
    let s = start().await;
    let res = client(&s.cert_pem, None)
        .get(format!("https://localhost:{}/healthz", s.addr.port()))
        .send()
        .await
        .unwrap();
    assert_eq!(res.status(), 200);
    assert_eq!(res.text().await.unwrap(), "ok");
    let _ = s.stop.send(true);
}

#[tokio::test]
async fn a_tls_12_only_client_cannot_connect() {
    let s = start().await;
    let got = client(&s.cert_pem, Some(reqwest::tls::Version::TLS_1_2))
        .get(format!("https://localhost:{}/healthz", s.addr.port()))
        .send()
        .await;
    assert!(got.is_err(), "a TLS 1.2 client was served");
    let _ = s.stop.send(true);
}

#[tokio::test]
async fn a_client_that_does_not_trust_the_certificate_cannot_connect() {
    let s = start().await;
    let other = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let got = client(&other.cert.pem(), None)
        .get(format!("https://localhost:{}/healthz", s.addr.port()))
        .send()
        .await;
    assert!(got.is_err());
    let _ = s.stop.send(true);
}

#[tokio::test]
async fn plaintext_http_gets_no_answer() {
    let s = start().await;
    let mut tcp = TcpStream::connect(s.addr).await.unwrap();
    tcp.write_all(b"GET /healthz HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        .await
        .unwrap();
    let mut got = Vec::new();
    let _ = tokio::time::timeout(Duration::from_secs(5), tcp.read_to_end(&mut got)).await;
    let text = String::from_utf8_lossy(&got);
    assert!(
        !text.contains("HTTP/1.1 200") && !text.contains("\r\nok"),
        "{text}"
    );
    let _ = s.stop.send(true);
}

#[tokio::test]
async fn stopping_closes_the_listener() {
    let s = start().await;
    s.stop.send(true).unwrap();
    tokio::time::sleep(Duration::from_millis(200)).await;
    let refused = tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(s.addr)).await;
    // The accept loop has returned and dropped the listener, so a new connection is refused.
    assert!(matches!(refused, Ok(Err(_))), "{refused:?}");
}
