//! The listener: a hand-written accept loop over `tokio-rustls` and `hyper-util` (PLAN.md 3.5).
//!
//! TLS 1.3 only, with the `aws-lc-rs` provider. A plaintext transport exists only in a `dev-insecure` build; in
//! a default build the type has no such variant, so no configuration can ask for one.

use std::future::Future;
use std::io::{self, BufReader};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder;
use hyper_util::service::TowerToHyperService;
use rustls::ServerConfig;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

/// How long a client has to finish the TLS handshake.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// How a listener speaks.
#[derive(Clone)]
pub enum Transport {
    /// TLS 1.3.
    Tls(TlsAcceptor),
    /// No encryption. Development builds only.
    #[cfg(feature = "dev-insecure")]
    Plain,
}

/// Builds a TLS 1.3-only server configuration from PEM files.
pub fn load_tls(cert_path: &Path, key_path: &Path) -> io::Result<TlsAcceptor> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile_certs(&mut BufReader::new(std::fs::File::open(cert_path)?))?;
    if certs.is_empty() {
        return Err(io::Error::other("no certificate in the certificate file"));
    }
    let key = rustls_pemfile_key(&mut BufReader::new(std::fs::File::open(key_path)?))?;
    acceptor(certs, key)
}

/// Builds an acceptor from a certificate chain and key.
pub fn acceptor(
    certs: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
) -> io::Result<TlsAcceptor> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let config = ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(io::Error::other)?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(io::Error::other)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

fn rustls_pemfile_certs(r: &mut dyn io::BufRead) -> io::Result<Vec<CertificateDer<'static>>> {
    use rustls::pki_types::pem::PemObject;
    CertificateDer::pem_reader_iter(r)
        .collect::<Result<Vec<_>, _>>()
        .map_err(io::Error::other)
}

fn rustls_pemfile_key(r: &mut dyn io::BufRead) -> io::Result<PrivateKeyDer<'static>> {
    use rustls::pki_types::pem::PemObject;
    PrivateKeyDer::from_pem_reader(r).map_err(io::Error::other)
}

/// Serves `router` on `listener` until `shutdown` turns true, then stops accepting and returns. Connections
/// already open are left to finish on their own tasks.
pub async fn serve(
    listener: TcpListener,
    transport: Transport,
    router: Router,
    mut shutdown: watch::Receiver<bool>,
) {
    loop {
        let accepted = tokio::select! {
            r = listener.accept() => r,
            _ = shutdown.changed() => return,
        };
        let (stream, _peer) = match accepted {
            Ok(pair) => pair,
            Err(e) => {
                tracing::warn!(error = %e, "accept failed");
                // A burst of failures (out of file descriptors) must not spin.
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let transport = transport.clone();
        let router = router.clone();
        tokio::spawn(async move {
            connection(stream, transport, router).await;
        });
    }
}

async fn connection(stream: TcpStream, transport: Transport, router: Router) {
    let service = TowerToHyperService::new(
        router.map_request(|r: hyper::Request<hyper::body::Incoming>| r.map(axum::body::Body::new)),
    );
    let builder = Builder::new(TokioExecutor::new());
    let served: Result<(), Box<dyn std::error::Error + Send + Sync>> = match transport {
        Transport::Tls(acceptor) => {
            let tls = match tokio::time::timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(tls)) => tls,
                Ok(Err(e)) => {
                    tracing::debug!(error = %e, "tls handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!("tls handshake timed out");
                    return;
                }
            };
            builder
                .serve_connection_with_upgrades(TokioIo::new(tls), service)
                .await
        }
        #[cfg(feature = "dev-insecure")]
        Transport::Plain => {
            builder
                .serve_connection_with_upgrades(TokioIo::new(stream), service)
                .await
        }
    };
    if let Err(e) = served {
        tracing::debug!(error = %e, "connection ended with an error");
    }
}

/// Resolves when the process is asked to stop (Ctrl-C or SIGTERM).
pub async fn stop_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = term.recv() => {}
            }
            return;
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

/// Runs `fut` and, when it finishes, flips the shutdown flag. A convenience for tests and `main`.
pub async fn then_shutdown(fut: impl Future<Output = ()>, tx: watch::Sender<bool>) {
    fut.await;
    let _ = tx.send(true);
}
