//! The pvlt server: the HTTP surface over the engine (PLAN.md 3.5, milestone M1).
//!
//! * [`config`]: settings from the environment.
//! * [`app`]: the state every handler shares, and the unseal progress.
//! * [`compat`]: the OPV-compatible `/api/v1/facts` routes OPV clients call.
//! * [`v2`]: the native API, driven by delegated Biscuit tokens and the policy.
//! * [`admin`]: sealing and unsealing, on a separate listener.
//! * [`gdpr`]: GDPR mode, the data-subject access and export routes (off unless `PVLT_GDPR_MODE` is set).
//! * [`pg`]: the Postgres key store and its migrations.
//! * [`bucket`]: the S3-compatible, directory or in-memory object store.
//! * [`tokens`]: Biscuit token verification and minting.
//! * [`tls`]: the listener. TLS 1.3 only; a plaintext listener exists only in a `dev-insecure` build.
//!
//! Two ways in: the deprecated `/api/v1` with one static token (a fixed principal, governed by the policy's
//! `compat` role if it has one), and `/v2` with delegated tokens checked against registered issuers and the
//! policy. The durable audit log is M4 (DECISIONS.md production gate 6).

pub mod admin;
pub mod app;
pub mod backup;
pub mod blobs;
pub mod bucket;
pub mod compat;
pub mod config;
pub mod error;
pub mod gdpr;
pub mod import_opv;
pub mod kms;
pub mod pg;
pub mod routes;
pub mod secret;
pub mod tls;
pub mod tokens;
pub mod tools;
pub mod v2;

/// Whether this build contains the insecure conveniences. Reported on `/readyz` and logged at start.
pub const INSECURE_BUILD: bool = cfg!(feature = "dev-insecure");

/// A string that is in the binary exactly when the insecure conveniences are. CI looks for it: a default build
/// must not contain it, and a `dev-insecure` build must, which proves the check can still see what it checks.
#[cfg(feature = "dev-insecure")]
#[used]
pub static DEV_INSECURE_MARKER: &str = "pvlt-build-marker:dev-insecure-conveniences-present";
