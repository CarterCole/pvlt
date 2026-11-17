//! The pvlt server: the HTTP surface over the engine (PLAN.md 3.5, milestone M1).
//!
//! * [`config`]: settings from the environment.
//! * [`app`]: the state every handler shares, and the unseal progress.
//! * [`compat`]: the OPV-compatible `/api/v1/facts` routes OPV clients call.
//! * [`v2`]: the native API, driven by delegated Biscuit tokens and the policy.
//! * [`admin`]: sealing and unsealing, on a separate listener.
//! * [`tls`]: the listener. TLS 1.3 only; a plaintext listener exists only in a `dev-insecure` build.
//!
//! Two ways in: the deprecated `/api/v1` with one static token (a fixed principal, governed by the policy's
//! `compat` role if it has one), and `/v2` with delegated tokens checked against registered issuers and the
//! policy. The durable audit log is M4 (DECISIONS.md production gate 6).

pub mod admin;
pub mod app;
pub mod backup;
pub mod blobs;
pub mod compat;
pub mod config;
pub mod error;
pub mod import_opv;
pub mod routes;
pub mod tls;
pub mod tools;
pub mod v2;

/// Whether this build contains the insecure conveniences. Reported on `/readyz` and logged at start.
pub const INSECURE_BUILD: bool = cfg!(feature = "dev-insecure");
