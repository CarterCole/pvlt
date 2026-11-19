//! The pvlt access policy: a strict, default-deny JSON document, its evaluator, and the per-role rate limiter.
//!
//! Pure logic. This crate holds no keys, does no I/O and has no clock of its own beyond the limiter's
//! `Instant`s, so a policy can be checked offline and the evaluator can be tested as a table of allow and deny
//! cases.
//!
//! * [`policy`]: the document, its canonical form and SHA-256, and [`policy::Policy::decide`].
//! * [`limits`]: the in-memory sliding-window limiter (per replica).

pub mod limits;
pub mod policy;
