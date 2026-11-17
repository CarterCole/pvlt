//! The Postgres key store.
//!
//! Implements [`pvlt_core::store::KeyStore`]. The schema is in `migrations/` and is applied by
//! [`PgStore::migrate`]. Read the module documentation of `pvlt_core::store` for what the store guarantees;
//! this crate keeps those guarantees with transactions, row locks and constraints, and the database refuses a
//! malformed or resurrected row even if this code has a bug.
//!
//! The store is only ever handed wrapped keys, ids and 32-byte blind identifiers, so nothing here can write a
//! plaintext value, subject or scope, and there is no query here that could return one.

mod backup;
mod pg;

pub use backup::{BACKUP_TABLES, TableDump};
pub use pg::PgStore;
