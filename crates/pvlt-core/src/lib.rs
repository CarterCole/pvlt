//! The pvlt engine: the key hierarchy, sealing, and the fact create, read and shred paths (PLAN.md, M1).
//!
//! * [`keys`]: the root key, domain keys, subject keys and data keys, and how each is wrapped by its parent.
//! * [`seal`]: creating the root key, splitting its unseal key into Shamir shares, and recovering it.
//! * [`keyring`]: the sealed or unsealed state of a running vault, and the domain key cache.
//! * [`store`]: the `KeyStore` trait and the records it holds. Only wrapped keys, ids and blind identifiers.
//! * [`objects`]: the `ObjectStore` trait, the bucket that holds sealed values.
//! * [`engine`]: create, read and shred facts over a key store and an object store.
//! * [`audit`]: what the engine reports about each operation.
//! * [`memory`]: in-process stores for tests.
//!
//! Rules that hold throughout, from PLAN.md 3.1:
//!
//! * Long-lived keys (root, domain) live in a locked [`pvlt_mem::Arena`]. Short-lived keys (subject, data) are
//!   heap boxes wiped on drop.
//! * Every salt is drawn here from the OS random number generator. `pvlt-format` never draws one.
//! * No key is held across an `.await`. The engine's async methods fetch rows first and then do all the key
//!   work in one synchronous step.
//! * Key types have no `Clone`, no `Serialize`, and a `Debug` that prints nothing about the contents.

pub mod audit;
pub mod audit_log;
pub mod engine;
mod error;
pub mod keyring;
pub mod keys;
pub mod ledger;
pub mod memory;
pub mod objects;
mod rng;
pub mod seal;
pub mod store;

pub use error::VaultError;
