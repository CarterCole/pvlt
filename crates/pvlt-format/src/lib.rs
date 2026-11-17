//! The pvlt v1 format, as specified in `docs/FORMAT.md`.
//!
//! This crate is the format and nothing else. It does no I/O, reads no clock and draws no randomness: every
//! salt is an argument, and the caller MUST pass 24 fresh bytes from the operating system CSPRNG for each
//! seal. Section numbers in the module docs refer to FORMAT.md.
//!
//! Key material is taken by reference and returned in [`zeroize::Zeroizing`] wrappers. Callers must not hold
//! those across an `.await`.

mod bytes;
mod error;

pub mod blind;
pub mod blob;
pub mod fact;
pub mod header;
pub mod log;
pub mod suite;
pub mod wrap;

pub use error::Error;
pub use suite::Suite;

/// Length of every key in v1.
pub const KEY_LEN: usize = 32;
/// Length of the per-unit random salt.
pub const SALT_LEN: usize = 24;
/// Length of an AEAD tag in every v1 suite.
pub const TAG_LEN: usize = 16;
/// Length of a domain, object, root-key or signing-key id.
pub const ID_LEN: usize = 16;

/// `"PVLT-v1" ‖ 0x00`, the domain-separation prefix for every label (section 1).
pub const PREFIX: &[u8; 8] = b"PVLT-v1\0";

/// A 32-byte key.
pub type Key = [u8; KEY_LEN];
/// A 24-byte salt.
pub type Salt = [u8; SALT_LEN];
/// A 16-byte id.
pub type Id = [u8; ID_LEN];
