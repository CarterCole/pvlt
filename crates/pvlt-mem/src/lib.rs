//! Locked, wiped memory for the vault's long-lived keys, and process hardening.
//!
//! This is the only crate in the workspace that uses `unsafe`, and everything unsafe in it is in two small
//! modules: `arena` (mapping, locking and slot access) and `harden` (process settings). Every unsafe block
//! has a `SAFETY` comment, which clippy enforces.
//!
//! What it gives, and what it does not:
//!
//! * Keys held in an [`Arena`] live in pages that are locked in RAM (so they are never swapped), excluded from
//!   core dumps where the OS allows it, fenced by inaccessible guard pages, and overwritten when the
//!   [`SecretKey`] is dropped.
//! * It does not stop a process with debugger access or root from reading memory, and it cannot wipe copies
//!   made elsewhere (registers, stack temporaries, buffers inside other crates). Callers keep key bytes inside
//!   a [`SecretKey`] and borrow them with [`SecretKey::expose`] for the shortest time they can.
//! * A forked child gets a copy of the arena. On Linux the pages are marked `MADV_WIPEONFORK`, so the child
//!   reads zeros; on macOS nothing wipes them, so do not fork a process that holds an arena.

mod arena;
mod error;
mod harden;

pub use arena::{Arena, KEY_LEN, Key, LockPolicy, Report, SecretKey};
pub use error::MemError;
pub use harden::{HardenReport, deny_debugger_attach, disable_core_dumps, harden_process};
