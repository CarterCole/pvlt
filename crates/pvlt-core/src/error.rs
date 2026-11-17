use core::fmt;

use pvlt_mem::MemError;

/// Why an engine operation failed. No variant carries a key, a value, a subject or a scope.
///
/// This is the start of the public error set from PLAN.md 3.8. `not_found`, `denied` and `rate_limited` arrive
/// with the code that can produce them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum VaultError {
    /// The vault is sealed: no root key is loaded.
    Sealed,
    /// There is no such record.
    NotFound,
    /// The request clashes with what is stored: a duplicate id, a legal hold, a missing parent record. The
    /// string names the clash.
    Conflict(&'static str),
    /// The key was destroyed on purpose. This is permanent, not a reason to retry.
    Shredded,
    /// A key or object did not open: wrong key, wrong context, or tampering. Deliberately one case.
    OpenFailed,
    /// The caller passed something the format or the operation does not allow. The string names the check.
    Invalid(&'static str),
    /// A resource the engine needs failed: the OS random number generator, or locked key memory.
    Unavailable(&'static str),
    /// The ledger, the key store and the bucket disagree in a way that must not be papered over: a forked or
    /// truncated ledger, a bad signature, a published entry that went missing. The server refuses to start.
    Integrity(&'static str),
}

impl VaultError {
    /// A short stable name, for logs and for the API's error codes (PLAN.md 3.8).
    pub fn code(&self) -> &'static str {
        match self {
            VaultError::Sealed => "sealed",
            VaultError::NotFound => "not_found",
            VaultError::Conflict(_) => "conflict",
            VaultError::Shredded => "shredded",
            VaultError::OpenFailed => "open_failed",
            VaultError::Invalid(_) => "invalid",
            VaultError::Unavailable(_) => "unavailable",
            VaultError::Integrity(_) => "integrity",
        }
    }
}

impl fmt::Display for VaultError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VaultError::Sealed => f.write_str("vault is sealed"),
            VaultError::NotFound => f.write_str("not found"),
            VaultError::Conflict(what) => write!(f, "conflict: {what}"),
            VaultError::Shredded => f.write_str("key was shredded"),
            VaultError::OpenFailed => f.write_str("open failed"),
            VaultError::Invalid(what) => write!(f, "invalid: {what}"),
            VaultError::Unavailable(what) => write!(f, "unavailable: {what}"),
            VaultError::Integrity(what) => write!(f, "integrity check failed: {what}"),
        }
    }
}

impl std::error::Error for VaultError {}

impl From<pvlt_format::Error> for VaultError {
    fn from(e: pvlt_format::Error) -> Self {
        use pvlt_format::Error as F;
        match e {
            F::OpenFailed => VaultError::OpenFailed,
            F::Shredded => VaultError::Shredded,
            F::UnsupportedSuite => VaultError::Invalid("unsupported suite"),
            F::Malformed(what) | F::Invalid(what) => VaultError::Invalid(what),
        }
    }
}

impl From<MemError> for VaultError {
    fn from(e: MemError) -> Self {
        match e {
            MemError::Exhausted => VaultError::Unavailable("key memory is full"),
            _ => VaultError::Unavailable("key memory"),
        }
    }
}
