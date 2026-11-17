use core::fmt;

/// Why a memory or hardening operation failed. Carries OS error numbers, never key bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemError {
    /// `mmap` or `mprotect` failed. The number is the OS error.
    Map(i32),
    /// `mlock` failed and the arena was created with [`crate::LockPolicy::Require`]. The usual cause is a
    /// memory-lock limit (`RLIMIT_MEMLOCK`, or `--ulimit memlock` in a container).
    Lock(i32),
    /// Every slot in the arena is in use.
    Exhausted,
    /// An argument is outside what the arena supports.
    Invalid(&'static str),
    /// A process hardening step failed. The string names the step and the number is the OS error.
    Harden(&'static str, i32),
    /// This platform has no way to do the requested hardening step.
    Unsupported(&'static str),
}

impl fmt::Display for MemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MemError::Map(e) => write!(f, "could not map key memory (os error {e})"),
            MemError::Lock(e) => write!(f, "could not lock key memory in RAM (os error {e})"),
            MemError::Exhausted => f.write_str("key memory is full"),
            MemError::Invalid(what) => write!(f, "invalid argument: {what}"),
            MemError::Harden(step, e) => write!(f, "hardening step {step} failed (os error {e})"),
            MemError::Unsupported(step) => write!(f, "hardening step {step} is not supported here"),
        }
    }
}

impl std::error::Error for MemError {}

/// The OS error number from the last failed system call.
pub(crate) fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
