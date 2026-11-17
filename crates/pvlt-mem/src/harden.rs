//! Process-wide hardening: no core dumps, and no debugger attaching to a running vault.
//!
//! Call [`harden_process`] once at startup, before any key is loaded. These settings are one-way: a process
//! cannot raise its core-dump limit back above a hard limit it lowered.

use crate::error::{MemError, last_errno};

/// Sets the core-dump size limit to zero (soft and hard), so a crash does not write keys to disk.
pub fn disable_core_dumps() -> Result<(), MemError> {
    let zero = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `zero` is a valid `rlimit` for the duration of the call, and `RLIMIT_CORE` is a valid resource.
    if unsafe { libc::setrlimit(libc::RLIMIT_CORE, &raw const zero) } == 0 {
        Ok(())
    } else {
        Err(MemError::Harden("disable core dumps", last_errno()))
    }
}

/// Stops other processes from attaching a debugger or reading this process's memory.
///
/// * Linux: `prctl(PR_SET_DUMPABLE, 0)`. This also blocks `ptrace` by the same user and `/proc/<pid>/mem`.
/// * macOS: `ptrace(PT_DENY_ATTACH)`. **If a debugger is already attached, the OS ends the process.** Do not
///   call this when running under `lldb`.
/// * Elsewhere: [`MemError::Unsupported`].
pub fn deny_debugger_attach() -> Result<(), MemError> {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `PR_SET_DUMPABLE` takes one integer argument, and `prctl` is variadic, so the remaining
        // arguments are passed as zero as the manual page requires.
        if unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) } == 0 {
            Ok(())
        } else {
            Err(MemError::Harden("set non-dumpable", last_errno()))
        }
    }
    #[cfg(target_os = "macos")]
    {
        // SAFETY: `PT_DENY_ATTACH` ignores its pid, address and data arguments.
        if unsafe { libc::ptrace(libc::PT_DENY_ATTACH, 0, core::ptr::null_mut(), 0) } == 0 {
            Ok(())
        } else {
            Err(MemError::Harden("deny debugger attach", last_errno()))
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        Err(MemError::Unsupported("deny debugger attach"))
    }
}

/// What [`harden_process`] managed to do.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HardenReport {
    /// The core-dump limit is now zero.
    pub core_dumps_disabled: Result<(), MemError>,
    /// `None` when the caller did not ask for it.
    pub debugger_attach_denied: Option<Result<(), MemError>>,
}

impl HardenReport {
    /// Whether every step that was asked for worked.
    pub fn all_ok(&self) -> bool {
        self.core_dumps_disabled.is_ok() && self.debugger_attach_denied.is_none_or(|r| r.is_ok())
    }
}

/// Applies the hardening steps and reports each result. The caller decides whether a failure is fatal: a
/// production server should refuse to start, a development one can log and go on.
pub fn harden_process(deny_debugger: bool) -> HardenReport {
    HardenReport {
        core_dumps_disabled: disable_core_dumps(),
        debugger_attach_denied: deny_debugger.then(deny_debugger_attach),
    }
}

#[cfg(test)]
mod tests {
    #![allow(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::indexing_slicing,
        clippy::panic
    )]

    use super::*;

    #[test]
    fn core_dump_limit_becomes_zero() {
        disable_core_dumps().unwrap();
        let mut now = libc::rlimit {
            rlim_cur: 1,
            rlim_max: 1,
        };
        // SAFETY: `now` is a valid, writable `rlimit`.
        let rc = unsafe { libc::getrlimit(libc::RLIMIT_CORE, &raw mut now) };
        assert_eq!(rc, 0);
        assert_eq!((now.rlim_cur, now.rlim_max), (0, 0));
    }

    // `deny_debugger_attach` is not called here: on macOS it ends the test process if a debugger is attached,
    // and on Linux it would make the test runner non-dumpable. It is covered by `tests/hardening.rs`, which
    // runs it in a child process.
}
