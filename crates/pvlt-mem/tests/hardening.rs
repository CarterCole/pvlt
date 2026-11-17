//! `deny_debugger_attach` changes the whole process, and on macOS it ends the process if a debugger is already
//! attached, so it runs in a child process and the parent only checks the outcome.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pvlt_mem::{deny_debugger_attach, harden_process};

/// Runs only when the parent sets `PVLT_HARDEN_CHILD`; otherwise it passes without doing anything.
#[test]
fn child_hardens_itself() {
    if std::env::var_os("PVLT_HARDEN_CHILD").is_none() {
        return;
    }
    let report = harden_process(true);
    assert!(report.all_ok(), "{report:?}");
    #[cfg(target_os = "linux")]
    {
        // SAFETY: `PR_GET_DUMPABLE` takes no further arguments and only reads a process flag.
        let dumpable = unsafe { libc::prctl(libc::PR_GET_DUMPABLE, 0, 0, 0, 0) };
        assert_eq!(
            dumpable, 0,
            "the process must be non-dumpable after hardening"
        );
    }
    std::process::exit(0);
}

#[test]
fn deny_debugger_attach_works_in_a_child_process() {
    let status = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            "child_hardens_itself",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("PVLT_HARDEN_CHILD", "1")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    assert!(
        status.success(),
        "the child could not harden itself: {status:?}"
    );
}

/// Keeps the import used on platforms where the child test above is compiled out.
#[test]
fn deny_debugger_attach_is_exported() {
    let _: fn() -> Result<(), pvlt_mem::MemError> = deny_debugger_attach;
}
