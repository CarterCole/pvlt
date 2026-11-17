//! The key arena: one mapping, guard pages on both sides, 32-byte slots in the middle.
//!
//! ```text
//!   | guard page (no access) | data pages: slot 0, slot 1, … (locked) | guard page (no access) |
//! ```
//!
//! # Invariants the unsafe code relies on
//!
//! 1. `Inner` owns the whole mapping from `base` for `total` bytes until it is dropped, and the mapping is
//!    never remapped or moved.
//! 2. The data region (`data`, `data_len`) is readable and writable. The pages on either side are not.
//! 3. Each slot index is either in the free list or owned by exactly one live [`SecretKey`], never both and
//!    never two owners. A slot's 32 bytes are therefore only reachable through that one `SecretKey`.
//! 4. A `SecretKey` keeps `Inner` alive through an `Arc`, so its slot pointer is valid for its whole life.
//! 5. While a `SecretKey` is alive, only shared references to its slot are handed out ([`SecretKey::expose`]).
//!    The one `&mut` to a slot is created before the `SecretKey` is returned to anyone (in
//!    [`Arena::alloc_with`]) and in `Drop`, which has exclusive access.

use core::ffi::c_void;
use core::fmt;
use core::ptr::NonNull;
use std::sync::{Arc, Mutex, PoisonError};

use zeroize::Zeroize;

use crate::error::{MemError, last_errno};

/// Length of a key.
pub const KEY_LEN: usize = 32;
/// A 32-byte key.
pub type Key = [u8; KEY_LEN];

/// What to do when the OS refuses to lock the arena's pages in RAM.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LockPolicy {
    /// Fail. For production: keys that can reach swap are a bug.
    Require,
    /// Carry on unlocked and say so in the [`Report`]. For development and tests on locked-down hosts.
    BestEffort,
}

/// Which protections the arena actually got. Expose this on `/readyz` and refuse to start in production when a
/// protection that should be on is off.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Report {
    /// The data pages are locked in RAM and cannot be swapped out.
    pub locked: bool,
    /// The data pages are excluded from core dumps (`MADV_DONTDUMP`). Linux only; elsewhere this is `false` and
    /// core dumps must be disabled for the process instead (see [`crate::disable_core_dumps`]).
    pub excluded_from_dumps: bool,
    /// The data pages read as zero in a forked child (`MADV_WIPEONFORK`). Linux only.
    pub wiped_on_fork: bool,
}

struct Inner {
    base: NonNull<u8>,
    total: usize,
    data: NonNull<u8>,
    data_len: usize,
    slots: usize,
    free: Mutex<Vec<usize>>,
    report: Report,
}

// SAFETY: `Inner` holds a raw pointer into a mapping that it owns for its whole life (invariant 1). The only
// mutation of shared state goes through `free`, which is a `Mutex`, and through slots, each of which has a
// single owner (invariant 3).
unsafe impl Send for Inner {}
// SAFETY: as above; shared access only reads slots through `SecretKey::expose` or locks `free`.
unsafe impl Sync for Inner {}

impl Drop for Inner {
    fn drop(&mut self) {
        // SAFETY: `data` is valid for `data_len` bytes, read-write, and `&mut self` means no `SecretKey` can
        // still exist (each holds an `Arc<Inner>`), so nothing else is reading it.
        unsafe { core::slice::from_raw_parts_mut(self.data.as_ptr(), self.data_len) }.zeroize();
        if self.report.locked {
            // SAFETY: the same region that `mlock` locked. A failure here changes nothing: the pages are
            // about to be unmapped, which releases the lock.
            unsafe { libc::munlock(self.data.as_ptr().cast::<c_void>(), self.data_len) };
        }
        // SAFETY: `base` and `total` are exactly what `mmap` returned and was asked for (invariant 1), and
        // nothing refers into the mapping after this.
        unsafe { libc::munmap(self.base.as_ptr().cast::<c_void>(), self.total) };
    }
}

/// A pool of locked key slots. Cloning is cheap and shares the same pool.
#[derive(Clone)]
pub struct Arena {
    inner: Arc<Inner>,
}

impl fmt::Debug for Arena {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Arena")
            .field("capacity", &self.capacity())
            .field("in_use", &self.slots_in_use())
            .field("report", &self.inner.report)
            .finish()
    }
}

fn page_size() -> Result<usize, MemError> {
    // SAFETY: `sysconf` with a valid name has no memory-safety preconditions.
    let n = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    usize::try_from(n)
        .ok()
        .filter(|p| *p > 0)
        .ok_or(MemError::Invalid("page size"))
}

impl Arena {
    /// Maps an arena with room for at least `min_slots` keys. The capacity is rounded up to whole pages, so
    /// use [`Arena::capacity`] for the real number.
    pub fn new(min_slots: usize, policy: LockPolicy) -> Result<Arena, MemError> {
        let page = page_size()?;
        let want = min_slots
            .max(1)
            .checked_mul(KEY_LEN)
            .ok_or(MemError::Invalid("too many slots"))?;
        let data_len = want
            .div_ceil(page)
            .checked_mul(page)
            .ok_or(MemError::Invalid("too many slots"))?;
        let total = data_len
            .checked_add(
                page.checked_mul(2)
                    .ok_or(MemError::Invalid("too many slots"))?,
            )
            .ok_or(MemError::Invalid("too many slots"))?;

        // SAFETY: an anonymous private mapping at a kernel-chosen address with no access. The arguments are
        // valid; the result is checked against `MAP_FAILED` before use.
        let base = unsafe {
            libc::mmap(
                core::ptr::null_mut(),
                total,
                libc::PROT_NONE,
                libc::MAP_PRIVATE | libc::MAP_ANON,
                -1,
                0,
            )
        };
        if base == libc::MAP_FAILED {
            return Err(MemError::Map(last_errno()));
        }
        let base = NonNull::new(base.cast::<u8>()).ok_or(MemError::Map(0))?;
        // SAFETY: `page` is less than `total`, so the result stays inside the mapping.
        let data = unsafe { NonNull::new_unchecked(base.as_ptr().add(page)) };

        let slots = data_len / KEY_LEN;
        let mut inner = Inner {
            base,
            total,
            data,
            data_len,
            slots,
            free: Mutex::new((0..slots).rev().collect()),
            report: Report {
                locked: false,
                excluded_from_dumps: false,
                wiped_on_fork: false,
            },
        };
        // From here every early return drops `inner`, which zeroes and unmaps. The data region is still
        // PROT_NONE until the `mprotect` below, so `Drop` must not run before it succeeds: it would fault.
        // Instead of reasoning about that, make the data region accessible first and fail cleanly if not.

        // SAFETY: `data..data+data_len` lies inside the mapping, between the two guard pages.
        let rc = unsafe {
            libc::mprotect(
                data.as_ptr().cast::<c_void>(),
                data_len,
                libc::PROT_READ | libc::PROT_WRITE,
            )
        };
        if rc != 0 {
            let errno = last_errno();
            // The data region is still PROT_NONE: unmap by hand and skip `Inner::drop`, which would write to it.
            // SAFETY: exactly the mapping created above. `forget` stops `Drop` from running.
            unsafe { libc::munmap(base.as_ptr().cast::<c_void>(), total) };
            core::mem::forget(inner);
            return Err(MemError::Map(errno));
        }

        // SAFETY: the region was just made accessible; `mlock` only changes paging behaviour.
        let locked = unsafe { libc::mlock(data.as_ptr().cast::<c_void>(), data_len) } == 0;
        if !locked && policy == LockPolicy::Require {
            return Err(MemError::Lock(last_errno()));
        }
        inner.report.locked = locked;

        #[cfg(target_os = "linux")]
        {
            // SAFETY: advice flags on a region this process owns; they do not change its contents.
            inner.report.excluded_from_dumps = unsafe {
                libc::madvise(
                    data.as_ptr().cast::<c_void>(),
                    data_len,
                    libc::MADV_DONTDUMP,
                )
            } == 0;
            // SAFETY: as above.
            inner.report.wiped_on_fork = unsafe {
                libc::madvise(
                    data.as_ptr().cast::<c_void>(),
                    data_len,
                    libc::MADV_WIPEONFORK,
                )
            } == 0;
        }

        Ok(Arena {
            inner: Arc::new(inner),
        })
    }

    /// The number of keys the arena can hold.
    pub fn capacity(&self) -> usize {
        self.inner.slots
    }

    /// The number of keys alive right now.
    pub fn slots_in_use(&self) -> usize {
        self.inner.slots - self.free().len()
    }

    /// Which protections the arena got.
    pub fn report(&self) -> Report {
        self.inner.report
    }

    fn free(&self) -> std::sync::MutexGuard<'_, Vec<usize>> {
        // Nothing run under this lock can panic, but if it ever did the list is still a valid list of free
        // slots, so carrying on is correct.
        self.inner
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
    }

    /// Takes a slot and lets `fill` write the key straight into locked memory, so the key never sits in an
    /// ordinary buffer first. If `fill` fails the slot is wiped and returned to the pool.
    pub fn alloc_with<E, F>(&self, fill: F) -> Result<SecretKey, E>
    where
        E: From<MemError>,
        F: FnOnce(&mut Key) -> Result<(), E>,
    {
        let slot = self.free().pop().ok_or(MemError::Exhausted)?;
        // From here the slot belongs to `key`, whose `Drop` wipes it and gives it back on any early return.
        let key = SecretKey {
            inner: Arc::clone(&self.inner),
            slot,
        };
        // SAFETY: `key` is the only owner of this slot (invariant 3) and has not been shared, so this is the
        // only reference to these 32 bytes (invariant 5). The pointer is in the data region and live.
        fill(unsafe { &mut *key.ptr() })?;
        Ok(key)
    }

    /// Moves a key into the arena and wipes the source.
    pub fn alloc(&self, key: &mut Key) -> Result<SecretKey, MemError> {
        let out = self.alloc_with::<MemError, _>(|slot| {
            slot.copy_from_slice(key.as_slice());
            Ok(())
        });
        key.zeroize();
        out
    }
}

/// A 32-byte key in locked memory. Wiped on drop. It has no `Clone`, no `Serialize`, and a `Debug` that prints
/// nothing about the contents.
pub struct SecretKey {
    inner: Arc<Inner>,
    slot: usize,
}

impl SecretKey {
    fn ptr(&self) -> *mut Key {
        // SAFETY: `slot < slots` (it came from the free list, which holds `0..slots`), so the offset is
        // inside the data region. `Key` has alignment 1.
        unsafe {
            self.inner
                .data
                .as_ptr()
                .add(self.slot * KEY_LEN)
                .cast::<Key>()
        }
    }

    /// Borrows the key bytes. Keep the borrow short and do not hold it across an `.await`.
    pub fn expose(&self) -> &Key {
        // SAFETY: the slot is owned by `self` and no `&mut` to it exists while `self` is shared
        // (invariant 5). The mapping outlives `self` through the `Arc` (invariant 4).
        unsafe { &*self.ptr() }
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        // SAFETY: `&mut self` gives exclusive access to this slot (invariant 3), and the mapping is alive.
        unsafe { &mut *self.ptr() }.zeroize();
        self.inner
            .free
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .push(self.slot);
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretKey(..)")
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

    fn arena(n: usize) -> Arena {
        Arena::new(n, LockPolicy::Require).unwrap()
    }

    #[test]
    fn alloc_moves_the_key_in_and_wipes_the_source() {
        let a = arena(4);
        let mut src = [0xAB; KEY_LEN];
        let k = a.alloc(&mut src).unwrap();
        assert_eq!(*k.expose(), [0xAB; KEY_LEN]);
        assert_eq!(src, [0; KEY_LEN], "the source buffer must be wiped");
    }

    #[test]
    fn dropping_a_key_wipes_its_slot_and_frees_it() {
        let a = arena(4);
        let k = a.alloc(&mut [0xCD; KEY_LEN]).unwrap();
        let slot_ptr = k.ptr();
        assert_eq!(a.slots_in_use(), 1);
        drop(k);
        assert_eq!(a.slots_in_use(), 0);
        // SAFETY: the arena is alive, so the mapping is too, and nothing owns this slot now.
        let after = unsafe { *slot_ptr };
        assert_eq!(
            after, [0; KEY_LEN],
            "a dropped key's slot must read as zero"
        );
    }

    #[test]
    fn keys_do_not_overlap() {
        let a = arena(8);
        let keys: Vec<SecretKey> = (0..8u8)
            .map(|i| a.alloc(&mut [i; KEY_LEN]).unwrap())
            .collect();
        for (i, k) in keys.iter().enumerate() {
            assert_eq!(*k.expose(), [u8::try_from(i).unwrap(); KEY_LEN]);
        }
    }

    #[test]
    fn exhaustion_is_an_error_and_slots_come_back() {
        let a = arena(1);
        let cap = a.capacity();
        let mut held: Vec<SecretKey> = (0..cap)
            .map(|_| a.alloc(&mut [1; KEY_LEN]).unwrap())
            .collect();
        assert_eq!(a.alloc(&mut [1; KEY_LEN]).unwrap_err(), MemError::Exhausted);
        held.pop();
        assert!(a.alloc(&mut [1; KEY_LEN]).is_ok());
    }

    #[test]
    fn a_failed_fill_wipes_and_returns_the_slot() {
        let a = arena(2);
        let r: Result<SecretKey, MemError> = a.alloc_with(|slot| {
            slot.fill(0xEE);
            Err(MemError::Invalid("fill failed"))
        });
        assert!(r.is_err());
        assert_eq!(a.slots_in_use(), 0);
        let k = a.alloc_with::<MemError, _>(|_| Ok(())).unwrap();
        assert_eq!(
            *k.expose(),
            [0; KEY_LEN],
            "a reused slot must not show the failed fill's bytes"
        );
    }

    #[test]
    fn capacity_is_rounded_to_pages() {
        let a = arena(1);
        let page = page_size().unwrap();
        assert_eq!(a.capacity(), page / KEY_LEN);
        assert!(a.capacity() >= 1);
    }

    #[test]
    fn a_required_lock_is_reported_as_taken() {
        let a = arena(4);
        assert!(a.report().locked);
        #[cfg(target_os = "linux")]
        assert!(a.report().excluded_from_dumps);
    }

    #[test]
    fn debug_shows_nothing_about_the_key() {
        let a = arena(1);
        let k = a.alloc(&mut [0x5A; KEY_LEN]).unwrap();
        let shown = format!("{k:?} {a:?}");
        assert!(
            !shown.contains("5A") && !shown.contains("90") && shown.contains("SecretKey(..)"),
            "{shown}"
        );
    }

    #[test]
    fn many_threads_can_alloc_and_drop() {
        let a = arena(64);
        std::thread::scope(|s| {
            for t in 0..8u8 {
                let a = a.clone();
                s.spawn(move || {
                    for i in 0..500u32 {
                        let fill = t ^ u8::try_from(i % 251).unwrap();
                        if let Ok(k) = a.alloc(&mut [fill; KEY_LEN]) {
                            assert_eq!(*k.expose(), [fill; KEY_LEN]);
                        }
                    }
                });
            }
        });
        assert_eq!(a.slots_in_use(), 0, "every slot must come back");
    }

    #[test]
    fn keys_outlive_the_arena_handle() {
        let a = arena(1);
        let k = a.alloc(&mut [9; KEY_LEN]).unwrap();
        drop(a);
        assert_eq!(*k.expose(), [9; KEY_LEN]);
    }

    #[test]
    fn types_are_send_and_sync() {
        fn check<T: Send + Sync>() {}
        check::<Arena>();
        check::<SecretKey>();
    }

    /// Runs only when the parent test sets `PVLT_GUARD_PROBE`; otherwise it passes without doing anything.
    /// Reads one byte of a fresh arena's mapping and exits, so a guard page ends the process with a signal.
    #[test]
    fn guard_probe_child() {
        let Ok(which) = std::env::var("PVLT_GUARD_PROBE") else {
            return;
        };
        let a = arena(1);
        let inner = &a.inner;
        let addr = match which.as_str() {
            "below" => inner.base.as_ptr(),
            // SAFETY: the offset stays inside the mapping; the read below is the point of the test.
            "above" => unsafe { inner.base.as_ptr().add(inner.total - 1) },
            "inside" => inner.data.as_ptr(),
            other => panic!("unknown probe {other}"),
        };
        // SAFETY: deliberately reads a guard page for "below" and "above", which must fault.
        let byte = unsafe { core::ptr::read_volatile(addr) };
        std::process::exit(if byte == 0 { 0 } else { 3 });
    }

    fn probe(which: &str) -> std::process::ExitStatus {
        std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "arena::tests::guard_probe_child",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("PVLT_GUARD_PROBE", which)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
    }

    #[test]
    fn guard_pages_fault_and_the_data_region_does_not() {
        use std::os::unix::process::ExitStatusExt;
        assert!(
            probe("inside").success(),
            "reading the data region must work"
        );
        for side in ["below", "above"] {
            let status = probe(side);
            assert!(
                status.signal().is_some(),
                "reading the guard page {side} the data must fault, got {status:?}"
            );
        }
    }
}
