#![allow(
    dead_code,
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use pvlt_mem::{Arena, LockPolicy};

/// An arena for tests. `BestEffort` so the tests also run where `mlock` is limited, such as some CI containers.
pub fn arena() -> Arena {
    Arena::new(256, LockPolicy::BestEffort).unwrap()
}

pub fn id(n: u8) -> [u8; 16] {
    [n; 16]
}
