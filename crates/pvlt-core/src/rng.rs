//! Randomness. Everything random in the engine comes from the operating system through here.

use pvlt_format::{Id, Salt};

use crate::VaultError;

/// Fills `buf` from the OS random number generator.
pub(crate) fn fill(buf: &mut [u8]) -> Result<(), VaultError> {
    getrandom::fill(buf)
        .map_err(|_| VaultError::Unavailable("operating system random number generator"))
}

/// A fresh 24-byte salt. Every seal and every wrap needs its own.
pub(crate) fn salt() -> Result<Salt, VaultError> {
    let mut s = [0u8; 24];
    fill(&mut s)?;
    Ok(s)
}

/// A fresh 16-byte random id.
pub(crate) fn id() -> Result<Id, VaultError> {
    let mut i = [0u8; 16];
    fill(&mut i)?;
    Ok(i)
}
