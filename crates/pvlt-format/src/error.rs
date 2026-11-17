use core::fmt;

/// Why a format operation failed. No variant carries input bytes, key material or plaintext.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// The input could not be opened: wrong key, wrong context, a commitment mismatch, a tag failure or bad
    /// padding. Section 3 requires these to be indistinguishable to the caller, so they are one variant.
    OpenFailed,
    /// The wrapped key is all zeros: it was destroyed on purpose (section 5).
    Shredded,
    /// The suite id is unknown, or this build does not include it.
    UnsupportedSuite,
    /// The input is structurally invalid before any key is involved. The string names the check.
    Malformed(&'static str),
    /// An argument is outside what the format allows. The string names the limit.
    Invalid(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::OpenFailed => f.write_str("open failed"),
            Error::Shredded => f.write_str("key was shredded"),
            Error::UnsupportedSuite => f.write_str("unsupported suite"),
            Error::Malformed(what) => write!(f, "malformed input: {what}"),
            Error::Invalid(what) => write!(f, "invalid argument: {what}"),
        }
    }
}

impl std::error::Error for Error {}
