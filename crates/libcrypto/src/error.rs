//! Error handling.

use core::fmt;

use spideroak_crypto::aead::{OpenError, SealError};

/// An internal error.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    InvalidArg(#[from] InvalidArg),

    #[error("{0}")]
    OpenError(#[from] OpenError),

    #[error("{0}")]
    Other(&'static str),

    #[error("{0}")]
    SealError(#[from] SealError),
}

impl From<&'static str> for Error {
    #[inline]
    fn from(err: &'static str) -> Self {
        Self::Other(err)
    }
}

/// The argument is invalid.
pub fn invalid_arg(arg: &'static str, reason: &'static str) -> Error {
    InvalidArg::new(arg, reason).into()
}

/// An argument is invalid.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub struct InvalidArg {
    arg: &'static str,
    reason: &'static str,
}

impl InvalidArg {
    /// Creates an `InvalidArg`.
    #[inline]
    pub(crate) const fn new(arg: &'static str, reason: &'static str) -> Self {
        Self { arg, reason }
    }
}

impl fmt::Display for InvalidArg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid argument: `{}`: {}", self.arg, self.reason)
    }
}
