//! Utility crate for

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

extern crate alloc;

pub use spideroak_libcrypto_macro::{aeads, libcrypto};

pub mod aead;
pub mod cipher;
#[doc(hidden)]
pub mod const_fmt;
#[doc(hidden)]
pub mod error;
#[doc(hidden)]
pub mod util;

#[doc(hidden)]
pub use buggy;
#[doc(hidden)]
pub use cfg_if;
#[doc(hidden)]
pub use spideroak_crypto;
