//! TODO

#![cfg_attr(feature = "linkage", feature(linkage))]
#![cfg_attr(docsrs, feature(doc_cfg))]
//#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

extern crate alloc;

mod aead;
pub mod testing;
mod util;
mod weak;

pub use aead::*;
// pub(crate) use aranya_capi_macro::opaque;
#[doc(hidden)]
pub use linkme;
#[doc(hidden)]
pub use spideroak_crypto;
