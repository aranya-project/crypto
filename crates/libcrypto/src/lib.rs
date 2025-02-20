//! TODO

#![cfg_attr(feature = "linkage", feature(linkage))]
#![cfg_attr(docsrs, feature(doc_cfg))]
//#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

extern crate alloc;

pub(crate) use aranya_capi_macro::opaque;
pub mod aead;
mod util;
pub(crate) mod weak;
#[doc(hidden)]
pub use linkme;
pub mod testing;
#[doc(hidden)]
pub use spideroak_crypto;
