//! TODO

#![cfg_attr(feature = "linkage", feature(linkage))]
#![cfg_attr(docsrs, feature(doc_cfg))]
//#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod aead;
#[doc(hidden)]
pub mod const_fmt;
mod error;
pub mod testing;
mod util;
mod weak;

mod generated {
    include!(concat!(env!("OUT_DIR"), "/generated.rs"));
}
pub use aead::*;
pub use generated::*;
#[doc(hidden)]
pub use linkme;
#[doc(hidden)]
pub use spideroak_crypto;
