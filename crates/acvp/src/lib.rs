//! ACVP testing utilities.

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

#[allow(unused_extern_crates, reason = "Depends which features are enabled")]
extern crate alloc;

pub mod testing;
pub mod traits;
mod util;
pub mod vectors;

pub use anyhow;
