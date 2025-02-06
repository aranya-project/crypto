//! TODO

#![cfg_attr(docsrs, feature(doc_cfg))]
//#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

mod crypto;
mod provider;

pub use provider::{Client, Server};
