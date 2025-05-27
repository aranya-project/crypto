//! Proc macros for [`spideroak-crypto`].
//!
//! [`spideroak-crypto`]: https://crates.io/crates/spideroak-crypto

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

mod alg_id;
mod oid;

use proc_macro::TokenStream;
use syn::Error;

/// See the `crypto` crate for documentation.
#[proc_macro_derive(AlgId, attributes(alg_id))]
pub fn alg_id(item: TokenStream) -> TokenStream {
    alg_id::parse(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

/// Takes an OID string literal input (e.g., `"1.2.3"`), DER
/// encodes it, and outputs the DER as a constant slice literal.
#[proc_macro]
pub fn oid(item: TokenStream) -> TokenStream {
    oid::parse(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
