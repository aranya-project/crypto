//! Code generation.

mod aead;
mod builder;
mod opaque;

pub use aead::{Aead, AEADS};
pub use builder::Builder;
use proc_macro2::TokenStream;

/// Formats a [`TokenStream`] as a string.
pub fn format(tokens: &TokenStream) -> String {
    let mut data = tokens.to_string();
    if let Ok(file) = syn::parse_file(&data) {
        data = prettyplease::unparse(&file);
    }
    data
}
