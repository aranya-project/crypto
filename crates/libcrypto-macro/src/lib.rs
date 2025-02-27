//! TODO

mod aeads;
mod build;
mod util;

use syn::Error;

// Use via the `spideroak-libcrypto` crate.
#[doc(hidden)]
#[proc_macro]
pub fn libcrypto(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    build::build(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

// Use via the `spideroak-libcrypto` crate.
#[doc(hidden)]
#[proc_macro]
pub fn aeads(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    aeads::aeads(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
