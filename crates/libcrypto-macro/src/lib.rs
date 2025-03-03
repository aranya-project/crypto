//! TODO

mod aeads;
mod api;
mod util;

use syn::Error;

// Use via the `spideroak-libcrypto` crate.
#[doc(hidden)]
#[proc_macro]
pub fn aeads(item: proc_macro::TokenStream) -> proc_macro::TokenStream {
    aeads::aeads(item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}

// Used by `spideroak-libcrypto`.
#[doc(hidden)]
#[proc_macro_attribute]
pub fn api(
    attr: proc_macro::TokenStream,
    item: proc_macro::TokenStream,
) -> proc_macro::TokenStream {
    api::api(attr.into(), item.into())
        .unwrap_or_else(Error::into_compile_error)
        .into()
}
