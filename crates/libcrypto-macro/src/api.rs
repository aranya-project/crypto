use proc_macro2::TokenStream;
use spideroak_libcrypto_codegen::api::{self, Api};
use syn::{ItemFn, Result};

pub(super) fn api(attr: TokenStream, item: TokenStream) -> Result<TokenStream> {
    // We don't want to generate anyting here, just make sure the
    // macro is correct.
    let orig = item.clone();
    let _ = syn::parse2::<Api>(attr)?;
    let item = syn::parse2::<ItemFn>(item)?;
    let _ = api::parse_item(item)?;
    Ok(orig)
}
