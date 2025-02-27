use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use crate::Bindings;

impl Bindings {
    pub(super) fn cipher(&self) -> anyhow::Result<TokenStream> {
        let unsupported = [
            "EVP_des_cbc",
            "EVP_des_ecb",
            "EVP_des_ede",
            "EVP_des_ede3",
            "EVP_des_ede_cbc",
            "EVP_des_ede3_cbc",
            "EVP_aes_128_ecb",
            "EVP_aes_128_cbc",
            "EVP_aes_128_ctr",
            "EVP_aes_128_ofb",
            "EVP_aes_256_ecb",
            "EVP_aes_256_cbc",
            "EVP_aes_256_ctr",
            "EVP_aes_256_ofb",
            "EVP_aes_256_xts",
            "EVP_enc_null",
            "EVP_rc2_cbc",
            "EVP_rc2_40_cbc",
        ]
        .iter()
        .map(|name| {
            let constructor = format_ident!("{}", name);
            quote! {
                /// Always returns `NULL`.
                #[no_mangle]
                pub extern "C" fn #constructor() -> *const EVP_CIPHER {
                    ::core::ptr::null()
                }
            }
        });
        Ok(quote! {
            /// A cipher.
            #[repr(C)]
            pub struct EVP_CIPHER {
                _inner: (usize,),
            }

            #(#unsupported)*
        })
    }
}
