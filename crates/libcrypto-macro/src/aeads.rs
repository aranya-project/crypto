use std::collections::BTreeMap;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use spideroak_libcrypto_codegen::AEADS;
use syn::{
    parse::{Parse, ParseStream},
    parse_quote, Error, Expr, Ident, ItemUnion, Result, Token, Type,
};

use crate::util::skip_comma;

pub(super) fn aeads(item: TokenStream) -> Result<TokenStream> {
    let aeads = syn::parse2::<Aeads>(item)?.aeads;

    let libcrypto = format_ident!("__spideroak_libcrypto");

    let item: ItemUnion = {
        let fields = aeads.iter().filter_map(|(ident, ty)| {
            let Some(ty) = ty else {
                return None;
            };
            let ident = format_ident!("_{}", ident.to_string().to_lowercase());
            Some(quote! {
                #ident: ::core::mem::ManuallyDrop<::core::mem::MaybeUninit<#ty>>
            })
        });
        parse_quote! {
            #[repr(C)]
            /// cbindgen:skip
            union __AeadsImpl {
                #(#fields),*
            }
        }
    };

    let ident = &item.ident;

    let aeads_impl = {
        let map = BTreeMap::from_iter(AEADS.iter().map(|aead| {
            (
                format_ident!("{}", aead.constructor),
                format_ident!("{}", aead.name),
            )
        }));
        let consts = aeads.iter().map(|(name, ty)| {
            let name = &map[name];
            let val: Expr = match ty {
                Some(ref path) => parse_quote! {
                    ::core::option::Option::Some(
                        &#libcrypto::aead::EVP_AEAD::new::<#path>())
                },
                None => parse_quote!(::core::option::Option::None),
            };
            quote! {
                const #name: ::core::option::Option<&#libcrypto::aead::EVP_AEAD> = #val;
            }
        });
        quote! {
            // SAFETY: This trait is automatically derived.
            #[automatically_derived]
            unsafe impl #libcrypto::aead::Aeads for #ident {
                #(#consts)*
            }

            const _: () = {
                #libcrypto::const_assert!(
                    <#ident as #libcrypto::aead::Aeads>::MAX_SIZE == ::core::mem::size_of::<#ident>(),
                    "BUG: invalid size:\n",
                    " got: ", <#ident as #libcrypto::aead::Aeads>::MAX_SIZE, "\n",
                    "want: ", ::core::mem::size_of::<#ident>()
                );
                #libcrypto::const_assert!(
                    <#ident as #libcrypto::aead::Aeads>::MAX_ALIGN == ::core::mem::align_of::<#ident>(),
                    "BUG: invalid alignment:\n",
                    " got: ", <#ident as #libcrypto::aead::Aeads>::MAX_ALIGN, "\n",
                    "want: ", ::core::mem::align_of::<#ident>()
                );
            };
        }
    };

    let code = quote! {
        #item
        #aeads_impl
    };
    Ok(code)
}

/// ```ignore
/// aeads! {
///     EVP_aead_aes_128_gcm => Aes128Gcm,
///     ...
/// }
/// ```
#[derive(Clone, Debug)]
struct Aeads {
    aeads: BTreeMap<Ident, Option<Type>>,
}

impl Parse for Aeads {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut aeads = BTreeMap::from_iter(
            AEADS
                .iter()
                .map(|aead| (format_ident!("{}", aead.constructor), None)),
        );

        while !input.is_empty() {
            let name = input.parse::<Ident>()?;
            let _ = input.parse::<Token![=>]>()?;
            let ty = input.parse::<Type>()?;
            skip_comma(input)?;

            let Some(opt) = aeads.get_mut(&name) else {
                return Err(Error::new_spanned(&name, "unknown AEAD"));
            };
            if opt.replace(ty).is_some() {
                return Err(Error::new_spanned(
                    &name,
                    "BUG: `ty` should have been `None`",
                ));
            }
        }
        assert_eq!(aeads.len(), AEADS.len());

        Ok(Self { aeads })
    }
}
