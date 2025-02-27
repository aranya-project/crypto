use std::collections::BTreeMap;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use spideroak_libcrypto_codegen::AEADS;
use syn::{
    braced,
    parse::{Parse, ParseStream},
    parse_quote, Error, Expr, Ident, Result, Token, TypePath,
};

use crate::util::skip_comma;

pub(super) fn build(item: TokenStream) -> Result<TokenStream> {
    let lib = syn::parse2::<Libcrypto>(item)?;
    Ok(lib.tokens)
}

mod kw {
    syn::custom_keyword!(aeads);
}

#[derive(Clone, Debug)]
struct Libcrypto {
    tokens: TokenStream,
}

impl Libcrypto {
    fn parse_aeads(&mut self, input: ParseStream<'_>) -> Result<()> {
        let _ = input.parse::<kw::aeads>()?;
        let content;
        let _ = braced!(content in input);
        let input = content;

        let mut aeads = BTreeMap::new();
        for aead in AEADS {
            aeads.insert(format_ident!("{}", aead.constructor), None);
        }

        while !input.is_empty() {
            let name = input.parse::<Ident>()?;
            let _ = input.parse::<Token![=>]>()?;
            let ty = input.parse::<TypePath>()?;
            skip_comma(&input)?;

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

        for (name, ty) in aeads.iter() {
            let name = format_ident!("__static_{}", name);
            let val: Expr = match ty {
                Some(ref path) => parse_quote! {
                    ::core::option::Option::Some(&EVP_AEAD::new::<#path>())
                },
                None => parse_quote!(::core::option::Option::None),
            };
            self.tokens.extend(quote! {
                #[used]
                #[allow(missing_docs)]
                #[allow(non_upper_case_globals)]
                static #name: ::core::option::Option<&EVP_AEAD> = #val;
            });
        }

        self.tokens.extend({
            let mut max_aead_size = TokenStream::new();
            let mut max_aead_align = TokenStream::new();

            for tokens in [&mut max_aead_size, &mut max_aead_align] {
                tokens.extend(quote! {
                    let mut max: usize = 0;
                });
            }

            for ty in aeads.values().filter_map(Option::as_ref) {
                max_aead_size.extend(quote! {
                    if ::core::mem::size_of::<#ty>() > max {
                        max = ::core::mem::size_of::<#ty>();
                    }
                });
                max_aead_align.extend(quote! {
                    if ::core::mem::align_of::<#ty>() > max {
                        max = ::core::mem::align_of::<#ty>();
                    }
                });
            }

            for tokens in [&mut max_aead_size, &mut max_aead_align] {
                tokens.extend(quote! {
                    max
                });
            }

            quote! {
                /// The maximum size in bytes of an AEAD.
                pub const MAX_AEAD_SIZE: usize = { #max_aead_size };
                /// The maximum alignment in bytes of an AEAD.
                pub const MAX_AEAD_ALIGN: usize = { #max_aead_align };
            }
        });

        Ok(())
    }
}

impl Parse for Libcrypto {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let mut api = Libcrypto {
            tokens: TokenStream::new(),
        };

        while !input.is_empty() {
            let lookahead = input.lookahead1();
            if lookahead.peek(kw::aeads) {
                api.parse_aeads(input)?;
            } else {
                return Err(lookahead.error());
            }
        }

        Ok(api)
    }
}
