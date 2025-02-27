use std::collections::BTreeMap;

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use spideroak_libcrypto_codegen::gen::AEADS;
use syn::{
    braced,
    parse::{Parse, ParseStream},
    parse_quote, Attribute, Error, Expr, Ident, ItemUnion, Result, Token, TypePath,
};

pub(super) fn aeads(item: TokenStream) -> Result<TokenStream> {
    let mut item = syn::parse2::<ItemUnion>(item)?;

    if !is_repr_c(&item.attrs) {
        item.attrs.push(parse_quote! {
            #[repr(C)]
        });
    }

    let mut algs = BTreeMap::new();
    for name in [
        "AES_128_GCM",
        "AES_256_GCM",
        "AES_128_GCM_TLS13",
        "AES_256_GCM_TLS13",
        "CHACHA20_POLY1305",
    ] {
        algs.insert(format_ident!("{}", name), None);
    }

    for field in item.fields.named.iter_mut() {
        let ty = &mut field.ty;
        *ty = parse_quote! {
            ::core::mem::ManuallyDrop<#ty>
        };
        let Some(Helper { alg }) = find_helper(&field.attrs)? else {
            return Err(Error::new_spanned(
                field,
                "missing `#[aead(...)]` attribute",
            ));
        };
        let Some(v) = algs.get_mut(&alg) else {
            return Err(Error::new_spanned(&alg, "unknown algorithm"));
        };
        if v.replace(&field.ty).is_some() {
            return Err(Error::new_spanned(
                &alg,
                "BUG: `ty` should have been `None`",
            ));
        }
    }

    let algs = algs.iter().map(|name, ty| {
        let val: Expr = match ty {
            Some(ref path) => parse_quote! {
                ::core::option::Option::Some(&EVP_AEAD::new::<#path>())
            },
            None => parse_quote!(::core::option::Option::None),
        };
    });

    let ident = &item.ident;
    let code = quote! {
        #item

        unsafe impl spideroak_libcrypto::aead::Aeads for #ident {
        }
    };
    Ok(code)
}

fn is_repr_c(attrs: &[Attribute]) -> bool {
    for attr in attrs {
        if attr.path().is_ident("repr") {
            return true; // TODO
        }
    }
    false
}

fn find_helper(attrs: &[Attribute]) -> Result<Option<Helper>> {
    for attr in attrs {
        if attr.path().is_ident("aead") {
            let helper = attr.parse_args::<Helper>()?;
            return Ok(Some(helper));
        }
    }
    Ok(None)
}

#[derive(Clone, Debug)]
struct Helper {
    alg: Ident,
}

impl Parse for Helper {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let span = input.span();
        let mut alg = None;
        while !input.is_empty() {
            let lookahead = input.lookahead1();
            if lookahead.peek(kw::alg) {
                let _ = input.parse::<kw::alg>()?;
                let _ = input.parse::<Token![=]>()?;
                alg = Some(input.parse::<Ident>()?);
            } else {
                return Err(lookahead.error());
            }
        }
        let alg = alg.ok_or_else(|| Error::new(span, "missing `alg`"))?;
        Ok(Self { alg })
    }
}

mod kw {
    syn::custom_keyword!(alg);
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
            let ty: Expr = match ty {
                Some(ref path) => parse_quote! {
                    ::core::option::Option::Some(&EVP_AEAD::new::<#path>())
                },
                None => parse_quote!(::core::option::Option::None),
            };
            self.tokens.extend(quote! {
                #[used]
                #[allow(missing_docs)]
                #[allow(non_upper_case_globals)]
                static #name: ::core::option::Option<&EVP_AEAD> = #ty;
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

/// Skips the next token if it's a comma.
fn skip_comma(input: ParseStream<'_>) -> Result<()> {
    let lookahead = input.lookahead1();
    if lookahead.peek(Token![,]) {
        let _: Token![,] = input.parse()?;
    }
    Ok(())
}
