//! API generation.

use std::mem;

use proc_macro2::{Span, TokenStream};
use quote::{format_ident, quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    parse_quote,
    punctuated::Punctuated,
    spanned::Spanned,
    Attribute, Error, File, FnArg, GenericArgument, Generics, Ident, Item, ItemFn, LitStr, Pat,
    PatIdent, Path, PathArguments, Result, ReturnType, Token, Type, TypePath, Visibility,
};

pub(crate) fn parse_str(src: &str) -> Result<TokenStream> {
    let file = syn::parse_file(src)?;
    parse(file)
}

fn parse(file: File) -> Result<TokenStream> {
    let mut tokens = TokenStream::new();
    for item in file.items {
        if let Item::Fn(item) = item {
            if let Some(new) = parse_item(item)? {
                tokens.extend(new);
            }
        }
    }
    Ok(tokens)
}

/// Parse an API function.
pub fn parse_item(mut item: ItemFn) -> Result<Option<TokenStream>> {
    let Some(Api { alias }) = Api::find(&mut item.attrs)? else {
        return Ok(None);
    };

    // TODO(eric): fix docs by rewriting `evp_aead_ctx_init` to
    // `EVP_AEAD_CTX_init`, etc.

    if item.sig.constness.is_some() {
        return Err(not_allowed(item.sig.constness));
    }
    if item.sig.asyncness.is_some() {
        return Err(not_allowed(item.sig.asyncness));
    }
    if item.sig.abi.is_some() {
        return Err(not_allowed(item.sig.abi));
    }
    if item.sig.variadic.is_some() {
        return Err(not_allowed(item.sig.variadic));
    }

    item.attrs.push(parse_quote! {
        #[no_mangle]
    });
    item.vis = Visibility::Public(Token![pub](Span::call_site()));
    item.sig.abi = Some(parse_quote!(extern "C"));
    // The exported API uses concrete types and generics for
    // `spideroak-libcrypto` are inferred.
    item.sig.generics = Generics::default();
    let ident = mem::replace(&mut item.sig.ident, alias);
    if let ReturnType::Type(_, ty) = &mut item.sig.output {
        *ty = parse_quote!(::core::ffi::c_int);
    }

    let args = item
        .sig
        .inputs
        .iter_mut()
        .map(|arg| {
            let FnArg::Typed(pat) = arg else {
                return Err(Error::new_spanned(arg, "unsupported arg type"));
            };
            let Pat::Ident(PatIdent {
                attrs,
                by_ref: None,
                ident,
                subpat: None,
                ..
            }) = &*pat.pat
            else {
                return Err(Error::new_spanned(pat, "unsupported pattern"));
            };
            if !attrs.is_empty() {
                return Err(Error::new_spanned(pat, "attributes not allowed here"));
            }

            let ty = &mut pat.ty;
            strip_generics(ty)?;
            qualify(ty)?;

            Ok(ident.clone())
        })
        .collect::<Result<Punctuated<_, Token![,]>>>()?;

    let libcrypto = format_ident!("__spideroak_libcrypto");
    let block = match &item.sig.output {
        ReturnType::Default => {
            parse_quote! {{
                unsafe { #libcrypto::api::#ident(#args) }
            }}
        }
        ReturnType::Type(..) => {
            parse_quote! {{
                match unsafe { #libcrypto::api::#ident(#args) } {
                    ::core::result::Result::Ok(()) => 1,
                    ::core::result::Result::Err(_) => 0,
                }
            }}
        }
    };
    item.block = Box::new(block);

    println!("{}", crate::format(&quote!(#item)));

    let code = quote! {
        #item
    };
    Ok(Some(code))
}

fn strip_generics(ty: &mut Type) -> Result<()> {
    let span = ty.span();
    match ty {
        Type::Array(array) => {
            strip_generics(&mut *array.elem)?;
        }
        Type::Path(TypePath { qself, path }) => {
            if qself.is_some() {
                return Err(Error::new(span, "qself not allowed here"));
            }
            if let Some(ty) = parse_maybe_uninit_mut(path) {
                strip_generics(ty)?;
            } else {
                for seg in &mut path.segments {
                    seg.arguments = PathArguments::None;
                }
            }
        }
        Type::Ptr(ptr) => {
            strip_generics(&mut *ptr.elem)?;
        }
        Type::Reference(xref) => {
            strip_generics(&mut xref.elem)?;
        }
        Type::Slice(s) => {
            strip_generics(&mut s.elem)?;
        }
        ty => return Err(Error::new_spanned(ty, "not supported")),
    };
    Ok(())
}

fn qualify(ty: &mut Type) -> Result<()> {
    let span = ty.span();
    match ty {
        Type::Array(array) => {
            qualify(&mut *array.elem)?;
        }
        Type::Path(TypePath { qself, path }) => {
            if qself.is_some() {
                return Err(Error::new(span, "qself not allowed here"));
            }
            if let Some(ty) = parse_maybe_uninit_mut(path) {
                *path = parse_quote!(::core::mem::MaybeUninit<#ty>);
            }
        }
        Type::Ptr(ptr) => {
            qualify(&mut *ptr.elem)?;
        }
        Type::Reference(xref) => {
            qualify(&mut xref.elem)?;
        }
        Type::Slice(s) => {
            qualify(&mut s.elem)?;
        }
        ty => return Err(Error::new_spanned(ty, "not supported")),
    };
    Ok(())
}

fn parse_maybe_uninit_mut(path: &mut Path) -> Option<&mut Type> {
    if path.leading_colon.is_some()
        || path.segments.len() != 1
        || path.segments[0].ident != "MaybeUninit"
    {
        return None;
    }
    let PathArguments::AngleBracketed(args) = &mut path.segments[0].arguments else {
        return None;
    };
    if args.args.len() != 1 {
        return None;
    }
    let GenericArgument::Type(ty) = &mut args.args[0] else {
        return None;
    };
    Some(ty)
}

fn not_allowed(tokens: impl ToTokens) -> Error {
    Error::new_spanned(tokens, "not allowed")
}

mod kw {
    syn::custom_keyword!(alias);
}

/// ```ignore
/// #[api(alias = "EVP_AEAD_CTX_init")]
/// pub unsafe fn evp_aead_ctx_init(...) -> Result<...> -> {
///     ...
/// }
/// ```
#[derive(Clone, Debug)]
pub struct Api {
    alias: Ident,
}

impl Api {
    fn find(attrs: &mut Vec<Attribute>) -> Result<Option<Self>> {
        let Some(idx) = attrs.iter().position(|attr| attr.path().is_ident("api")) else {
            return Ok(None);
        };
        let attr = attrs.remove(idx).parse_args::<Self>()?;
        Ok(Some(attr))
    }
}

impl Parse for Api {
    fn parse(input: ParseStream<'_>) -> Result<Self> {
        let span = input.span();
        let mut alias = None;

        while !input.is_empty() {
            let lookahead = input.lookahead1();
            if lookahead.peek(kw::alias) {
                let key = input.parse::<Ident>()?;
                let _ = input.parse::<Token![=]>()?;
                let val = input.parse::<LitStr>()?;
                if alias
                    .replace(Ident::new(&val.value(), val.span()))
                    .is_some()
                {
                    return Err(Error::new_spanned(key, "duplicate key"));
                }
            } else {
                return Err(lookahead.error());
            }
            skip_comma(input)?;
        }

        let alias = alias.ok_or_else(|| Error::new(span, "missing `alias`"))?;

        Ok(Self { alias })
    }
}

/// Skips the next token if it's a comma.
pub(crate) fn skip_comma(input: ParseStream<'_>) -> Result<()> {
    let lookahead = input.lookahead1();
    if lookahead.peek(Token![,]) {
        let _: Token![,] = input.parse()?;
    }
    Ok(())
}
