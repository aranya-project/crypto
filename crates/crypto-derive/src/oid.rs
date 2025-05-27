#![allow(clippy::arithmetic_side_effects)]

use std::{ops::RangeBounds, str::FromStr};

use proc_macro2::{Literal, Span, TokenStream};
use quote::{quote, ToTokens};
use syn::{
    parse::{Parse, ParseStream},
    Error, LitStr,
};

type Arc = u128;

pub(crate) fn parse(input: TokenStream) -> syn::Result<TokenStream> {
    let oid = syn::parse2::<Oid>(input)?.into_token_stream();
    Ok(oid)
}

struct Oid {
    arcs: Vec<Arc>,
    // "true" number of arcs b/c the first and second arcs are
    // combined into one.
    n: usize,
}

impl ToTokens for Oid {
    fn to_tokens(&self, tokens: &mut TokenStream) {
        let mut der = Vec::new();
        for &arc in &self.arcs {
            let bits = <Arc>::BITS - arc.leading_zeros();
            let nbytes = if arc == 0 {
                1
            } else {
                ((bits + 6) / 7) as usize
            };
            for i in (0..nbytes).rev() {
                let mut o = (arc >> (i * 7)) & 0x7f;
                if i != 0 {
                    o |= 0x80;
                }
                der.push(o as u8);
            }
        }
        tokens.extend(quote! {
            &[#(#der,)*]
        })
    }
}

impl Oid {
    fn try_push(&mut self, mut arc: Arc) -> Result<(), &'static str> {
        if self.n == 0 && arc > Arc::from(2u32) {
            return Err("first arc out of range (must be in [0, 2])");
        }
        if self.n == 1 {
            let arc1 = self.arcs.remove(0);
            let arc2 = arc;
            if arc1 < 2 && arc2 >= 40 {
                return Err("second arc out of range (must be in [0, 39])");
            }
            arc = (arc1 * 40) + arc2;
        }
        self.arcs.push(arc);
        self.n += 1;
        Ok(())
    }
}

impl Parse for Oid {
    fn parse(input: ParseStream<'_>) -> syn::Result<Self> {
        let lit = input.parse::<LitStr>()?;
        let span = lit.span();
        let s = lit.value();

        let mut oid = Self {
            arcs: Vec::new(),
            n: 0,
        };
        let mut idx = 1;
        for elem in s.split(".") {
            if elem.is_empty() {
                let span = make_span(span, idx..idx + 1);
                return Err(Error::new(span, "empty arc"));
            }
            let arc = Arc::from_str(elem).map_err(|_| {
                let span = make_span(span, idx..idx + elem.len());
                Error::new(span, "invalid arc (must be [0-9]+)")
            })?;
            oid.try_push(arc).map_err(|err| {
                let span = make_span(span, idx..idx + elem.len());
                Error::new(span, err)
            })?;
            idx += elem.len() + 1;
        }

        if oid.n < 2 {
            return Err(input.error("expected at least two arcs"));
        }

        Ok(oid)
    }
}

fn make_span<R>(span: Span, range: R) -> Span
where
    R: RangeBounds<usize>,
{
    let mut s = Literal::string("");
    s.set_span(span);
    s.subspan(range).unwrap_or(span)
}
