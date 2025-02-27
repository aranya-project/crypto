use core::alloc::Layout;

use proc_macro2::TokenStream;
use quote::quote;
use syn::{parse_quote, Attribute, Ident, ItemStruct, Type};

pub(crate) fn opaque_wrapper(
    ident: Ident,
    inner: Type,
    layout: Layout,
    meta: Vec<Attribute>,
    libcrypto: &Ident,
) -> TokenStream {
    let item = parse_quote! {
        #(#meta)*
        #[repr(transparent)]
        #[non_exhaustive]
        #[allow(non_camel_case_types)]
        pub struct #ident(#inner);
    };
    let def = opaque(item, layout, libcrypto);
    quote! {
        #def

        impl #ident {
            #[allow(dead_code, reason = "Depends on the type")]
            fn as_inner(ptr: *const Self) -> *const #inner {
                ptr.cast()
            }

            #[allow(dead_code, reason = "Depends on the type")]
            fn as_inner_mut(ptr: *mut Self) -> *mut #inner {
                ptr.cast()
            }

            #[allow(dead_code, reason = "Depends on the type")]
            fn as_inner_uninit(ptr: *const ::core::mem::MaybeUninit<Self>) ->
                *const ::core::mem::MaybeUninit<#inner>
            {
                ptr.cast()
            }

            #[allow(dead_code, reason = "Depends on the type")]
            fn as_inner_uninit_mut(ptr: *mut ::core::mem::MaybeUninit<Self>) ->
                *mut ::core::mem::MaybeUninit<#inner>
            {
                ptr.cast()
            }

            #[allow(dead_code, reason = "Depends on the type")]
            fn from_inner(ptr: *const #inner) -> *const Self {
                ptr.cast()
            }
        }
    }
}

fn opaque(item: ItemStruct, layout: Layout, libcrypto: &Ident) -> TokenStream {
    let size = layout.size();
    let align = layout.align();
    let repr_align = syn::LitInt::new(&align.to_string(), proc_macro2::Span::call_site());
    let vis = &item.vis;
    let ident = &item.ident;
    quote! {
        #[cfg(cbindgen)]
        #[repr(C, align(#repr_align))]
        #vis struct #ident {
            /// This field only exists for size purposes. It is
            /// UNDEFINED BEHAVIOR to read from or write to it
            /// after the object has been initialized.
            /// @private
            __for_size_only: [u8; #size],
        }

        #[cfg(not(cbindgen))]
        #item

        #[allow(clippy::absurd_extreme_comparisons)]
        const _: () = {
            #libcrypto::const_assert!(
                #size >= ::core::mem::size_of::<#ident>(),
                "bug: invalid size:\n",
                " got: ", #size, "\n",
                "want: ", ::core::mem::size_of::<#ident>()
            );
            #libcrypto::const_assert!(
                #align >= ::core::mem::align_of::<#ident>(),
                "bug: invalid alignment:\n",
                " got: ", #align, "\n",
                "want: ", ::core::mem::align_of::<#ident>()
            );
        };
    }
}
