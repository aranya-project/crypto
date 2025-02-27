use proc_macro2::TokenStream;
use quote::quote;
use syn::{Ident, ItemStruct};

pub(crate) fn opaque(
    item: ItemStruct,
    size: usize,
    align: usize,
    libcrypto: &Ident,
) -> TokenStream {
    quote! {
        #[cfg(cbindgen)]
        #[repr(C, align(#align))]
        $vis struct $name {
            /// This field only exists for size purposes. It is
            /// UNDEFINED BEHAVIOR to read from or write to it
            /// after the object has been initialized.
            /// @private
            __for_size_only: [u8; #size],
        }

        #[cfg(not(cbindgen))]
        #item

        const _: () = {
            #libcrypto::const_assert!(
                $size as usize >= ::core::mem::size_of::<$name>(),
                "bug: invalid size:\n",
                " got:", $size as usize, "\n",
                "want: >= ", ::core::mem::size_of::<$name>()
            );
            #libcrypto::const_assert!(
                $size as usize >= ::core::mem::align_of::<$name>(),
                "bug: invalid alignment:\n",
                " got:", $size as usize, "\n",
                "want: >= ", ::core::mem::align_of::<$name>()
            );
        };
    }
}
