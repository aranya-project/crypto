macro_rules! opaque {
    (
        size = $size:expr, align = $align:expr;

        $(#[$meta:meta])*
        $vis:vis struct $name:ident {
            $($t:tt)+
        }
    ) => {
        $(#[$meta])*
        #[cfg(not(cbindgen))]
        $vis struct $name {
            $($t)+
        }

        $(#[$meta])*
        #[cfg(cbindgen)]
        #[repr(C, align($align))]
        $vis struct $name {
            /// This field only exists for size purposes. It is
            /// UNDEFINED BEHAVIOR to read from or write to it
            /// after the object has been initialized.
            /// @private
            __for_size_only: [u8; $size],
        }

        const _: () = {
            $crate::const_fmt::const_assert!(
                $size as usize >= ::core::mem::size_of::<$name>(),
                "bug: invalid size:\n",
                " got:", $size as usize, "\n",
                "want: >= ", ::core::mem::size_of::<$name>()
            );
            $crate::const_fmt::const_assert!(
                $size as usize >= ::core::mem::align_of::<$name>(),
                "bug: invalid alignment:\n",
                " got:", $size as usize, "\n",
                "want: >= ", ::core::mem::align_of::<$name>()
            );
        };
    }
}
pub(crate) use opaque;
