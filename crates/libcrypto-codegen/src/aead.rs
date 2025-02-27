use core::{alloc::Layout, cmp};

use proc_macro2::TokenStream;
use quote::{format_ident, quote};
use syn::parse_quote;

use crate::{util::opaque_wrapper, Bindings};

/// An AEAD.
#[derive(Debug)]
pub struct Aead<'a> {
    /// Simple docs.
    pub doc: &'a str,
    /// The constant ident in `spideroak_libcrypto::aead::Aeads`.
    pub name: &'a str,
    /// `EVP_aead_xxx`.
    pub constructor: &'a str,
}

/// All AEADs.
pub const AEADS: &[Aead<'_>] = &[
    Aead {
        doc: "AES-128-GCM",
        name: "AES_128_GCM",
        constructor: "EVP_aead_aes_128_gcm",
    },
    Aead {
        doc: "AES-256-GCM",
        name: "AES_256_GCM",
        constructor: "EVP_aead_aes_256_gcm",
    },
    Aead {
        doc: "AES-128-GCM for TLS 1.3",
        name: "AES_128_GCM_TLS13",
        constructor: "EVP_aead_aes_128_gcm_tls13",
    },
    Aead {
        doc: "AES-256-GCM for TLS 1.3",
        name: "AES_256_GCM_TLS13",
        constructor: "EVP_aead_aes_256_gcm_tls13",
    },
    Aead {
        doc: "ChaCha20-Poly1305",
        name: "CHACHA20_POLY1305",
        constructor: "EVP_aead_chacha20_poly1305",
    },
];

impl Bindings {
    pub(super) fn aead(&self) -> anyhow::Result<TokenStream> {
        let Self {
            libcrypto,
            max_aead_size,
            max_aead_align,
        } = self;

        let aeads_impl = format_ident!("__AeadsImpl");

        let aeads = AEADS.iter().map(|aead| {
            let Aead {
                doc,
                name,
                constructor,
            } = aead;
            let name = format_ident!("{}", name);
            let constructor = format_ident!("{}", constructor);
            quote! {
                #[doc = #doc]
                ///
                /// Returns `NULL` if the AEAD is not
                /// supported.
                #[no_mangle]
                pub extern "C" fn #constructor() -> *const EVP_AEAD {
                    let ptr = match <#aeads_impl as #libcrypto::aead::Aeads>::#name {
                        Some(v) => ::core::ptr::from_ref(v),
                        None => return ::core::ptr::null(),
                    };
                    EVP_AEAD::from_inner(ptr)
                }
            }
        });

        let engine = opaque_wrapper(
            format_ident!("ENGINE"),
            parse_quote!(#libcrypto::aead::ENGINE),
            Layout::from_size_align(16, 8)?,
            parse_quote! {
                /// Unused.
                #[derive(Copy, Clone, Debug)]
            },
            libcrypto,
        );

        let evp_aead = opaque_wrapper(
            format_ident!("EVP_AEAD"),
            parse_quote!(#libcrypto::aead::EVP_AEAD),
            Layout::from_size_align(120, 16)?,
            parse_quote! {
                /// A specific AEAD algorithm.
                ///
                /// It is safe for concurrent use.
                #[derive(Clone, Debug)]
            },
            libcrypto,
        );

        let evp_aead_ctx = opaque_wrapper(
            format_ident!("EVP_AEAD_CTX"),
            parse_quote!(#libcrypto::aead::EVP_AEAD_CTX<#aeads_impl>),
            Layout::from_size_align(8 + max_aead_size, cmp::max(16, *max_aead_align))?,
            parse_quote! {
                /// An AEAD instance.
                ///
                /// It must be initialized with
                /// [`EVP_AEAD_CTX_init`] before it can be used.
                #[derive(Default, Debug)]
            },
            libcrypto,
        );

        let code = quote! {
            #engine

            #evp_aead

            /// Returns the size in bytes of the key used by
            /// `aead`.
            #[no_mangle]
            pub extern "C" fn EVP_AEAD_key_length(aead: &EVP_AEAD) -> usize {
                aead.0.key_length()
            }

            /// Returns the size in bytes of the nonce used by
            /// `aead`.
            #[no_mangle]
            pub extern "C" fn EVP_AEAD_nonce_length(aead: &EVP_AEAD) -> usize {
                aead.0.nonce_length()
            }

            /// Returns the size in bytes of `aead`'s
            /// authentication overhead.
            #[no_mangle]
            pub extern "C" fn EVP_AEAD_max_overhead(aead: &EVP_AEAD) -> usize {
                aead.0.max_overhead()
            }

            /// Returns the size in bytes of `aead`'s
            /// authentication overhead.
            #[no_mangle]
            pub extern "C" fn EVP_AEAD_max_tag_len(aead: &EVP_AEAD) -> usize {
                aead.0.max_tag_len()
            }

            #(#aeads)*

            #evp_aead_ctx

            /// Sets an uninitialized `ctx` to all zeros. This is
            /// equivalent to
            ///
            /// ```c
            /// EVP_AEAD_CTX ctx;
            /// memset(&ctx, 0, sizeof(ctx))
            /// ```
            ///
            /// but is more explicit.
            ///
            /// `ctx` must still be initialized with
            /// [`EVP_AEAD_CTX_init`] before use.
            ///
            /// It is safe to call [`EVP_AEAD_CTX_cleanup`] after
            /// calling this routine.
            ///
            /// # Safety
            ///
            /// - You must uphold Rust's aliasing requirements.
            #[no_mangle]
            pub unsafe extern "C" fn EVP_AEAD_CTX_zero(
                ctx: *mut ::core::mem::MaybeUninit<EVP_AEAD_CTX>,
            ) {
                let ctx = EVP_AEAD_CTX::as_inner_uninit_mut(ctx);

                // SAFETY: See the function's safety docs.
                unsafe { #libcrypto::aead::evp_aead_ctx_zero(ctx) }
            }

            /// Initializes `ctx` for the given AEAD algorithm.
            ///
            /// - `key_len` must match
            ///   [`EVP_AEAD_key_len(aead)`].
            /// - If non-zero, `tag_len` must match
            ///   [`EVP_AEAD_tag_len(aead)`].
            /// - `impl_` must be null.
            ///
            /// It returns 1 on success and 0 otherwise. It is
            /// safe to call [`EVP_AEAD_CTX_cleanup`] on error.
            ///
            /// # Safety
            ///
            /// - `ctx`, `aead`, and `key` must be non-null and
            ///   suitably aligned.
            /// - `key` must be valid for reads up to `key_len`
            ///   bytes.
            /// - `key_len` must be less than or equal to
            ///   [`isize::MAX`].
            #[no_mangle]
            pub unsafe extern "C" fn EVP_AEAD_CTX_init(
                ctx: *mut ::core::mem::MaybeUninit<EVP_AEAD_CTX>,
                aead: *const EVP_AEAD,
                key: *const u8,
                key_len: usize,
                tag_len: usize,
                impl_: *const ::core::mem::MaybeUninit<ENGINE>,
            ) -> ::core::ffi::c_int {
                let ctx = EVP_AEAD_CTX::as_inner_uninit_mut(ctx);
                let aead = EVP_AEAD::as_inner(aead);
                let impl_ = ENGINE::as_inner_uninit(impl_);

                // SAFETY: See the function's safety docs.
                let result = unsafe {
                    #libcrypto::aead::evp_aead_ctx_init(
                        ctx,
                        aead,
                        key,
                        key_len,
                        tag_len,
                        impl_,
                    )
                };
                if result.is_ok() {
                    1
                } else {
                    0
                }
            }

            /// Frees all resources used by `ctx`.
            ///
            /// # Safety
            ///
            /// - If non-null, `ctx` must have been initialized
            ///   with [`EVP_AEAD_CTX_init`].
            #[no_mangle]
            pub unsafe extern "C" fn EVP_AEAD_CTX_cleanup(
                ctx: *mut EVP_AEAD_CTX,
            ) {
                let ctx = EVP_AEAD_CTX::as_inner_mut(ctx);

                // SAFETY: See the function's safety docs.
                unsafe { #libcrypto::aead::evp_aead_ctx_cleanup(ctx) }
            }

            /// Encrypts and authenticates `in_len` bytes from
            /// `in_`, authenticates `ad_len` bytes from `ad`,
            /// and writes the resulting ciphertext to `out`.
            ///
            /// At most `max_out_len` bytes are written to `out`.
            /// On success, `out_len` is updated with the number
            /// of bytes written to `out`.
            ///
            /// It returns 1 on success and 0 otherwise.
            ///
            /// - `max_out_len` must be at least `in_len` plus
            ///   the result of [`EVP_AEAD_max_overhead`].
            /// - `nonce_len` must be equal to the result of
            ///   [`EVP_AEAD_nonce_length`].
            /// - If `nonce_len` is zero, `nonce` must be null.
            /// - If `in_` is null, `in_len` must be zero.
            /// - If `in_` is non-null, `in_len` must be non-zero.
            /// - If `ad` is null, `ad_len` must be zero.
            /// - If `ad` is non-null, `ad_len` must be non-zero.
            /// - `out` and `in_` must overlap entirely or not at
            ///   all.
            ///
            /// # Safety
            ///
            /// - `ctx` and `out_len` must be non-null and
            ///   suitably aligned.
            /// - If non-null, all other pointers must be
            ///   suitably aligned.
            /// - If non-null, `out` must be valid for writes up
            ///   to `max_out_len` bytes.
            /// - `max_out_len` must be at most `isize::MAX`.
            /// - If non-null, `nonce` must be valid for reads up
            ///   to `nonce_len` bytes.
            /// - `nonce_len` must be at most `isize::MAX`.
            /// - If non-null, `in_` must be valid for reads up
            ///   to `in_len` bytes.
            /// - `in_len` must be at most `isize::MAX`.
            /// - If non-null `ad` must be valid for reads up to
            ///   `ad_len` bytes.
            /// - `ad_len` must be at most `isize::MAX`.
            #[no_mangle]
            pub unsafe extern "C" fn EVP_AEAD_CTX_seal(
                ctx: *const EVP_AEAD_CTX,
                out: *mut u8,
                out_len: *mut ::core::mem::MaybeUninit<usize>,
                max_out_len: usize,
                nonce: *const u8,
                nonce_len: usize,
                in_: *const u8,
                in_len: usize,
                ad: *const u8,
                ad_len: usize,
            ) -> ::core::ffi::c_int {
                let ctx = EVP_AEAD_CTX::as_inner(ctx);

                // SAFETY: See the function's safety docs.
                let result = unsafe {
                    #libcrypto::aead::evp_aead_ctx_seal(
                        ctx,
                        out,
                        out_len,
                        max_out_len,
                        nonce,
                        nonce_len,
                        in_,
                        in_len,
                        ad,
                        ad_len,
                    )
                };
                if result.is_ok() {
                    1
                } else {
                    0
                }
            }

            /// Decrypts and authenticates `in_len` bytes from
            /// `in_`, authenticates `ad_len` bytes from `ad`,
            /// and writes the resulting plaintext to `out`.
            ///
            /// At most `max_out_len` bytes are written to `out`.
            /// On success, `out_len` is updated with the number
            /// of bytes written to `out`.
            ///
            /// It returns 1 on success and 0 otherwise.
            ///
            /// - `max_out_len` must be at least `in_len` less
            ///   the result of [`EVP_AEAD_max_overhead`].
            /// - `nonce_len` must be equal to the result of
            ///   [`EVP_AEAD_nonce_length`].
            /// - If `nonce_len` is zero, `nonce` must be null.
            /// - If `in_` is null, `in_len` must be zero.
            /// - If `in_` is non-null, `in_len` must be non-zero.
            /// - If `ad` is null, `ad_len` must be zero.
            /// - If `ad` is non-null, `ad_len` must be non-zero.
            /// - `out` and `in_` must overlap entirely or not at
            ///   all.
            ///
            /// # Safety
            ///
            /// - `ctx` and `out_len` must be non-null and
            ///   suitably aligned.
            /// - If non-null, all other pointers must be
            ///   suitably aligned.
            /// - If non-null, `out` must be valid for writes up
            ///   to `max_out_len` bytes.
            /// - `max_out_len` must be at most `isize::MAX`.
            /// - If non-null, `nonce` must be valid for reads up
            ///   to `nonce_len` bytes.
            /// - `nonce_len` must be at most `isize::MAX`.
            /// - If non-null, `in_` must be valid for reads up
            ///   to `in_len` bytes.
            /// - `in_len` must be at most `isize::MAX`.
            /// - If non-null `ad` must be valid for reads up to
            ///   `ad_len` bytes.
            /// - `ad_len` must be at most `isize::MAX`.
            #[no_mangle]
            pub unsafe extern "C" fn EVP_AEAD_CTX_open(
                ctx: *const EVP_AEAD_CTX,
                out: *mut u8,
                out_len: *mut ::core::mem::MaybeUninit<usize>,
                max_out_len: usize,
                nonce: *const u8,
                nonce_len: usize,
                in_: *const u8,
                in_len: usize,
                ad: *const u8,
                ad_len: usize,
            ) -> ::core::ffi::c_int {
                let ctx = EVP_AEAD_CTX::as_inner(ctx);

                // SAFETY: See the function's safety docs.
                let result = unsafe {
                    #libcrypto::aead::evp_aead_ctx_open(
                        ctx,
                        out,
                        out_len,
                        max_out_len,
                        nonce,
                        nonce_len,
                        in_,
                        in_len,
                        ad,
                        ad_len,
                    )
                };
                if result.is_ok() {
                    1
                } else {
                    0
                }
            }
        };
        Ok(code)
    }
}
