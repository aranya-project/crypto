use proc_macro2::TokenStream;
use quote::{format_ident, quote};

use super::builder::Builder;

/// An AEAD.
#[derive(Debug)]
pub struct Aead<'a> {
    /// The algorithm name.
    pub name: &'a str,
    /// `EVP_aead_xxx`.
    pub constructor: &'a str,
}

/// All AEADs.
pub const AEADS: &[Aead<'_>] = &[
    Aead {
        name: "AES-128-GCM",
        constructor: "EVP_aead_aes_128_gcm",
    },
    Aead {
        name: "AES-256-GCM",
        constructor: "EVP_aead_aes_256_gcm",
    },
    Aead {
        name: "AES-128-GCM for TLS 1.3",
        constructor: "EVP_aead_aes_128_gcm_tls13",
    },
    Aead {
        name: "AES-256-GCM for TLS 1.3",
        constructor: "EVP_aead_aes_256_gcm_tls13",
    },
    Aead {
        name: "Chacha20-Poly1305",
        constructor: "EVP_aead_chacha20_poly1305",
    },
];

impl Builder {
    pub(super) fn aeads(&self) -> TokenStream {
        let libcrypto = &self.libcrypto;

        let known_aeads = AEADS.iter().map(|aead| {
            let constructor = format_ident!("{}", aead.constructor);
            quote! { #constructor() }
        });
        let aeads = AEADS.iter().map(|aead| {
            let Aead { name, constructor } = aead;
            let statik = format_ident!("__static_{}", constructor);
            let constructor = format_ident!("{}", constructor);
            quote! {
                #[doc = #name]
                ///
                /// Returns `NULL` if the AEAD is not
                /// supported.
                #[no_mangle]
                pub extern "C" fn #constructor() -> *const EVP_AEAD {
                    match #statik {
                        Some(v) => ptr::from_ref(v),
                        None => ptr::null(),
                    }
                }
            }
        });

        quote! {
            use core::{
                alloc::Layout,
                ffi::c_int,
                mem::{ManuallyDrop, MaybeUninit},
                ptr,
            };

            use #libcrypto::{
                buggy::{bug, Bug},
                error::{invalid_arg, Error},
                spideroak_crypto::{
                    aead::{Aead, BufferTooSmallError, InvalidNonceSize, OpenError, SealError},
                    import::{Import, ImportError},
                    zeroize::Zeroize,
                },
                try_from_raw_parts, try_from_raw_parts_mut,
                try_ptr_as_mut, try_ptr_as_ref,
                util::{any_overlap, inexact_overlap, less_or_eq, pedantic_slice_checks},
            };

            /// Unused.
            /// cbindgen:no-export
            #[repr(C)]
            #[non_exhaustive]
            #[derive(Debug)]
            pub struct ENGINE {}

            #libcrypto::opaque! { size = 112, align = 16;
            /// A specific AEAD algorithm.
            ///
            /// It is safe for concurrent use.
            #[repr(C)]
            #[non_exhaustive]
            #[derive(Clone, Debug)]
            pub struct EVP_AEAD {
                /// See [`Aead::KEY_SIZE`].
                key_len: usize,
                /// See [`Aead::NONCE_SIZE`].
                nonce_len: usize,
                /// See [`Aead::OVERHEAD`].
                overhead: usize,
                /// See [`Aead::MAX_PLAINTEXT_SIZE`].
                p_max: u64,
                /// See [`Aead::MAX_CIPHERTEXT_SIZE`].
                c_max: u64,
                /// See [`Aead::MAX_ADDITIONAL_DATA_SIZE`].
                a_max: u64,

                /// The memory layout of the `Aead`.
                layout: Layout,

                /// Initializes `ctx.inner` with [`Aead::new`].
                init: fn(ctx: &mut EVP_AEAD_CTX, key: &[u8]) -> Result<(), ImportError>,

                /// Frees the allocated data.
                ///
                /// # Safety
                ///
                /// - `ctx` must be initialized.
                cleanup: unsafe fn(ctx: &mut EVP_AEAD_CTX),

                /// [`Aead::seal`].
                ///
                /// # Safety
                ///
                /// - `ctx` must be initialized.
                #[allow(clippy::type_complexity)]
                seal: unsafe fn(
                    ctx: &EVP_AEAD_CTX,
                    dst: &mut [u8],
                    nonce: &[u8],
                    plaintext: &[u8],
                    additional_data: &[u8],
                ) -> Result<(), SealError>,

                /// [`Aead::seal_in_place`].
                ///
                /// # Safety
                ///
                /// - `ctx` must be initialized.
                #[allow(clippy::type_complexity)]
                seal_in_place: unsafe fn(
                    ctx: &EVP_AEAD_CTX,
                    nonce: &[u8],
                    data: &mut [u8],
                    overhead: &mut [u8],
                    additional_data: &[u8],
                ) -> Result<(), SealError>,

                /// [`Aead::open`].
                ///
                /// # Safety
                ///
                /// - `ctx` must be initialized.
                #[allow(clippy::type_complexity)]
                open: unsafe fn(
                    ctx: &EVP_AEAD_CTX,
                    dst: &mut [u8],
                    nonce: &[u8],
                    ciphertext: &[u8],
                    additional_data: &[u8],
                ) -> Result<(), OpenError>,

                /// [`Aead::open_in_place`].
                ///
                /// # Safety
                ///
                /// - `ctx` must be initialized.
                #[allow(clippy::type_complexity)]
                open_in_place: unsafe fn(
                    ctx: &EVP_AEAD_CTX,
                    nonce: &[u8],
                    data: &mut [u8],
                    overhead: &mut [u8],
                    additional_data: &[u8],
                ) -> Result<(), OpenError>,
            }
            }

            impl EVP_AEAD {
                #[doc(hidden)]
                pub const fn new<A: Aead>() -> Self {
                    // TODO
                    const {
                        assert!(
                            size_of::<EVP_AEAD_CTX>() >= size_of::<EvpAeadCtx<A>>(),
                            "bug: invalid size"
                        );
                        assert!(
                            align_of::<EVP_AEAD_CTX>() >= align_of::<EvpAeadCtx<A>>(),
                            "bug: invalid alignment"
                        );
                    }

                    Self {
                        key_len: A::KEY_SIZE,
                        nonce_len: A::NONCE_SIZE,
                        overhead: A::OVERHEAD,
                        p_max: A::MAX_PLAINTEXT_SIZE,
                        c_max: A::MAX_CIPHERTEXT_SIZE,
                        a_max: A::MAX_ADDITIONAL_DATA_SIZE,
                        layout: Layout::new::<A>(),
                        init: |ctx, key| {
                            let key = <A::Key as Import<_>>::import(key)?;
                            let aead = A::new(&key);

                            // SAFETY:
                            // - We checked at compile time that
                            //   `EvpAeadCtx<A>` has at least the
                            //   same size and alignment as
                            //   `EVP_AEAD_CTX`.
                            let ctx = unsafe { &mut *(ctx as *mut EVP_AEAD_CTX).cast::<EvpAeadCtx<A>>() };
                            ctx.inner.write(InnerAead {
                                aead: ManuallyDrop::new(aead),
                            });

                            Ok(())
                        },
                        cleanup: |ctx| {
                            // SAFETY:
                            // - We checked at compile time that
                            //   `EvpAeadCtx<A>` has at least the
                            //   same size and alignment as
                            //   `EVP_AEAD_CTX`.
                            let ctx = unsafe { &mut *(ctx as *mut EVP_AEAD_CTX).cast::<EvpAeadCtx<A>>() };
                            // SAFETY: See the function pointer's
                            // safety docs.
                            let inner = unsafe { ctx.inner.assume_init_mut() };
                            // SAFETY: We have to trust that the
                            // caller does not assume that
                            // `self.inner` is initialized after
                            // this point.
                            unsafe { ManuallyDrop::drop(&mut inner.aead) }

                            // Clobber `self.inner` in case `A`
                            // isn't `ZeroizeOnDrop`.
                            //
                            // NB: This is safe because we are
                            // not assuming that `self.inner` is
                            // initialized.
                            ctx.inner.zeroize();
                        },
                        seal: |ctx, dst, nonce, plaintext, additional_data| {
                            // SAFETY: See the function pointer's
                            // safety docs.
                            let aead = unsafe { ctx.get_inner::<A>()? };
                            aead.seal(dst, nonce, plaintext, additional_data)
                        },
                        seal_in_place: |ctx, nonce, data, overhead, additional_data| {
                            // SAFETY: See the function pointer's
                            // safety docs.
                            let aead = unsafe { ctx.get_inner::<A>()? };
                            aead.seal_in_place(nonce, data, overhead, additional_data)
                        },
                        open: |ctx, dst, nonce, plaintext, additional_data| {
                            // SAFETY: See the function pointer's
                            // safety docs.
                            let aead = unsafe { ctx.get_inner::<A>()? };
                            aead.open(dst, nonce, plaintext, additional_data)
                        },
                        open_in_place: |ctx, nonce, data, overhead, additional_data| {
                            // SAFETY: See the function pointer's
                            // safety docs.
                            let aead = unsafe { ctx.get_inner::<A>()? };
                            aead.open_in_place(nonce, data, overhead, additional_data)
                        },
                    }
                }
            }

            /// Returns the size in bytes of the key used by
            /// `aead`.
            #[no_mangle]
            pub extern "C" fn EVP_AEAD_key_length(aead: &EVP_AEAD) -> usize {
                aead.key_len
            }

            /// Returns the size in bytes of the nonce used by
            /// `aead`.
            #[no_mangle]
            pub extern "C" fn EVP_AEAD_nonce_length(aead: &EVP_AEAD) -> usize {
                aead.nonce_len
            }

            /// Returns the size in bytes of `aead`'s
            /// authentication overhead.
            #[no_mangle]
            pub extern "C" fn EVP_AEAD_max_overhead(aead: &EVP_AEAD) -> usize {
                aead.overhead
            }

            /// Returns the size in bytes of `aead`'s
            /// authentication overhead.
            #[no_mangle]
            pub extern "C" fn EVP_AEAD_max_tag_len(aead: &EVP_AEAD) -> usize {
                aead.overhead
            }

            #(#aeads)*

            /// Is this a known [`EVP_AEAD`]?
            #[inline]
            fn is_known_aead(aead: *const EVP_AEAD) -> bool {
                #(aead == #known_aeads )||*
            }

            /// The size in bytes of [`EVP_AEAD_CTX`].
            pub const EVP_AEAD_CTX_SIZE: usize = 8 + MAX_AEAD_SIZE;

            /// The alignment in bytes of [`EVP_AEAD_CTX`].
            pub const EVP_AEAD_CTX_ALIGN: usize = MAX_AEAD_ALIGN;

            #libcrypto::opaque! { size = EVP_AEAD_CTX_SIZE, align = EVP_AEAD_CTX_ALIGN;
            /// An AEAD instance.
            ///
            /// It must be initialized with [`EVP_AEAD_CTX_init`]
            /// before it can be used.
            #[repr(C)]
            #[non_exhaustive]
            #[derive(Debug)]
            pub struct EVP_AEAD_CTX {
                /// The AEAD algorithm.
                ///
                /// The [NPO] guarantees that this is safe to use
                /// with zeroed memory.
                ///
                /// [NPO]: https://doc.rust-lang.org/std/option/index.html#representation
                aead: Option<&'static EVP_AEAD>,

                /// The `Aead` instance.
                ///
                /// This is actually `MaybeUninit<InnerAead<A>>`
                /// where `A: Aead`.
                ///
                /// If `self.aead` is `Some`, then this field is
                /// initialized.
                ///
                /// # Caveats
                ///
                /// It is obviously very easy for C code to
                /// corrupt memory, so this is a best-effort
                /// attempt. We can't control what other
                /// languages do to violate Rust's invariants.
                inner: MaybeUninit<[u8; MAX_AEAD_SIZE]>,
            }
            }

            impl EVP_AEAD_CTX {
                /// Returns the underlying [`Aead`], or
                /// [`Err(Bug)`] if `self` is not initialized.
                ///
                /// # Safety
                ///
                /// - `self` must be initialized.
                unsafe fn get_inner<A>(&self) -> Result<&A, Bug> {
                    if self.aead.is_none() {
                        bug!("`EVP_AEAD_CTX` is not initialized");
                    };
                    let inner = {
                        let ptr = ptr::addr_of!(self.inner).cast::<MaybeUninit<InnerAead<A>>>();
                        // SAFETY: The FFI caller is responsible
                        // for ensuring that `*self` is large
                        // enough. See also this method's safety
                        // docs.
                        unsafe { (&*ptr).assume_init_ref() }
                    };
                    // SAFETY: See the method's safety docs.
                    let aead = unsafe { &*inner.aead };
                    Ok(aead)
                }

                fn init(&mut self, aead: &'static EVP_AEAD, key: &[u8]) -> Result<(), ImportError> {
                    self.aead = Some(aead);
                    (aead.init)(self, key)
                }

                fn cleanup(&mut self) -> Result<(), Bug> {
                    let Some(aead) = self.aead.take() else {
                        bug!("`EVP_AEAD_CTX` is not initialized");
                    };
                    // SAFETY:
                    // - `self.aead` is (was) `Some`, so
                    //   `self.inner` is initialized (see
                    //   `self.inner`'s docs for caveats).
                    unsafe { (aead.cleanup)(self) }
                    Ok(())
                }

                fn seal(
                    &self,
                    dst: &mut [u8],
                    nonce: &[u8],
                    plaintext: &[u8],
                    additional_data: &[u8],
                ) -> Result<(), SealError> {
                    let Some(aead) = self.aead else {
                        bug!("`EVP_AEAD_CTX` is not initialized");
                    };
                    // SAFETY:
                    // - `self.aead` is `Some`, so `self.inner`
                    //   is initialized (see `self.inner`'s docs
                    //   for caveats).
                    unsafe { (aead.seal)(self, dst, nonce, plaintext, additional_data) }
                }

                fn seal_in_place(
                    &self,
                    nonce: &[u8],
                    data: &mut [u8],
                    overhead: &mut [u8],
                    additional_data: &[u8],
                ) -> Result<(), SealError> {
                    let Some(aead) = self.aead else {
                        bug!("`EVP_AEAD_CTX` is not initialized");
                    };
                    // SAFETY:
                    // - `self.aead` is `Some`, so `self.inner`
                    //   is initialized (see `self.inner`'s docs
                    //   for caveats).
                    unsafe { (aead.seal_in_place)(self, nonce, data, overhead, additional_data) }
                }

                fn open(
                    &self,
                    dst: &mut [u8],
                    nonce: &[u8],
                    ciphertext: &[u8],
                    additional_data: &[u8],
                ) -> Result<(), OpenError> {
                    let Some(aead) = self.aead else {
                        bug!("`EVP_AEAD_CTX` is not initialized");
                    };
                    // SAFETY:
                    // - `self.aead` is `Some`, so `self.inner`
                    //   is initialized (see `self.inner`'s docs
                    //   for caveats).
                    unsafe { (aead.open)(self, dst, nonce, ciphertext, additional_data) }
                }

                fn open_in_place(
                    &self,
                    nonce: &[u8],
                    data: &mut [u8],
                    overhead: &mut [u8],
                    additional_data: &[u8],
                ) -> Result<(), OpenError> {
                    let Some(aead) = self.aead else {
                        bug!("`EVP_AEAD_CTX` is not initialized");
                    };
                    // SAFETY:
                    // - `self.aead` is `Some`, so `self.inner`
                    //   is initialized (see `self.inner`'s docs
                    //   for caveats).
                    unsafe { (aead.open_in_place)(self, nonce, data, overhead, additional_data) }
                }
            }

            impl Default for EVP_AEAD_CTX {
                #[inline]
                fn default() -> Self {
                    Self {
                        aead: None,
                        inner: MaybeUninit::uninit(),
                    }
                }
            }

            /// Used when reading/writing to
            /// [`EVP_AEAD_CTX.inner`].
            #[doc(hidden)]
            #[repr(C)]
            #[non_exhaustive]
            #[derive(Debug)]
            struct EvpAeadCtx<A> {
                /// The AEAD algorithm.
                ///
                /// The [NPO] guarantees that this is safe to use
                /// with zeroed memory.
                ///
                /// [NPO]: https://doc.rust-lang.org/std/option/index.html#representation
                aead: Option<&'static EVP_AEAD>,
                /// The `Aead` instance.
                ///
                /// If `self.aead` is `Some`, then this field is
                /// initialized.
                ///
                /// # Caveats
                ///
                /// It is obviously very easy for C code to
                /// corrupt memory, so this is a best-effort
                /// attempt. We can't control what other
                /// languages do to violate Rust's invariants.
                inner: MaybeUninit<InnerAead<A>>,
            }

            impl<A> Default for EvpAeadCtx<A> {
                #[inline]
                fn default() -> Self {
                    Self {
                        aead: None,
                        inner: MaybeUninit::uninit(),
                    }
                }
            }

            #[repr(C)]
            union InnerAead<A> {
                aead: ManuallyDrop<A>,
                _buf: [u8; MAX_AEAD_SIZE],
            }

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
            pub unsafe extern "C" fn EVP_AEAD_CTX_zero(ctx: *mut MaybeUninit<EVP_AEAD_CTX>) {
                // SAFETY:
                // - We have to trust that the caller upholds
                //   Rust's aliasing requirements.
                let Ok(ctx) = try_ptr_as_mut!(@unsafe ctx) else {
                    return;
                };
                ctx.write(EVP_AEAD_CTX::default());
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
                ctx: *mut MaybeUninit<EVP_AEAD_CTX>,
                aead: *const EVP_AEAD,
                key: *const u8,
                key_len: usize,
                tag_len: usize,
                impl_: *const MaybeUninit<ENGINE>,
            ) -> c_int {
                if evp_aead_ctx_init(ctx, aead, key, key_len, tag_len, impl_).is_ok() {
                    1
                } else {
                    0
                }
            }

            fn evp_aead_ctx_init(
                ctx: *mut MaybeUninit<EVP_AEAD_CTX>,
                aead: *const EVP_AEAD,
                key: *const u8,
                key_len: usize,
                tag_len: usize,
                impl_: *const MaybeUninit<ENGINE>,
            ) -> Result<(), Error> {
                // Ensure that `ctx` is valid even if we return
                // an error.
                //
                // SAFETY:
                // - We have to trust that the caller upholds
                //   Rust's aliasing requirements.
                let ctx = try_ptr_as_mut!(@unsafe ctx)?.write(EVP_AEAD_CTX::default());

                if !aead.is_null() && !is_known_aead(aead) {
                    return Err(invalid_arg("aead", "unknown `EVP_AEAD`"));
                }

                // SAFETY:
                // - We have to trust that the caller upholds
                //   Rust's aliasing requirements.
                // - We have to trust that the caller initialized
                //   `aead`.
                let aead = try_ptr_as_ref!(@unsafe aead)?;

                let key = {
                    if key_len != aead.key_len {
                        return Err(invalid_arg("key_len", "invalid key length"));
                    }
                    // SAFETY:
                    // - We have to trust that the caller has
                    //   initialized `nonce`.
                    // - We have to trust that `nonce` is valid
                    //   for reads up to `nonce_len` bytes.
                    // - We checked that `nonce` does not alias
                    //   `out`, but we still have to trust that
                    //   the caller upholds Rust's aliasing
                    //   requirements for any other uses of
                    //   `nonce`.
                    try_from_raw_parts!(@unsafe key,key_len)?
                };

                if !impl_.is_null() {
                    return Err(invalid_arg("impl_", "pointer must be null"));
                }

                if tag_len != 0 && tag_len != aead.overhead {
                    return Err(invalid_arg("tag_len", "invalid tag length"));
                }

                ctx.init(aead, key)
                    .map_err(|_| "unable to initialize `Aead`")?;

                Ok(())
            }

            /// Frees all resources used by `ctx`.
            ///
            /// # Safety
            ///
            /// - If non-null, `ctx` must have been initialized
            ///   with [`EVP_AEAD_CTX_init`].
            #[no_mangle]
            pub unsafe extern "C" fn EVP_AEAD_CTX_cleanup(ctx: *mut EVP_AEAD_CTX) {
                // SAFETY:
                // - We have to trust that the caller upholds
                //   Rust's aliasing requirements.
                // - We have to trust that the caller initialized
                //   `ctx`.
                let Ok(ctx) = try_ptr_as_mut!(@unsafe ctx) else {
                    return;
                };
                // Not much we can do here. Plus, `buggy` calls
                // `unreachable!` in debug mode for us.
                let _ = ctx.cleanup();
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
                out_len: *mut MaybeUninit<usize>,
                max_out_len: usize,
                nonce: *const u8,
                nonce_len: usize,
                in_: *const u8,
                in_len: usize,
                ad: *const u8,
                ad_len: usize,
            ) -> c_int {
                if evp_aead_ctx_seal(
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
                .is_ok()
                {
                    1
                } else {
                    0
                }
            }

            #[allow(clippy::too_many_arguments, reason = "I didn't come up with the API")]
            fn evp_aead_ctx_seal(
                ctx: *const EVP_AEAD_CTX,
                out: *mut u8,
                out_len: *mut MaybeUninit<usize>,
                max_out_len: usize,
                nonce: *const u8,
                nonce_len: usize,
                in_: *const u8,
                in_len: usize,
                ad: *const u8,
                ad_len: usize,
            ) -> Result<(), Error> {
                // SAFETY:
                // - We have to trust that the caller upholds
                //   Rust's aliasing requirements.
                // - We have to trust that the caller initialized
                //   `ctx`.
                let ctx = try_ptr_as_ref!(@unsafe ctx)?;

                let Some(aead) = ctx.aead else {
                    return Err(invalid_arg("ctx", "not initialized"));
                };

                // Sanity check `out`, but don't convert it to
                // a slice yet because it might alias `in_`.
                pedantic_slice_checks(out, max_out_len).map_err(|msg| invalid_arg("out, max_out_len", msg))?;

                // SAFETY:
                // - We have to trust that the caller upholds
                //   Rust's aliasing requirements.
                let out_len = try_ptr_as_mut!(@unsafe out_len)?;

                let nonce = {
                    if any_overlap(out, max_out_len, nonce, nonce_len) {
                        return Err(invalid_arg("nonce", "cannot overlap with `out`"));
                    }
                    if nonce_len != aead.nonce_len {
                        return Err(SealError::InvalidNonceSize(InvalidNonceSize).into());
                    }
                    // SAFETY:
                    // - We have to trust that the caller has
                    //   initialized `nonce`.
                    // - We have to trust that `nonce` is valid
                    //   for reads up to `nonce_len` bytes.
                    // - We checked that `nonce` does not alias
                    //   `out`, but we still have to trust that
                    //   the caller upholds Rust's aliasing
                    //   requirements for any other uses of
                    //   `nonce`.
                    try_from_raw_parts!(@unsafe nonce, nonce_len)?
                };

                if !less_or_eq(in_len, aead.p_max) {
                    return Err(SealError::PlaintextTooLong.into());
                }
                // Sanity check `in_`, but don't convert it to
                // a slice yet because it might alias `out`.
                pedantic_slice_checks(in_, in_len).map_err(|msg| invalid_arg("in_, in_len", msg))?;

                let additional_data = {
                    if any_overlap(out, max_out_len, ad, ad_len) {
                        return Err(invalid_arg("ad", "cannot overlap with `out`"));
                    }
                    if !less_or_eq(ad_len, aead.a_max) {
                        return Err(SealError::AdditionalDataTooLong.into());
                    }
                    // SAFETY:
                    // - We have to trust that the caller has
                    //   initialized `ad`.
                    // - We have to trust that `ad` is valid for
                    //   reads up to `ad_len` bytes.
                    // - We checked that `ad` does not alias
                    //   `out`, but we still have to trust that
                    //   the caller upholds Rust's aliasing
                    //   requirements for any other uses of
                    //   `nonce`.
                    try_from_raw_parts!(@unsafe ad, ad_len)?
                };

                if inexact_overlap(in_, in_len, out, max_out_len) {
                    return Err(invalid_arg(
                        "in_, out",
                        "must overlap entirely or not at all",
                    ));
                }

                // The number of bytes written to `out`.
                //
                // Given
                //   in_len <= p_max
                //   p_max = c_max - overhead
                // this addition can only overflow if `usize` is
                // tiny.
                let Some(nw) = in_len.checked_add(aead.overhead) else {
                    return Err(SealError::Other("`in_` too large").into());
                };

                // SAFETY:
                // - We have to trust that `out` is valid for
                //   reads up to `max_out_len` bytes.
                // - We have to trust that the caller upholds
                //   Rust's aliasing requirements for any other
                //   uses of `out`.
                let out = try_from_raw_parts_mut!(@unsafe out, max_out_len)?;
                if out.len() < nw {
                    return Err(SealError::BufferTooSmall(BufferTooSmallError(Some(aead.overhead))).into());
                }

                if in_ == out.as_ptr() {
                    let (data, overhead) = out.split_at_mut(nw);
                    ctx.seal_in_place(nonce, data, overhead, additional_data)?;
                } else {
                    // SAFETY:
                    // - We have to trust that `in_` is valid for
                    //   reads up to `in_len` bytes.
                    // - We checked that `in_` does not alias
                    //   `out_`, but we still have to trust that
                    //   the caller upholds Rust's aliasing
                    //   requirements for any other uses of
                    //   `in_`.
                    let plaintext = try_from_raw_parts!(@unsafe in_, in_len)?;
                    ctx.seal(out, nonce, plaintext, additional_data)?;
                }

                out_len.write(nw);

                Ok(())
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
                out_len: *mut MaybeUninit<usize>,
                max_out_len: usize,
                nonce: *const u8,
                nonce_len: usize,
                in_: *const u8,
                in_len: usize,
                ad: *const u8,
                ad_len: usize,
            ) -> c_int {
                if evp_aead_ctx_open(
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
                .is_ok()
                {
                    1
                } else {
                    0
                }
            }

            #[allow(clippy::too_many_arguments, reason = "I didn't come up with the API")]
            fn evp_aead_ctx_open(
                ctx: *const EVP_AEAD_CTX,
                out: *mut u8,
                out_len: *mut MaybeUninit<usize>,
                max_out_len: usize,
                nonce: *const u8,
                nonce_len: usize,
                in_: *const u8,
                in_len: usize,
                ad: *const u8,
                ad_len: usize,
            ) -> Result<(), Error> {
                // SAFETY:
                // - We have to trust that the caller upholds
                //   Rust's aliasing requirements.
                // - We have to trust that the caller initialized
                //   `ctx`.
                let ctx = try_ptr_as_ref!(@unsafe ctx)?;

                let Some(aead) = ctx.aead else {
                    return Err(invalid_arg("ctx", "not initialized"));
                };

                // Sanity check `out`, but don't convert it to
                // a slice yet because it might alias `in_`.
                pedantic_slice_checks(out, max_out_len).map_err(|msg| invalid_arg("out, max_out_len", msg))?;

                // SAFETY:
                // - We have to trust that the caller upholds
                //   Rust's aliasing requirements.
                let out_len = try_ptr_as_mut!(@unsafe out_len)?;

                let nonce = {
                    if any_overlap(out, max_out_len, nonce, nonce_len) {
                        return Err(invalid_arg("nonce", "cannot overlap with `out`"));
                    }
                    if nonce_len != aead.nonce_len {
                        return Err(OpenError::InvalidNonceSize(InvalidNonceSize).into());
                    }
                    // SAFETY:
                    // - We have to trust that the caller has
                    //   initialized `nonce`.
                    // - We have to trust that `nonce` is valid
                    //   for reads up to `nonce_len` bytes.
                    // - We checked that `nonce` does not alias
                    //   `out`, but we still have to trust that
                    //   the caller upholds Rust's aliasing
                    //   requirements for any other uses of
                    //   `nonce`.
                    try_from_raw_parts!(@unsafe nonce, nonce_len)?
                };

                if !less_or_eq(in_len, aead.p_max) {
                    return Err(OpenError::PlaintextTooLong.into());
                }
                // Sanity check `in_`, but don't convert it to
                // a slice yet because it might alias `out`.
                pedantic_slice_checks(in_, in_len).map_err(|msg| invalid_arg("in_, in_len", msg))?;

                let additional_data = {
                    if any_overlap(out, max_out_len, ad, ad_len) {
                        return Err(invalid_arg("ad", "cannot overlap with `out`"));
                    }
                    if !less_or_eq(ad_len, aead.a_max) {
                        return Err(OpenError::AdditionalDataTooLong.into());
                    }
                    // SAFETY:
                    // - We have to trust that the caller has
                    //   initialized `ad`.
                    // - We have to trust that `ad` is valid for
                    //   reads up to `ad_len` bytes.
                    // - We checked that `ad` does not alias
                    //   `out`, but we still have to trust that
                    //   the caller upholds Rust's aliasing
                    //   requirements for any other uses of
                    //   `nonce`.
                    try_from_raw_parts!(@unsafe ad, ad_len)?
                };

                if inexact_overlap(in_, in_len, out, max_out_len) {
                    return Err(invalid_arg(
                        "in_, out",
                        "must overlap entirely or not at all",
                    ));
                }

                // The number of bytes written to `out`.
                //
                // in_len <= c_max and c_max = p_max + overhead.
                let Some(nw) = in_len.checked_sub(aead.overhead) else {
                    // If the ciphertext does not have a full
                    // tag, etc. it cannot be authenticated.
                    return Err(OpenError::Authentication.into());
                };

                // SAFETY:
                // - We have to trust that `out` is valid for
                //   reads up to `max_out_len` bytes.
                // - We have to trust that the caller upholds
                //   Rust's aliasing requirements for any other
                //   uses of `out`.
                let out = try_from_raw_parts_mut!(@unsafe out, max_out_len)?;
                if out.len() < nw {
                    return Err(OpenError::BufferTooSmall(BufferTooSmallError(Some(aead.overhead))).into());
                }

                let result = if in_ == out.as_ptr() {
                    let (data, overhead) = out.split_at_mut(nw);
                    ctx.open_in_place(nonce, data, overhead, additional_data)
                } else {
                    // SAFETY:
                    // - We have to trust that `in_` is valid for
                    //   reads up to `in_len` bytes.
                    // - We checked that `in_` does not alias
                    //   `out_`, but we still have to trust that
                    //   the caller upholds Rust's aliasing
                    //   requirements for any other uses of
                    //   `in_`.
                    let plaintext = try_from_raw_parts!(@unsafe in_, in_len)?;
                    ctx.open(out, nonce, plaintext, additional_data)
                };
                if result.is_err() {
                    out.zeroize();
                    return result.map_err(Into::into);
                }

                out_len.write(nw);

                Ok(())
            }
        }
    }
}
