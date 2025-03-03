//! `aead.h`
//!
//! NB: `#define S2N_LIBCRYPTO_SUPPORTS_EVP_AEAD_TLS`

#![allow(non_camel_case_types)]

use core::{
    alloc::Layout,
    fmt,
    mem::{ManuallyDrop, MaybeUninit},
    ptr,
};

use buggy::{bug, Bug};
use spideroak_crypto::{
    aead::{Aead, BufferTooSmallError, InvalidNonceSize, OpenError, SealError},
    import::{Import, ImportError},
    zeroize::Zeroize,
};
use spideroak_libcrypto_macro::api;

use crate::{
    error::{invalid_arg, Error},
    util::{
        any_overlap, inexact_overlap, less_or_eq, pedantic_slice_checks, try_from_raw_parts,
        try_from_raw_parts_mut, try_ptr_as_mut, try_ptr_as_ref, Void,
    },
};

/// Unused.
#[repr(C)]
#[non_exhaustive]
#[derive(Copy, Clone, Debug)]
pub struct ENGINE {
    _words: [usize; 2],
}

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

    /// Initializes `ptr` with [`Aead::new`].
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   `Aead` it will point to.
    #[allow(clippy::type_complexity)]
    init: unsafe fn(
        // A pointer to the uninitialized `Aead`.
        ptr: *mut MaybeUninit<Void>,
        key: &[u8],
    ) -> Result<(), ImportError>,

    /// Drops `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   `Aead` it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   `Aead`.
    /// - `ptr` must not be used after this function is called.
    cleanup: unsafe fn(ptr: *mut ManuallyDrop<Void>),

    /// [`Aead::seal`].
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   `Aead` it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   `Aead`.
    #[allow(clippy::type_complexity)]
    seal: unsafe fn(
        // A pointer to the `Aead`.
        ptr: *const Void,
        dst: &mut [u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), SealError>,

    /// [`Aead::seal_in_place`].
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   `Aead` it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   `Aead`.
    #[allow(clippy::type_complexity)]
    seal_in_place: unsafe fn(
        // A pointer to the `Aead`.
        ptr: *const Void,
        nonce: &[u8],
        data: &mut [u8],
        overhead: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), SealError>,

    /// [`Aead::open`].
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   `Aead` it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   `Aead`.
    #[allow(clippy::type_complexity)]
    open: unsafe fn(
        // A pointer to the `Aead`.
        ptr: *const Void,
        dst: &mut [u8],
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError>,

    /// [`Aead::open_in_place`].
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   `Aead` it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   `Aead`.
    #[allow(clippy::type_complexity)]
    open_in_place: unsafe fn(
        // A pointer to the `Aead`.
        ptr: *const Void,
        nonce: &[u8],
        data: &mut [u8],
        overhead: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError>,
}

impl EVP_AEAD {
    #[doc(hidden)]
    pub const fn new<A: Aead>() -> Self {
        Self {
            key_len: A::KEY_SIZE,
            nonce_len: A::NONCE_SIZE,
            overhead: A::OVERHEAD,
            p_max: A::MAX_PLAINTEXT_SIZE,
            c_max: A::MAX_CIPHERTEXT_SIZE,
            a_max: A::MAX_ADDITIONAL_DATA_SIZE,
            layout: Layout::new::<A>(),
            init: |ptr, key| {
                let key = <A::Key as Import<_>>::import(key)?;
                let aead = A::new(&key);

                // SAFETY: See the function pointer's safety
                // docs.
                let ptr = unsafe { &mut *(ptr.cast::<MaybeUninit<A>>()) };
                ptr.write(aead);

                Ok(())
            },
            cleanup: |ptr| {
                // SAFETY: See the function pointer's safety
                // docs.
                let aead = unsafe { &mut *(ptr.cast::<ManuallyDrop<A>>()) };
                // SAFETY: See the function pointer's safety
                // docs.
                unsafe { ManuallyDrop::drop(aead) }
            },
            seal: |ptr, dst, nonce, plaintext, additional_data| {
                // SAFETY: See the function pointer's safety
                // docs.
                let aead = unsafe { &*(ptr.cast::<A>()) };
                aead.seal(dst, nonce, plaintext, additional_data)
            },
            seal_in_place: |ptr, nonce, data, overhead, additional_data| {
                // SAFETY: See the function pointer's safety
                // docs.
                let aead = unsafe { &*(ptr.cast::<A>()) };
                aead.seal_in_place(nonce, data, overhead, additional_data)
            },
            open: |ptr, dst, nonce, plaintext, additional_data| {
                // SAFETY: See the function pointer's safety
                // docs.
                let aead = unsafe { &*(ptr.cast::<A>()) };
                aead.open(dst, nonce, plaintext, additional_data)
            },
            open_in_place: |ptr, nonce, data, overhead, additional_data| {
                // SAFETY: See the function pointer's safety
                // docs.
                let aead = unsafe { &*(ptr.cast::<A>()) };
                aead.open_in_place(nonce, data, overhead, additional_data)
            },
        }
    }
}

impl EVP_AEAD {
    /// Returns the size in bytes of the AEAD's key.
    #[doc(alias = "EVP_AEAD_key_length")]
    #[inline]
    pub const fn key_length(&self) -> usize {
        self.key_len
    }

    /// Returns the size in bytes of the AEAD's nonce.
    #[doc(alias = "EVP_AEAD_nonce_length")]
    #[inline]
    pub const fn nonce_length(&self) -> usize {
        self.nonce_len
    }

    /// Returns the size in bytes of the AEAD's authentication
    /// overhead.
    #[doc(alias = "EVP_AEAD_max_overhead")]
    #[inline]
    pub const fn max_overhead(&self) -> usize {
        self.overhead
    }

    /// Returns the size in bytes of the AEAD's authentication
    /// overhead.
    #[doc(alias = "EVP_AEAD_max_tag_len")]
    #[inline]
    pub const fn max_tag_len(&self) -> usize {
        self.overhead
    }
}

/// Supported AEADs.
///
/// Do not implement this trait yourself. Instead use
/// [`aeads`][crate::aeads].
///
/// # Safety
///
/// - `Self` must be a `repr(C)` union.
/// - The size of `Self` must be exactly `MAX_SIZE` bytes.
/// - The alignment of `Self` must be exactly `MAX_ALIGN` bytes.
pub unsafe trait Aeads: Sized {
    /// AES-128-GCM.
    const AES_128_GCM: Option<&EVP_AEAD>;
    /// AES-256-GCM.
    const AES_256_GCM: Option<&EVP_AEAD>;
    /// AES-128-GCM for TLS 1.3.
    const AES_128_GCM_TLS13: Option<&EVP_AEAD>;
    /// AES-256-GCM for TLS 1.3.
    const AES_256_GCM_TLS13: Option<&EVP_AEAD>;
    /// ChaCha20-Poly1305.
    const CHACHA20_POLY1305: Option<&EVP_AEAD>;

    #[doc(hidden)]
    const AEADS: &[Option<&EVP_AEAD>] = &[
        Self::AES_128_GCM,
        Self::AES_256_GCM,
        Self::AES_128_GCM_TLS13,
        Self::AES_256_GCM_TLS13,
        Self::CHACHA20_POLY1305,
    ];

    /// The maximum size of all [`EVP_AEAD`]s listed in this
    /// trait.
    const MAX_SIZE: usize = {
        let mut n = 0;
        let mut i = 0;
        while i < Self::AEADS.len() {
            if let Some(aead) = Self::AEADS[i] {
                n = max(n, aead.layout.size())
            }
            i += 1;
        }
        n
    };

    /// The maximum alignment of all [`EVP_AEAD`]s listed in this
    /// trait.
    const MAX_ALIGN: usize = {
        let mut n = 0;
        let mut i = 0;
        while i < Self::AEADS.len() {
            if let Some(aead) = Self::AEADS[i] {
                n = max(n, aead.layout.align())
            }
            i += 1;
        }
        n
    };
}

const fn max(a: usize, b: usize) -> usize {
    [a, b][(a < b) as usize]
}

/// A number that's at least [`size_of::<EVP_AEAD_CTX<Void>>()`].
#[doc(hidden)]
pub const EVP_AEAD_CTX_BASE_SIZE: usize = 8;

/// A number that's at least [`align_of::<EVP_AEAD_CTX<Void>>()`].
#[doc(hidden)]
pub const EVP_AEAD_CTX_BASE_ALIGN: usize = 8;

/// An AEAD instance.
///
/// It must be initialized with [`evp_aead_ctx_init`] before it
/// can be used.
#[repr(C)]
#[non_exhaustive]
pub struct EVP_AEAD_CTX<T> {
    /// The AEAD algorithm.
    ///
    /// The [NPO] guarantees that this is safe to use with zeroed
    /// memory.
    ///
    /// [NPO]: https://doc.rust-lang.org/std/option/index.html#representation
    vtable: Option<&'static EVP_AEAD>,

    /// The `Aead` instance.
    ///
    /// # Invariants
    ///
    /// - If `self.vtable` is `Some`, then this field is
    ///   initialized.
    ///
    /// # Caveats
    ///
    /// It is obviously very easy for C code to corrupt memory,
    /// so this is a best-effort attempt. We can't control what
    /// other languages do to violate Rust's invariants.
    aead: MaybeUninit<T>,
}

impl<T: Aeads> EVP_AEAD_CTX<T> {
    /// Invokes `f` with the [`EVP_AEAD`] and a pointer to the
    /// [`Aead`].
    ///
    /// It returns [`Err(Bug)`] if `self` is not initialized or
    /// if the [`EVP_AEAD`] refers to an unknown [`Aead`].
    fn with_aead<F, R>(&self, f: F) -> Result<R, Bug>
    where
        F: FnOnce(&EVP_AEAD, *const Void) -> R,
    {
        let Some(vtable) = self.vtable else {
            // All code paths should have checked `self.vtable`
            // by this point.
            bug!("`EVP_AEAD_CTX` is not initialized");
        };

        // `vtable` is `Some`, so `self.aead` is initialized.
        let ptr = self.aead.as_ptr().cast::<Void>();

        Ok(f(vtable, ptr))
    }

    fn init(&mut self, vtable: &'static EVP_AEAD, key: &[u8]) -> Result<(), ImportError> {
        if self.vtable.is_some() {
            self.cleanup()?;
        }
        debug_assert!(self.vtable.is_none());

        let ptr = ptr::addr_of_mut!(self.aead).cast::<MaybeUninit<Void>>();

        // SAFETY: `ptr` is non-null and suitably aligned for
        // the `Aead`.
        unsafe { (vtable.init)(ptr, key)? }

        // Only set `self.vtable` after we've initialized
        // `self.aead` since `self.vtable` indicates whether
        // `self.aead` is initialized.
        self.vtable = Some(vtable);

        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Bug> {
        let Some(vtable) = self.vtable.take() else {
            // All code paths should have checked `self.vtable`
            // by this point.
            bug!("`EVP_AEAD_CTX` is not initialized");
        };

        // `ManuallyDrop<T>` is a transparent wrapper around `T`,
        // so the cast is valid.
        let ptr = self.aead.as_mut_ptr().cast::<ManuallyDrop<Void>>();

        // SAFETY:
        // - `ptr` is non-null and suitably aligned because (a)
        //   we used `MaybeUninit::as_mut_ptr`, and (b) `T`
        //   implements `Aeads` is required to be suitably
        //   aligned for all supported AEADs.
        // - The memory `ptr` points is initialized to because
        //   `vtable` is (was) `Some`.
        // - We do not use `ptr` (except to re-initialize it)
        //   after this call.
        unsafe { (vtable.cleanup)(ptr) }

        // Clobber `self.aead` in case the `Aead` isn't
        // `ZeroizeOnDrop`.
        self.aead.zeroize();

        Ok(())
    }

    fn seal(
        &self,
        dst: &mut [u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), SealError> {
        self.with_aead(|vt, ptr| {
            // SAFETY:
            // - `self.vtable` is `Some`, so `self.aead` is
            //   initialized (see `self.aead`'s docs for
            //   caveats).
            unsafe { (vt.seal)(ptr, dst, nonce, plaintext, additional_data) }
        })?
    }

    fn seal_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        overhead: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), SealError> {
        self.with_aead(|vt, ptr| {
            // SAFETY:
            // - `self.vtable` is `Some`, so `self.aead` is
            //   initialized (see `self.aead`'s docs for
            //   caveats).
            unsafe { (vt.seal_in_place)(ptr, nonce, data, overhead, additional_data) }
        })?
    }

    fn open(
        &self,
        dst: &mut [u8],
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError> {
        self.with_aead(|vt, ptr| {
            // SAFETY:
            // - `self.vtable` is `Some`, so `self.aead` is
            //   initialized (see `self.aead`'s docs for
            //   caveats).
            unsafe { (vt.open)(ptr, dst, nonce, ciphertext, additional_data) }
        })?
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        overhead: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError> {
        self.with_aead(|vt, ptr| {
            // SAFETY:
            // - `self.vtable` is `Some`, so `self.aead` is
            //   initialized (see `self.aead`'s docs for
            //   caveats).
            unsafe { (vt.open_in_place)(ptr, nonce, data, overhead, additional_data) }
        })?
    }
}

impl<T> Default for EVP_AEAD_CTX<T> {
    #[inline]
    fn default() -> Self {
        Self {
            vtable: None,
            aead: MaybeUninit::uninit(),
        }
    }
}

impl<T> fmt::Debug for EVP_AEAD_CTX<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EVP_AEAD_CTX")
            .field("aead", &self.vtable)
            .finish_non_exhaustive()
    }
}

/// Sets an uninitialized `ctx` to all zeros. This is equivalent
/// to
///
/// ```c
/// EVP_AEAD_CTX ctx;
/// memset(&ctx, 0, sizeof(ctx))
/// ```
///
/// but is more explicit.
///
/// `ctx` must still be initialized with [`evp_aead_ctx_init`]
/// before use.
///
/// It is safe to call [`evp_aead_ctx_cleanup`] after calling
/// this routine.
///
/// # Safety
///
/// - You must uphold Rust's aliasing requirements.
pub unsafe fn evp_aead_ctx_zero<T: Aeads>(ctx: *mut MaybeUninit<EVP_AEAD_CTX<T>>) {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let Ok(ctx) = try_ptr_as_mut!(@unsafe ctx) else {
        return;
    };
    ctx.write(EVP_AEAD_CTX::default());
}

/// Initializes `ctx` for the given AEAD algorithm.
///
/// - `ctx`, `aead`, and `key` must be non-null and suitably
///   aligned.
/// - `key_len` must match [`EVP_AEAD::nonce_length`].
/// - If non-zero, `tag_len` must match
///   [`EVP_AEAD::max_tag_len`].
/// - `impl_` must be null.
///
/// It returns 1 on success and 0 otherwise. It is safe to call
/// [`evp_aead_ctx_cleanup`] on error.
///
/// # Safety
///
/// - `ctx` must be valid for writes up to
///   `size_of::<EVP_AEAD_CTX<T>>()` bytes.
/// - `aead` must be initialized.
/// - `key` must be valid for reads up to `key_len` bytes.
/// - `key_len` must be less than or equal to [`isize::MAX`].
/// - You must uphold Rust's aliasing invariants.
pub unsafe fn evp_aead_ctx_init<T: Aeads>(
    ctx: *mut MaybeUninit<EVP_AEAD_CTX<T>>,
    aead: *const EVP_AEAD,
    key: *const u8,
    key_len: usize,
    tag_len: usize,
    impl_: *const MaybeUninit<ENGINE>,
) -> Result<(), Error> {
    // Ensure that `ctx` is valid even if we return an error.
    //
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let ctx = try_ptr_as_mut!(@unsafe ctx)?.write(EVP_AEAD_CTX::default());

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `aead`.
    let vtable = try_ptr_as_ref!(@unsafe aead)?;

    if !is_known_aead::<T>(vtable) {
        return Err(invalid_arg("aead", "unknown `EVP_AEAD`"));
    }

    let key = {
        if key_len != vtable.key_len {
            return Err(invalid_arg("key_len", "invalid key length"));
        }
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `key`.
        // - We have to trust that `nonce` is valid for reads up
        //   to `key_len` bytes.
        // - We have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `key`.
        try_from_raw_parts!(@unsafe key, key_len)?
    };

    if !impl_.is_null() {
        return Err(invalid_arg("impl_", "pointer must be null"));
    }

    if tag_len != 0 && tag_len != vtable.overhead {
        return Err(invalid_arg("tag_len", "invalid tag length"));
    }

    ctx.init(vtable, key)
        .map_err(|_| "unable to initialize `Aead`")?;

    Ok(())
}

#[inline]
fn is_known_aead<T: Aeads>(aead: &EVP_AEAD) -> bool {
    macro_rules! test_aeads {
        ($($name:ident),* $(,)?) => {
            $(
                if T::$name.is_some_and(|v| ptr::eq(v, aead)) {
                    return true;
                }
            )*
            false
        };
    }
    test_aeads! {
        AES_128_GCM,
        AES_256_GCM,
        AES_128_GCM_TLS13,
        AES_256_GCM_TLS13,
        CHACHA20_POLY1305,
    }
}

/// Releases all resources used by `ctx`, but does not free `ctx`
/// itself.
///
/// # Safety
///
/// - If non-null, `ctx` must have been initialized with
///   `EVP_AEAD_CTX_init`.
pub unsafe fn evp_aead_ctx_cleanup<T: Aeads>(ctx: *mut EVP_AEAD_CTX<T>) {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx`.
    let Ok(ctx) = try_ptr_as_mut!(@unsafe ctx) else {
        return;
    };
    // Not much we can do here. Plus, `buggy` calls
    // `unreachable!` in debug mode for us.
    let _ = ctx.cleanup();
}

/// Encrypts and authenticates `in_len` bytes from `in_`,
/// authenticates `ad_len` bytes from `ad`, and writes the
/// resulting ciphertext to `out`.
///
/// At most `max_out_len` bytes are written to `out`. On success,
/// `out_len` is updated with the number of bytes written to
/// `out`.
///
/// It returns 1 on success and 0 otherwise.
///
/// - `ctx` must be non-null and suitably aligned.
/// - If non-null, `out` must be suitably aligned.
/// - `out_len` must be non-null and suitably aligned.
/// - `max_out_len` must be at least `in_len` less the result of
///   [`EVP_AEAD::max_overhead`] and at most `isize::MAX`.
/// - `nonce_len` must be equal to the result of
///   [`EVP_AEAD::nonce_length`] and at most `isize::MAX`.
/// - If `nonce` is non-null then it must be suitably aligned.
/// - `nonce` must not overlap at all with `out`.
/// - If non-null, `in_` must be suitably aligned.
/// - If `in_` is null, `in_len` must be zero. Otherwise,
///   `in_len` must be non-zero and at most `isize::MAX`.
/// - If non-null, `ad` must be suitably aligned.
/// - If `ad` is null, `ad_len` must be zero. Otherwise, `ad_len`
///   must be non-zero and at most `isize::MAX`.
/// - `ad` must not overlap at all with `out`.
/// - `out` and `in_` must overlap entirely or not at all.
///
/// # Safety
///
/// - `ctx` must have been initialized with
///   [`evp_aead_ctx_init`].
/// - If non-null, `out` must be valid for writes up to
///   `max_out_len` bytes.
/// - If non-null, `nonce` must be valid for reads up to
///   `nonce_len` bytes.
/// - If non-null, `in_` must be valid for reads up to `in_len`
///   bytes.
/// - If non-null `ad` must be valid for reads up to `ad_len`
///   bytes.
#[allow(clippy::too_many_arguments, reason = "I didn't come up with the API")]
pub unsafe fn evp_aead_ctx_seal<T: Aeads>(
    ctx: *const EVP_AEAD_CTX<T>,
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
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx`.
    let ctx = try_ptr_as_ref!(@unsafe ctx)?;

    let Some(vtable) = ctx.vtable else {
        return Err(invalid_arg("ctx", "not initialized"));
    };

    // Sanity check `out`, but don't convert it to a slice yet
    // because it might alias `in_`.
    pedantic_slice_checks(out, max_out_len).map_err(|msg| invalid_arg("out, max_out_len", msg))?;

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let out_len = try_ptr_as_mut!(@unsafe out_len)?;

    let nonce = {
        if any_overlap(out, max_out_len, nonce, nonce_len) {
            return Err(invalid_arg("nonce", "cannot overlap with `out`"));
        }
        if nonce_len != vtable.nonce_len {
            return Err(SealError::InvalidNonceSize(InvalidNonceSize).into());
        }
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `nonce`.
        // - We have to trust that `nonce` is valid for reads up
        //   to `nonce_len` bytes.
        // - We checked that `nonce` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `nonce`.
        try_from_raw_parts!(@unsafe nonce, nonce_len)?
    };

    if !less_or_eq(in_len, vtable.p_max) {
        return Err(SealError::PlaintextTooLong.into());
    }
    // Sanity check `in_`, but don't convert it to a slice yet
    // because it might alias `out`.
    pedantic_slice_checks(in_, in_len).map_err(|msg| invalid_arg("in_, in_len", msg))?;

    let additional_data = {
        if any_overlap(out, max_out_len, ad, ad_len) {
            return Err(invalid_arg("ad", "cannot overlap with `out`"));
        }
        if !less_or_eq(ad_len, vtable.a_max) {
            return Err(SealError::AdditionalDataTooLong.into());
        }
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `ad`.
        // - We have to trust that `ad` is valid for reads up to
        //   `ad_len` bytes.
        // - We checked that `ad` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `nonce`.
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
    // `in_len` <= `p_max` and `p_max` = `c_max` - `overhead`, so
    // this addition can only overflow if `usize` is tiny.
    let Some(nw) = in_len.checked_add(vtable.overhead) else {
        return Err(SealError::Other("`in_` too large").into());
    };

    // SAFETY:
    // - We have to trust that `out` is valid for reads up to
    //   `max_out_len` bytes.
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements for any other uses of `out`.
    let out = try_from_raw_parts_mut!(@unsafe out, max_out_len)?;
    if out.len() < nw {
        return Err(SealError::BufferTooSmall(BufferTooSmallError(Some(vtable.overhead))).into());
    }

    if in_ == out.as_ptr() {
        let (data, overhead) = out.split_at_mut(nw);
        ctx.seal_in_place(nonce, data, overhead, additional_data)?;
    } else {
        // SAFETY:
        // - We have to trust that `in_` is valid for reads up to
        //   `in_len` bytes.
        // - We checked that `in_` does not alias `out_`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `in_`.
        let plaintext = try_from_raw_parts!(@unsafe in_, in_len)?;
        ctx.seal(out, nonce, plaintext, additional_data)?;
    }

    out_len.write(nw);

    Ok(())
}

/// Decrypts and authenticates `in_len` bytes from `in_`,
/// authenticates `ad_len` bytes from `ad`, and writes the
/// resulting plaintext to `out`.
///
/// At most `max_out_len` bytes are written to `out`. On success,
/// `out_len` is updated with the number of bytes written to
/// `out`.
///
/// It returns 1 on success and 0 otherwise.
///
/// - `ctx` must be non-null and suitably aligned.
/// - If non-null, `out` must be suitably aligned.
/// - `out_len` must be non-null and suitably aligned.
/// - `max_out_len` must be at least `in_len` less the result of
///   [`EVP_AEAD::max_overhead`] and at most `isize::MAX`.
/// - `nonce_len` must be equal to the result of
///   [`EVP_AEAD::nonce_length`] and at most `isize::MAX`.
/// - If `nonce` is non-null then it must be suitably aligned.
/// - `nonce` must not overlap at all with `out`.
/// - If non-null, `in_` must be suitably aligned.
/// - If `in_` is null, `in_len` must be zero. Otherwise,
///   `in_len` must be non-zero and at most `isize::MAX`.
/// - If non-null, `ad` must be suitably aligned.
/// - If `ad` is null, `ad_len` must be zero. Otherwise, `ad_len`
///   must be non-zero and at most `isize::MAX`.
/// - `ad` must not overlap at all with `out`.
/// - `out` and `in_` must overlap entirely or not at all.
///
/// # Safety
///
/// - `ctx` must have been initialized with
///   [`evp_aead_ctx_init`].
/// - If non-null, `out` must be valid for writes up to
///   `max_out_len` bytes.
/// - If non-null, `nonce` must be valid for reads up to
///   `nonce_len` bytes.
/// - If non-null, `in_` must be valid for reads up to `in_len`
///   bytes.
/// - If non-null `ad` must be valid for reads up to `ad_len`
///   bytes.
#[allow(clippy::too_many_arguments, reason = "I didn't come up with the API")]
#[api(alias = "EVP_AEAD_CTX_open")]
pub unsafe fn evp_aead_ctx_open<T: Aeads>(
    ctx: *const EVP_AEAD_CTX<T>,
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
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx`.
    let ctx = try_ptr_as_ref!(@unsafe ctx)?;

    let Some(vtable) = ctx.vtable else {
        return Err(invalid_arg("ctx", "not initialized"));
    };

    // Sanity check `out`, but don't convert it to a slice yet
    // because it might alias `in_`.
    pedantic_slice_checks(out, max_out_len).map_err(|msg| invalid_arg("out, max_out_len", msg))?;

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let out_len = try_ptr_as_mut!(@unsafe out_len)?;

    let nonce = {
        if any_overlap(out, max_out_len, nonce, nonce_len) {
            return Err(invalid_arg("nonce", "cannot overlap with `out`"));
        }
        if nonce_len != vtable.nonce_len {
            return Err(OpenError::InvalidNonceSize(InvalidNonceSize).into());
        }
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `nonce`.
        // - We have to trust that `nonce` is valid for reads up
        //   to `nonce_len` bytes.
        // - We checked that `nonce` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `nonce`.
        try_from_raw_parts!(@unsafe nonce, nonce_len)?
    };

    if !less_or_eq(in_len, vtable.p_max) {
        return Err(OpenError::PlaintextTooLong.into());
    }
    // Sanity check `in_`, but don't convert it to a slice yet
    // because it might alias `out`.
    pedantic_slice_checks(in_, in_len).map_err(|msg| invalid_arg("in_, in_len", msg))?;

    let additional_data = {
        if any_overlap(out, max_out_len, ad, ad_len) {
            return Err(invalid_arg("ad", "cannot overlap with `out`"));
        }
        if !less_or_eq(ad_len, vtable.a_max) {
            return Err(OpenError::AdditionalDataTooLong.into());
        }
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `ad`.
        // - We have to trust that `ad` is valid for reads up to
        //   `ad_len` bytes.
        // - We checked that `ad` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `nonce`.
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
    // `in_len` <= `c_max` and `c_max` = `p_max` + `overhead`.
    let Some(nw) = in_len.checked_sub(vtable.overhead) else {
        // If the ciphertext does not have a full tag, etc. it
        // cannot be authenticated.
        return Err(OpenError::Authentication.into());
    };

    // SAFETY:
    // - We have to trust that `out` is valid for reads up to
    //   `max_out_len` bytes.
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements for any other uses of `out`.
    let out = try_from_raw_parts_mut!(@unsafe out, max_out_len)?;
    if out.len() < nw {
        return Err(OpenError::BufferTooSmall(BufferTooSmallError(Some(vtable.overhead))).into());
    }

    let result = if in_ == out.as_ptr() {
        let (data, overhead) = out.split_at_mut(nw);
        ctx.open_in_place(nonce, data, overhead, additional_data)
    } else {
        // SAFETY:
        // - We have to trust that `in_` is valid for reads up to
        //   `in_len` bytes.
        // - We checked that `in_` does not alias `out_`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `in_`.
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
