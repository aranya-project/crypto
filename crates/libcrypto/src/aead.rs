//! AEAD support.
//!
//! NB: `#define S2N_LIBCRYPTO_SUPPORTS_EVP_AEAD_TLS`

#![allow(non_camel_case_types)]

use alloc::boxed::Box;
use core::{ffi::c_int, mem::MaybeUninit, ptr};

use spideroak_crypto::{
    aead::{Aead, BufferTooSmallError, InvalidNonceSize, OpenError, SealError},
    import::{Import, ImportError},
    zeroize::Zeroize,
};

use crate::{
    opaque,
    util::{
        any_overlap, inexact_overlap, less_or_eq, pedantic_slice_checks, try_from_raw_parts,
        try_from_raw_parts_mut, try_ptr_as_mut, try_ptr_as_ref, ISIZE_MAX,
    },
};

/// Adds support for a particular AEAD.
#[macro_export]
macro_rules! impl_aead {
    (AES_128_GCM, $aead:ty) => {
        $crate::impl_aead!(@imp AES_128_GCM, $aead);
    };
    (AES_256_GCM, $aead:ty) => {
        $crate::impl_aead!(@imp AES_256_GCM, $aead);
    };
    (AES_128_GCM_TLS13, $aead:ty) => {
        $crate::impl_aead!(@imp AES_128_GCM_TLS13, $aead);
    };
    (AES_256_GCM_TLS13, $aead:ty) => {
        $crate::impl_aead!(@imp AES_256_GCM_TLS13, $aead);
    };
    (CHACHA20_POLY1305, $aead:ty) => {
        $crate::impl_aead!(@imp CHACHA20_POLY1305, $aead);
    };
    (@imp $name:ident, $aead:ty) => {
        const _: () = {
            use $crate::aead::$name;
            $crate::set_sym!($name, || -> $crate::aead::EVP_AEAD {
                $crate::aead::EVP_AEAD::new::<$aead>()
            });
        };
    };
}

/// A specific AEAD algorithm.
#[repr(C)]
#[non_exhaustive]
#[derive(Clone, Debug)]
//#[opaque(size = 96, align = 8)]
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

    /// [`Aead::new`].
    init: fn(key: &[u8]) -> Result<*const u8, ImportError>,

    /// Frees the allocated data.
    drop: fn(ctx: &mut EVP_AEAD_CTX),

    /// [`Aead::seal`].
    #[allow(clippy::type_complexity)]
    seal: fn(
        ctx: &EVP_AEAD_CTX,
        dst: &mut [u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), SealError>,

    /// [`Aead::seal_in_place`].
    #[allow(clippy::type_complexity)]
    seal_in_place: fn(
        ctx: &EVP_AEAD_CTX,
        nonce: &[u8],
        data: &mut [u8],
        overhead: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), SealError>,

    /// [`Aead::open`].
    #[allow(clippy::type_complexity)]
    open: fn(
        ctx: &EVP_AEAD_CTX,
        dst: &mut [u8],
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError>,

    /// [`Aead::open_in_place`].
    #[allow(clippy::type_complexity)]
    open_in_place: fn(
        ctx: &EVP_AEAD_CTX,
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
            init: |key| {
                let key = <A::Key as Import<_>>::import(key)?;
                let aead = A::new(&key);
                let ptr = Box::into_raw(Box::new(aead)).cast::<u8>();
                Ok(ptr)
            },
            drop: |ctx| {
                // SAFETY:
                // - We have to trust that the caller initialized
                //   it with `EVP_AEAD_CTX_init`.
                let boxed = unsafe { Box::from_raw(ctx.ptr.cast::<A>().cast_mut()) };
                drop(boxed);
            },
            seal: |ctx, dst, nonce, plaintext, additional_data| {
                // SAFETY: We have to trust that `ptr` is
                // non-null and suitably aligned.
                let aead = unsafe { ctx.aead::<A>() };
                aead.seal(dst, nonce, plaintext, additional_data)
            },
            seal_in_place: |ctx, nonce, data, overhead, additional_data| {
                // SAFETY: We have to trust that `ptr` is
                // non-null and suitably aligned.
                let aead = unsafe { ctx.aead::<A>() };
                aead.seal_in_place(nonce, data, overhead, additional_data)
            },
            open: |ctx, dst, nonce, plaintext, additional_data| {
                // SAFETY: We have to trust that `ptr` is
                // non-null and suitably aligned.
                let aead = unsafe { ctx.aead::<A>() };
                aead.open(dst, nonce, plaintext, additional_data)
            },
            open_in_place: |ctx, nonce, data, overhead, additional_data| {
                // SAFETY: We have to trust that `ptr` is
                // non-null and suitably aligned.
                let aead = unsafe { ctx.aead::<A>() };
                aead.open_in_place(nonce, data, overhead, additional_data)
            },
        }
    }
}

/// Returns the size in bytes of the AEAD's key.
#[no_mangle]
pub extern "C" fn EVP_AEAD_key_length(aead: &EVP_AEAD) -> usize {
    aead.key_len
}

/// Returns the size in bytes of the AEAD's nonce.
#[no_mangle]
pub extern "C" fn EVP_AEAD_nonce_length(aead: &EVP_AEAD) -> usize {
    aead.nonce_len
}

/// Returns the size in bytes of the AEAD's authentication
/// overhead.
#[no_mangle]
pub extern "C" fn EVP_AEAD_max_overhead(aead: &EVP_AEAD) -> usize {
    aead.overhead
}

/// See [`EVP_AEAD_max_overhead`].
#[no_mangle]
pub extern "C" fn EVP_AEAD_max_tag_len(aead: &EVP_AEAD) -> usize {
    aead.overhead
}

macro_rules! add_evp_aead {
    ($name:ident, $sym:ident, $doc:expr $(,)?) => {
        #[doc = $doc]
        #[doc = "Returns `NULL` if the AEAD is not supported."]
        #[no_mangle]
        pub extern "C" fn $name() -> *const EVP_AEAD {
            $crate::weak::get_sym!($sym)
        }
        $crate::weak::new_sym!($sym, EVP_AEAD);
    };
}
add_evp_aead!(EVP_aead_aes_128_gcm, AES_128_GCM, "AES-128-GCM");
add_evp_aead!(EVP_aead_aes_256_gcm, AES_256_GCM, "AES-256-GCM");
add_evp_aead!(
    EVP_aead_aes_128_gcm_tls13,
    AES_128_GCM_TLS13,
    "AES-128-GCM for TLS v1.3",
);
add_evp_aead!(
    EVP_aead_aes_256_gcm_tls13,
    AES_256_GCM_TLS13,
    "AES-256-GCM for TLS v1.3",
);
add_evp_aead!(
    EVP_aead_chacha20_poly1305,
    CHACHA20_POLY1305,
    "ChaCha20Poly1305",
);

/// Unused.
/// cbindgen:no-export
#[repr(C)]
#[non_exhaustive]
#[derive(Debug)]
pub struct ENGINE {}

/// An AEAD instance.
#[repr(C)]
#[non_exhaustive]
#[derive(Debug)]
#[opaque(size = 24, align = 8)]
pub struct EVP_AEAD_CTX {
    /// The AEAD algorithm.
    ///
    /// Ideally, this would be `&'static EVP_AEAD`, but we need
    /// to support C doing this:
    ///
    /// ```C
    /// EVP_AEAD_CTX ctx;
    /// memset(&ctx, 0, sizeof(ctx));
    /// ```
    aead: *const EVP_AEAD,

    /// Points to the `Aead` instance.
    ///
    /// This is allocated by `Box`.
    ///
    /// It is null if the `EVP_AEAD_CTX` has not yet been
    /// initialized or if `EVP_AEAD_CTX_cleanup` was called.
    ptr: *const u8,
}

impl EVP_AEAD_CTX {
    /// Returns `self.ptr` cast to `A`.
    ///
    /// # Safety
    ///
    /// - `self.ptr` must be non-null.
    /// - `self.ptr` must be suitably aligned and initialized for
    ///   `A`.
    /// - You must uphold Rust's aliasing rules.
    unsafe fn aead<A>(&self) -> &A {
        // SAFETY: See the method's safety docs.
        unsafe { &*(self.ptr.cast::<A>()) }
    }
}

impl Default for EVP_AEAD_CTX {
    fn default() -> Self {
        Self {
            aead: ptr::null(),
            ptr: ptr::null(),
        }
    }
}

/// Sets an uninitialized `ctx` to all zeros.
///
/// `ctx` must still be initialized with [`EVP_AEAD_CTX_init`]
/// before use.
///
/// It is safe to call [`EVP_AEAD_CTX_cleanup`] after calling
/// this routine.
///
/// # Safety
///
/// - You must uphold Rust's aliasing requirements.
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_zero(ctx: *mut MaybeUninit<EVP_AEAD_CTX>) {
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
/// - `key_len` must match [`EVP_AEAD_key_len(aead)`].
/// - If non-zero, `tag_len` must match
///   [`EVP_AEAD_tag_len(aead)`].
/// - `impl_` must be null.
///
/// It returns 1 on success and 0 otherwise. It is safe to call
/// [`EVP_AEAD_CTX_cleanup`] on error.
///
/// # Safety
///
/// - `ctx`, `aead`, and `key` must be non-null and suitably
///   aligned.
/// - `key` must be valid for reads up to `key_len` bytes.
/// - `key_len` must be less than or equal to than
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
) -> Result<(), &'static str> {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let ctx = try_ptr_as_mut!(@unsafe ctx)?;

    // Ensure that `ctx` is valid even if we return an error.
    ctx.write(EVP_AEAD_CTX::default());

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `aead`.
    let aead = try_ptr_as_ref!(@unsafe aead)?;

    let key = {
        if key_len != aead.key_len {
            return Err("invalid `key_len`");
        }
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `nonce`.
        // - We have to trust that `nonce` is valid for reads up to
        //   `nonce_len` bytes.
        // - We checked that `nonce` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `nonce`.
        try_from_raw_parts!(@unsafe key,key_len)?
    };

    if !impl_.is_null() {
        return Err("`impl_` must be null");
    }

    if tag_len != 0 && tag_len != aead.overhead {
        return Err("invalid `tag_len`");
    }

    let ptr = (aead.init)(key).map_err(|_| "unable to initialize `Aead`")?;
    ctx.write(EVP_AEAD_CTX { aead, ptr });

    Ok(())
}

/// Frees all resources used by `ctx`.
///
/// # Safety
///
/// - If non-null, `ctx` must have been initialized with
///   `EVP_AEAD_CTX_init`.
#[no_mangle]
pub unsafe extern "C" fn EVP_AEAD_CTX_cleanup(ctx: *mut EVP_AEAD_CTX) {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx`.
    let Ok(ctx) = try_ptr_as_mut!(@unsafe ctx) else {
        return;
    };
    if ctx.ptr.is_null() {
        return;
    }
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx`.
    let Ok(aead) = try_ptr_as_ref!(@unsafe ctx.aead) else {
        return;
    };
    (aead.drop)(ctx);
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
/// - `max_out_len` must be at least `in_len` plus the result of
///   [`EVP_AEAD_max_overhead`].
/// - `nonce_len` must be equal to the result of
///   [`EVP_AEAD_nonce_length`].
/// - If `nonce_len` is zero, `nonce` must be null.
/// - If `in_` is null, `in_len` must be zero.
/// - If `in_` is non-null, `in_len` must be non-zero.
/// - If `ad` is null, `ad_len` must be zero.
/// - If `ad` is non-null, `ad_len` must be non-zero.
/// - `out` and `in_` must overlap entirely or not at all.
///
/// # Safety
///
/// - `ctx` and `out_len` must be non-null and suitably aligned.
/// - If non-null, all other pointers must be suitably aligned.
/// - If non-null, `out` must be valid for writes up to
///   `max_out_len` bytes.
/// - `max_out_len` must be at most `isize::MAX`.
/// - If non-null, `nonce` must be valid for reads up to
///   `nonce_len` bytes.
/// - `nonce_len` must be at most `isize::MAX`.
/// - If non-null, `in_` must be valid for reads up to `in_len`
///   bytes.
/// - `in_len` must be at most `isize::MAX`.
/// - If non-null `ad` must be valid for reads up to `ad_len`
///   bytes.
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
) -> Result<(), SealError> {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx`.
    let ctx = try_ptr_as_ref!(@unsafe ctx).map_err(SealError::Other)?;

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx`.
    let aead = try_ptr_as_ref!(@unsafe ctx.aead).map_err(SealError::Other)?;

    // Sanity check `out`, but don't convert it to a slice yet
    // because it might alias `in_`.
    pedantic_slice_checks!(out, max_out_len).map_err(SealError::Other)?;

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let out_len = try_ptr_as_mut!(@unsafe out_len).map_err(SealError::Other)?;

    let nonce = {
        if any_overlap(out, max_out_len, nonce, nonce_len) {
            return Err(SealError::Other("`out` cannot overlap with `nonce`"));
        }
        if nonce_len != aead.nonce_len {
            return Err(SealError::InvalidNonceSize(InvalidNonceSize));
        }
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `nonce`.
        // - We have to trust that `nonce` is valid for reads up
        //   to `nonce_len` bytes.
        // - We checked that `nonce` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `nonce`.
        try_from_raw_parts!(@unsafe nonce, nonce_len).map_err(SealError::Other)?
    };

    if !less_or_eq(in_len, aead.p_max) {
        return Err(SealError::PlaintextTooLong);
    }
    // Sanity check `in_`, but don't convert it to a slice yet
    // because it might alias `out`.
    pedantic_slice_checks!(in_, in_len).map_err(SealError::Other)?;

    let additional_data = {
        if any_overlap(out, max_out_len, ad, ad_len) {
            return Err(SealError::Other("`out` cannot overlap with `ad`"));
        }
        if !less_or_eq(ad_len, aead.a_max) {
            return Err(SealError::AdditionalDataTooLong);
        }
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `ad`.
        // - We have to trust that `ad` is valid for reads up to
        //   `ad_len` bytes.
        // - We checked that `ad` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `nonce`.
        try_from_raw_parts!(@unsafe ad, ad_len).map_err(SealError::Other)?
    };

    if inexact_overlap(in_, in_len, out, max_out_len) {
        return Err(SealError::Other(
            "`in_` and `out` must overlap entirely or not at all",
        ));
    }

    // The number of bytes written to `out`.
    //
    // `in_len` <= `p_max` and `p_max` = `c_max` - `overhead`, so
    // this addition can only overflow if `usize` is tiny.
    let Some(nw) = in_len.checked_add(aead.overhead) else {
        // If the ciphertext does not have a full tag, etc. it
        // cannot be authenticated.
        return Err(SealError::Other("`in_` too large"));
    };

    // SAFETY:
    // - We have to trust that `out` is valid for reads up to
    //   `max_out_len` bytes.
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements for any other uses of `out`.
    let out = try_from_raw_parts_mut!(@unsafe out, max_out_len).map_err(SealError::Other)?;
    if out.len() < nw {
        return Err(SealError::BufferTooSmall(BufferTooSmallError(Some(
            aead.overhead,
        ))));
    }

    if in_ == out.as_ptr() {
        let (data, overhead) = out.split_at_mut(nw);
        (aead.seal_in_place)(ctx, nonce, data, overhead, additional_data)?;
    } else {
        // SAFETY:
        // - We have to trust that `in_` is valid for reads up to
        //   `in_len` bytes.
        // - We checked that `in_` does not alias `out_`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `in_`.
        let plaintext = try_from_raw_parts!(@unsafe in_, in_len).map_err(SealError::Other)?;
        (aead.seal)(ctx, out, nonce, plaintext, additional_data)?;
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
/// - `max_out_len` must be at least `in_len` less the result of
///   [`EVP_AEAD_max_overhead`].
/// - `nonce_len` must be equal to the result of
///   [`EVP_AEAD_nonce_length`].
/// - If `nonce_len` is zero, `nonce` must be null.
/// - If `in_` is null, `in_len` must be zero.
/// - If `in_` is non-null, `in_len` must be non-zero.
/// - If `ad` is null, `ad_len` must be zero.
/// - If `ad` is non-null, `ad_len` must be non-zero.
/// - `out` and `in_` must overlap entirely or not at all.
///
/// # Safety
///
/// - `ctx` and `out_len` must be non-null and suitably aligned.
/// - If non-null, all other pointers must be suitably aligned.
/// - If non-null, `out` must be valid for writes up to
///   `max_out_len` bytes.
/// - `max_out_len` must be at most `isize::MAX`.
/// - If non-null, `nonce` must be valid for reads up to
///   `nonce_len` bytes.
/// - `nonce_len` must be at most `isize::MAX`.
/// - If non-null, `in_` must be valid for reads up to `in_len`
///   bytes.
/// - `in_len` must be at most `isize::MAX`.
/// - If non-null `ad` must be valid for reads up to `ad_len`
///   bytes.
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
) -> Result<(), OpenError> {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx`.
    let ctx = try_ptr_as_ref!(@unsafe ctx).map_err(OpenError::Other)?;

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx`.
    let aead = try_ptr_as_ref!(@unsafe ctx.aead).map_err(OpenError::Other)?;

    // Sanity check `out`, but don't convert it to a slice yet
    // because it might alias `in_`.
    pedantic_slice_checks!(out, max_out_len).map_err(OpenError::Other)?;

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let out_len = try_ptr_as_mut!(@unsafe out_len).map_err(OpenError::Other)?;

    let nonce = {
        if any_overlap(out, max_out_len, nonce, nonce_len) {
            return Err(OpenError::Other("`out` cannot overlap with `nonce`"));
        }
        if nonce_len != aead.nonce_len {
            return Err(OpenError::InvalidNonceSize(InvalidNonceSize));
        }
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `nonce`.
        // - We have to trust that `nonce` is valid for reads up
        //   to `nonce_len` bytes.
        // - We checked that `nonce` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `nonce`.
        try_from_raw_parts!(@unsafe nonce, nonce_len).map_err(OpenError::Other)?
    };

    if !less_or_eq(in_len, aead.p_max) {
        return Err(OpenError::PlaintextTooLong);
    }
    // Sanity check `in_`, but don't convert it to a slice yet
    // because it might alias `out`.
    pedantic_slice_checks!(in_, in_len).map_err(OpenError::Other)?;

    let additional_data = {
        if any_overlap(out, max_out_len, ad, ad_len) {
            return Err(OpenError::Other("`out` cannot overlap with `ad`"));
        }
        if !less_or_eq(ad_len, aead.a_max) {
            return Err(OpenError::AdditionalDataTooLong);
        }
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `ad`.
        // - We have to trust that `ad` is valid for reads up to
        //   `ad_len` bytes.
        // - We checked that `ad` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `nonce`.
        try_from_raw_parts!(@unsafe ad, ad_len).map_err(OpenError::Other)?
    };

    if inexact_overlap(in_, in_len, out, max_out_len) {
        return Err(OpenError::Other(
            "`in_` and `out` must overlap entirely or not at all",
        ));
    }

    // The number of bytes written to `out`.
    //
    // `in_len` <= `c_max` and `c_max` = `p_max` + `overhead`.
    let Some(nw) = in_len.checked_sub(aead.overhead) else {
        // If the ciphertext does not have a full tag, etc. it
        // cannot be authenticated.
        return Err(OpenError::Authentication);
    };

    // SAFETY:
    // - We have to trust that `out` is valid for reads up to
    //   `max_out_len` bytes.
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements for any other uses of `out`.
    let out = try_from_raw_parts_mut!(@unsafe out, max_out_len).map_err(OpenError::Other)?;
    if out.len() < nw {
        return Err(OpenError::BufferTooSmall(BufferTooSmallError(Some(
            aead.overhead,
        ))));
    }

    let result = if in_ == out.as_ptr() {
        let (data, overhead) = out.split_at_mut(nw);
        (aead.open_in_place)(ctx, nonce, data, overhead, additional_data)
    } else {
        // SAFETY:
        // - We have to trust that `in_` is valid for reads up to
        //   `in_len` bytes.
        // - We checked that `in_` does not alias `out_`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `in_`.
        let plaintext = try_from_raw_parts!(@unsafe in_, in_len).map_err(OpenError::Other)?;
        (aead.open)(ctx, out, nonce, plaintext, additional_data)
    };
    if result.is_err() {
        out.zeroize();
        return result;
    }

    out_len.write(nw);

    Ok(())
}
