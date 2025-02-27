//! `cipher.h`

#![allow(non_camel_case_types)]

use alloc::boxed::Box;
use core::{
    convert::Infallible,
    ffi::c_int,
    mem::{ManuallyDrop, MaybeUninit},
    ptr,
};

use buggy::Bug;

use crate::{
    aead::ENGINE,
    error::{invalid_arg, Error},
    util::{
        any_overlap, inexact_overlap, less_or_eq, pedantic_slice_checks, try_from_raw_parts,
        try_from_raw_parts_mut, try_ptr_as_mut, try_ptr_as_ref,
    },
};

/// A specific cipher algorithm.
#[repr(C)]
#[non_exhaustive]
#[derive(Debug)]
pub struct EVP_CIPHER {
    nid: i32,
    key_len: usize,
    iv_len: usize,

    /// Returns a pointer to an initialized cipher.
    ///
    /// # Safety
    ///
    /// - You must uphold Rust's lifetime, aliasing, etc.
    ///   invariants for the returned pointer.
    init: unsafe fn(key: &[u8], iv: &[u8]) -> Option<*mut ()>,

    /// Invokes the cipher's operation
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   type it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   type.
    cipher: unsafe fn(ptr: *mut (), out: &mut [u8], in_: &[u8]) -> Result<(), ()>,

    /// Drops `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   type it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   type.
    /// - `ptr` must not be used after this function is called.
    cleanup: unsafe fn(ptr: *mut ()) -> Result<(), Bug>,
}

impl EVP_CIPHER {
    /// Returns the size in bytes of the key used by the cipher.
    #[doc(alias = "EVP_CIPHER_key_length")]
    pub const fn key_length(&self) -> usize {
        self.key_len
    }

    /// Returns the size in bytes of an IV used by the cipher.
    #[doc(alias = "EVP_CIPHER_iv_length")]
    pub const fn iv_length(&self) -> usize {
        self.iv_len
    }
}

/// A cipher instance.
#[repr(C)]
#[non_exhaustive]
#[derive(Debug)]
pub struct EVP_CIPHER_CTX {
    /// The cipher algorithm.
    ///
    /// The [NPO] guarantees that this is safe to use with zeroed
    /// memory.
    ///
    /// [NPO]: https://doc.rust-lang.org/std/option/index.html#representation
    vtable: Option<&'static EVP_CIPHER>,

    // The cipher instance.
    //
    /// If `self.vtable` is `Some`, then this field is initialized.
    ///
    /// # Caveats
    ///
    /// It is obviously very easy for C code to corrupt memory,
    /// so this is a best-effort attempt. We can't control what
    /// other languages do to violate Rust's invariants.
    cipher: *mut (),
}

impl EVP_CIPHER_CTX {
    #[must_use]
    fn init(&mut self, vtable: &'static EVP_CIPHER, key: &[u8], iv: &[u8]) -> Option<()> {
        // SAFETY: We uphold Rust's invariants via the vtable.
        self.cipher = unsafe { (vtable.init)(key, iv)? };

        // Only set `self.vtable` after we've initialized
        // `self.cipher` since this field indicates whether
        // `self.cipher` is initialized.
        self.vtable = Some(vtable);

        Some(())
    }
}

impl Default for EVP_CIPHER_CTX {
    #[inline]
    fn default() -> Self {
        Self {
            vtable: None,
            cipher: ptr::null_mut(),
        }
    }
}

/// Allocates a new [`EVP_CIPHER_CTX`] then calls
/// [`evp_cipher_ctx_init`].
pub fn evp_cipher_ctx_new() -> *mut EVP_CIPHER_CTX {
    let mut ctx = MaybeUninit::uninit();
    evp_cipher_ctx_init(&mut ctx);
    Box::into_raw(Box::new(
        // SAFETY: We initialized `ctx`
        unsafe { ctx.assume_init() },
    ))
}

/// Calls [`evp_cipher_ctx_cleanup`] then frees `ctx`.
///
/// # Safety
///
/// - If non-null, `ctx` must have been initialized with
///   `EVP_CIPHER_CTX_init`.
pub unsafe fn evp_cipher_ctx_free(ctx: *mut EVP_CIPHER_CTX) {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx`.
    let Ok(ctx) = try_ptr_as_mut!(@unsafe ctx) else {
        return;
    };
    // SAFETY: See the above safety comment.
    let cipher = unsafe { Box::from_raw(ctx) };
    drop(cipher);
}

/// Initializes `ctx`.
pub fn evp_cipher_ctx_init(ctx: &mut MaybeUninit<EVP_CIPHER_CTX>) {
    ctx.write(EVP_CIPHER_CTX::default());
}

/// Releases all resources used by `ctx`, but does not free `ctx`
/// itself.
///
/// # Safety
///
/// - If non-null, `ctx` must have been initialized with
///   `EVP_CIPHER_CTX_init`.
pub unsafe fn evp_cipher_ctx_cleanup(_ctx: *mut EVP_CIPHER_CTX) -> Result<(), Infallible> {
    // NB: This returns `Result<(), Infallible>` beause
    // `EVP_CIPHER_CTX_cleanup` "[always] returns one."

    todo!()
}

/// Configures `ctx`.
///
/// - `engine` must be null.
/// - If `enc` is 0 or 1, `key` and `iv` must be non-null.
/// - If `enc` is -1, either or both of `key` and `iv` may be
///   null to reuse the existing values.
///
/// # Safety
///
/// - `ctx` must have been initialized by
///   [`evp_cipher_ctx_init`].
/// - `ctx` must be non-null and suitably aligned.
/// - `cipher` must be non-null and suitably aligned.
/// - If non-null, `key` must be suitably aligned.
/// - `key` must be valid for reads up to
///   [`EVP_CIPHER::key_length`] bytes.
/// - If non-null, `iv` must be suitably aligned.
/// - `iv` must be valid for reads up to
///   [`EVP_CIPHER::iv_length`] bytes.
pub unsafe fn evp_cipher_init_ex(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    engine: *const ENGINE,
    key: *const u8,
    iv: *const u8,
    enc: c_int,
) -> Result<(), Error> {
    // Ensure that `ctx` is valid even if we return an error.
    //
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let ctx = try_ptr_as_mut!(@unsafe ctx)?;

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `cipher`.
    let vtable = try_ptr_as_ref!(@unsafe cipher)?;

    if !engine.is_null() {
        return Err(invalid_arg("engine", "pointer must be null"));
    }

    let key = {
        let key_len = vtable.key_length();
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `key`.
        // - We have to trust that `key` is valid for reads up to
        //   `key_len` bytes.
        // - We checked that `key` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `key`.
        try_from_raw_parts!(@unsafe key, key_len)?;
    };

    let iv = {
        let iv_len = vtable.iv_length();
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `iv`.
        // - We have to trust that `iv` is valid for reads up to
        //   `iv_len` bytes.
        // - We checked that `iv` does not alias `out`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `iv`.
        try_from_raw_parts!(@unsafe iv, iv_len)?;
    };

    ctx.init(vtable, key, iv)
        .map_err(|_| "unable to initialize cipher")?;

    Ok(())
}

/// Calls `evp_cipher_init_ex(..., 1)`.
///
/// # Safety
///
/// See [`evp_cipher_init_ex`].
pub unsafe fn evp_encrypt_init_ex(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    engine: *const ENGINE,
    key: *const u8,
    iv: *const u8,
) -> Result<(), Error> {
    // SAFETY: See the function's safety docs.
    unsafe { evp_cipher_init_ex(ctx, cipher, engine, key, iv, 1) }
}

/// Calls `evp_cipher_init_ex(..., 0)`.
///
/// # Safety
///
/// See [`evp_cipher_init_ex`].
pub unsafe fn evp_decrypt_init_ex(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    engine: *const ENGINE,
    key: *const u8,
    iv: *const u8,
) -> Result<(), Error> {
    // SAFETY: See the function's safety docs.
    unsafe { evp_cipher_init_ex(ctx, cipher, engine, key, iv, 0) }
}
