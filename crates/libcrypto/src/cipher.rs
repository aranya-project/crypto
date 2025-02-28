//! `cipher.h`

#![allow(non_camel_case_types)]

use alloc::boxed::Box;
use core::{
    convert::Infallible,
    ffi::{c_int, c_void},
    mem::MaybeUninit,
    ptr, slice,
};

use buggy::{bug, Bug, BugExt};
use cipher::{Block, BlockDecryptMut, BlockEncryptMut, KeyInit};
use inout::{InOutBuf, InOutBufReserved};
use spideroak_crypto::{typenum::Unsigned, zeroize::Zeroize};

use crate::{
    aead::ENGINE,
    error::{invalid_arg, Error},
    util::{
        any_overlap, inexact_overlap, less_or_eq, pedantic_slice_checks, try_from_raw_parts,
        try_from_raw_parts_mut, try_from_raw_parts_opt, try_from_raw_parts_opt_mut, try_ptr_as_mut,
        try_ptr_as_opt_ref, try_ptr_as_ref, Void,
    },
};

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum EncOpt {
    Reuse = -1,
    Decrypt = 0,
    Encrypt = 1,
}

impl TryFrom<c_int> for EncOpt {
    type Error = &'static str;
    fn try_from(enc: c_int) -> Result<Self, Self::Error> {
        match enc {
            -1 => Ok(Self::Reuse),
            0 => Ok(Self::Decrypt),
            1 => Ok(Self::Encrypt),
            _ => Err("invalid option"),
        }
    }
}

enum Input<'inp, 'out> {
    /// AAD.
    Ad(&'out [u8]),
    /// Plaintext or ciphertext.
    Data(InOutBufReserved<'inp, 'out, u8>),
}

impl<'inp, 'out> Input<'inp, 'out> {
    const fn from_ad(ad: &'out [u8]) -> Self {
        Self::Ad(ad)
    }

    const fn from_data(data: InOutBufReserved<'inp, 'out, u8>) -> Self {
        Self::Data(data)
    }

    fn is_empty(&self) -> bool {
        match self {
            Self::Ad(ad) => ad.is_empty(),
            Self::Data(msg) => msg.get_in().is_empty(),
        }
    }
}

/// A specific cipher algorithm.
#[repr(C)]
#[non_exhaustive]
#[derive(Debug)]
pub struct EVP_CIPHER {
    /// TODO(eric): keep this?
    nid: i32,

    /// The size in bytes of the cipher's key.
    key_len: usize,

    /// The size in bytes of the cipher's IV, or zero if the
    /// cipher does not use an IV.
    iv_len: usize,

    /// The size in bytes of the cipher's block, or one if the
    /// cipher is not a block cipher.
    block_size: usize,

    /// Is this cipher an AEAD?
    is_aead: bool,

    /// Returns a pointer to an initialized cipher.
    ///
    /// # Safety
    ///
    /// - `ptr` (both levels) must be suitably aligned for the
    ///   types they points to.
    init: unsafe fn(ptr: *mut *mut Void, key: &[u8], iv: &[u8]) -> Result<(), &'static str>,

    /// Drops `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   type it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   type.
    /// - `ptr` must not be used after this function is called.
    /// - `ptr` must have been allocated by `init`.
    cleanup: unsafe fn(ptr: *mut Void),

    /// Invokes the cipher.
    ///
    /// It returns the number of bytes written to `out`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   type it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   type.
    /// - You must uphold Rust's aliasing invariants. In
    ///   particular, `ptr` must not alias or be used for the
    ///   duration of this function call.
    cipher: unsafe fn(ptr: *mut Void, data: Input<'_, '_>, encrypt: bool) -> Result<usize, Error>,

    /// Finalizes the cipher.
    ///
    /// It returns the number of bytes written to `out`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   type it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   type.
    /// - You must uphold Rust's aliasing invariants. In
    ///   particular, `ptr` must not alias or be used for the
    ///   duration of this function call.
    finalize: unsafe fn(ptr: *mut Void, out: &mut [u8], encrypt: bool) -> Result<usize, Error>,
}

impl EVP_CIPHER {
    #[doc(hidden)]
    pub const fn from_block_cipher<T: KeyInit + BlockEncryptMut + BlockDecryptMut>() -> Self {
        Self {
            nid: 0,
            key_len: <T::KeySize as Unsigned>::USIZE,
            iv_len: 0,
            block_size: <T::BlockSize as Unsigned>::USIZE,
            is_aead: false,
            init: |ptr, key, _iv| {
                debug_assert!(!ptr.is_null());

                let cipher = {
                    let cipher =
                        BlockCipher::new(T::new_from_slice(key).map_err(|_| "invalid key length")?);
                    Box::into_raw(Box::new(cipher))
                };
                // SAFETY: See the function pointer's safety
                // docs.
                unsafe { ptr.cast::<*mut BlockCipher<T>>().write(cipher) }

                Ok(())
            },
            cipher: |ptr, data, encrypt| {
                debug_assert!(!ptr.is_null());

                let Input::Data(data) = data else {
                    // All code paths should have checked for
                    // this by this point.
                    bug!("not an AEAD");
                };

                // SAFETY: See the function pointer's safety
                // docs.
                let cipher = unsafe { &mut *(ptr.cast::<BlockCipher<T>>()) };

                let n = if encrypt {
                    cipher.encrypt(data)?
                } else {
                    cipher.decrypt(data)?
                };
                Ok(n)
            },
            finalize: |ptr, out, encrypt| {
                debug_assert!(!ptr.is_null());

                // SAFETY: See the function pointer's safety
                // docs.
                let cipher = unsafe { &mut *(ptr.cast::<BlockCipher<T>>()) };

                let n = if encrypt {
                    cipher.finalize(out)?
                } else {
                    cipher.finalize(out)?
                };
                Ok(n)
            },
            cleanup: |ptr| {
                debug_assert!(!ptr.is_null());

                // SAFETY: See the function pointer's safety
                // docs.
                let aead = unsafe { &mut *(ptr.cast::<ManuallyDrop<A>>()) };
                // SAFETY: See the function pointer's safety
                // docs.
                unsafe { ManuallyDrop::drop(aead) }
            },
        }
    }
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

    /// Returns the size in bytes of the cipher's block, or one
    /// if `self` is a stream cipher.
    #[doc(alias = "EVP_CIPHER_block_size")]
    pub const fn block_size(&self) -> usize {
        self.block_size
    }
}

/// A block cipher.
struct BlockCipher<B: BlockEncryptMut + BlockDecryptMut> {
    cipher: B,
    partial: Block<B>,
    /// Index into `partial`.
    idx: usize,
}

impl<B: BlockEncryptMut + BlockDecryptMut> BlockCipher<B> {
    const BLOCK_SIZE: usize = <B::BlockSize as Unsigned>::USIZE;

    fn new(cipher: B) -> Self {
        Self {
            cipher,
            partial: Block::<B>::default(),
            idx: 0,
        }
    }

    /// Returns the number of bytes written.
    fn finalize(&mut self, out: &mut [u8]) -> Result<usize, Bug> {
        if self.idx > 0 {}
        todo!()
    }

    /// Returns the number of bytes written.
    fn encrypt(&mut self, data: InOutBufReserved<'_, '_, u8>) -> Result<usize, Bug> {
        let nblocks = self.xcrypt(
            data,
            B::encrypt_blocks_inout_mut,
            B::encrypt_block_b2b_mut,
            B::encrypt_block_mut,
        )?;
        Ok(nblocks * Self::BLOCK_SIZE)
    }

    /// Returns the number of bytes written.
    fn decrypt(&mut self, data: InOutBufReserved<'_, '_, u8>) -> Result<usize, Bug> {
        let nblocks = self.xcrypt(
            data,
            B::decrypt_blocks_inout_mut,
            B::decrypt_block_b2b_mut,
            B::decrypt_block_mut,
        )?;
        Ok(nblocks * Self::BLOCK_SIZE)
    }

    /// Returns the number of **blocks** written.
    fn xcrypt<F1, F2, F3>(
        &mut self,
        mut data: InOutBufReserved<'_, '_, u8>,
        mut crypt_blocks: F1,
        mut crypt_block_b2b: F2,
        mut crypt_block: F3,
    ) -> Result<usize, Bug>
    where
        F1: FnMut(&mut B, InOutBuf<'_, '_, Block<B>>),
        F2: FnMut(&mut B, &Block<B>, &mut Block<B>),
        F3: FnMut(&mut B, &mut Block<B>),
    {
        if !data
            .get_out_len()
            .checked_sub(data.get_in_len())
            .is_some_and(|n| n >= Self::BLOCK_SIZE)
        {
            bug!("ouput should be at least one block size larger than input")
        }
        // Here we know that:
        // - `out` is at least 1 block size larger than `in`
        // - `out` and `in` either overlap exactly (up to
        //   `in_len`) or not at all.

        if data.get_in_len() == 0 {
            return Ok(0);
        }

        // Fast path: We don't have any partial blocks.
        if self.idx == 0 {
            let data = {
                let in_len = data.get_in_len();
                let (in_ptr, out_ptr) = data.into_raw();
                // SAFETY: All arguments come from
                // `InOutBufReserved`. We're just truncating the
                // length of `out_ptr` down to `in_len`.
                unsafe { InOutBuf::from_raw(in_ptr, out_ptr, in_len) }
            };
            let (head, tail) = data.into_chunks();
            let nblocks = head.len();
            crypt_blocks(&mut self.cipher, head);

            let tail = tail.get_in();
            if !tail.is_empty() {
                self.partial[..tail.len()].copy_from_slice(tail);
                self.idx = tail.len();
            }
            return Ok(nblocks);
        }

        // Figure out the number of bytes needed to fill the
        // partial block.
        let n = self
            .partial
            .len()
            .checked_sub(self.idx)
            .assume("`idx` is a valid index into `self.partial`")?
            .min(data.get_in_len());

        // This would be nicer as
        //   let (head, tail) = data.get_in().split_at(n);
        // but we can't hold the shared borrow of `tail` during
        // the call to `data.get_out()`.
        self.partial[self.idx..].copy_from_slice(&data.get_in()[..n]);
        self.idx += n;
        if self.idx < self.partial.len() {
            // Still don't have a full block.
            return Ok(0);
        }
        debug_assert!(self.idx == self.partial.len());

        // We have a full block.
        let out = data
            .get_out()
            .get_mut(..self.partial.len())
            .assume("`data.get_out()` should have space for at least one block")?
            .try_into()
            .assume("`data.get_out()` should have space for at least one block")?;

        crypt_block_b2b(&mut self.cipher, &self.partial, out);

        let tail = &data.get_in()[n..];
        if tail.len() < self.partial.len() {
            // We only have a partial block left.
            self.partial.copy_from_slice(tail);
            self.idx = tail.len();
            return Ok(1);
        }

        // We just wrote one block to `out` and read [1,
        // BLOCK_SIZE-1] bytes from `in`. This means that `out`
        // might be `BLOCK_SIZE-1` bytes ahead if `in`, which is
        // problematic: `in` and `out` need to overlap entirely
        // or not at all.

        let mut in_len = data.get_in_len() - n;
        let out_len = data.get_out_len() - Self::BLOCK_SIZE;

        if out_len < in_len {
            bug!("`out_len` < `in_len`")
        }

        let (in_ptr, out_ptr) = data.into_raw();
        if in_ptr != out_ptr.cast_const() {
            let (head, tail) = {
                // They don't overlap, so just proceed like
                // normal (ish).
                //
                // SAFETY:
                // - All the arguments come from
                //   `InOutBufReserved`.
                // - We double checked that `in_len <= `out_len.
                let data = unsafe { InOutBuf::from_raw(in_ptr, out_ptr, in_len) };
                data.into_chunks()
            };
            let nblocks = head.len();
            self.cipher.encrypt_blocks_inout_mut(head);

            let tail = tail.get_in();
            if !tail.is_empty() {
                self.partial[..tail.len()].copy_from_slice(tail);
                self.idx = tail.len();
            }
            // +1 because we already wrote one block.
            return Ok(nblocks + 1);
        }

        let nblocks = in_len / Self::BLOCK_SIZE;
        for i in 0..nblocks {
            // SAFETY:
            // - We checked that there are enough blocks
            //   remaining in `in`.
            // - `u8` and `Block<B>` have the same alignment.
            let mut src = unsafe { in_ptr.cast::<Block<B>>().add(i).read() };

            crypt_block(&mut self.cipher, &mut src);

            // SAFETY:
            // - `out` is larger than `in`, so if we can read
            //   a block from `in` we can write a block to `out`.
            // - `u8` and `Block<B>` have the same alignment.
            unsafe { out_ptr.cast::<Block<B>>().add(i).write(src) }
        }

        in_len %= Self::BLOCK_SIZE;
        if in_len > 0 {
            // SAFETY:
            // - `nblocks` is `in_len/BLOCK_SIZE`, so
            //   `nblocks*BLOCK_SIZE` points in the allocation.
            let tail = unsafe {
                slice::from_raw_parts(in_ptr.byte_add(nblocks * Self::BLOCK_SIZE), in_len)
            };
            self.partial[..tail.len()].copy_from_slice(tail);
            self.idx = tail.len();
        }

        // +1 because we already wrote one block.
        Ok(nblocks + 1)
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

    /// The cipher instance.
    ///
    /// # Invariants:
    ///
    /// - If non-null, then this field is suitably aligned and
    ///   the memory it points to is initialized.
    ///
    /// # Caveats
    ///
    /// It is obviously very easy for C code to corrupt memory,
    /// so this is a best-effort attempt. We can't control what
    /// other languages do to violate Rust's invariants.
    cipher: *mut Void,

    /// Are we encrypting or decrypting?
    encrypt: bool,

    /// Is padding enabled?
    pad: bool,
}

impl EVP_CIPHER_CTX {
    fn init(
        &mut self,
        vtable: &'static EVP_CIPHER,
        key_iv: Option<(&[u8], &[u8])>,
        enc: EncOpt,
    ) -> Result<(), Error> {
        if self.vtable.is_some() {
            self.cleanup()?;
        }
        debug_assert!(self.vtable.is_none());

        self.vtable = Some(vtable);

        if enc != EncOpt::Reuse {
            self.encrypt = enc == EncOpt::Encrypt;
        }

        if let Some((key, iv)) = key_iv {
            let ptr = ptr::addr_of_mut!(self.cipher);
            // SAFETY: See `self.cipher`'s docs.
            unsafe { (vtable.init)(ptr, key, iv)? };
        }

        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Bug> {
        let Some(vtable) = self.vtable.take() else {
            // All code paths should have checked `self.vtable`
            // by this point.
            bug!("`EVP_CIPHER_CTX` is not initialized");
        };
        debug_assert!(!self.cipher.is_null());

        if !self.cipher.is_null() {
            // SAFETY:
            // - `self.cipher` is non-null and suitably aligned
            //   for the type it points to.
            // - The memory `ptr` points to is initialized
            //   because `vtable` is (was) `Some`.
            unsafe { (vtable.cleanup)(self.cipher) }
        }
        self.cipher = ptr::null_mut();

        Ok(())
    }

    fn finalize(&mut self, out: &mut [u8], encrypt: bool) -> Result<usize, Error> {
        let Some(vtable) = self.vtable else {
            // All code paths should have checked `self.vtable`
            // by this point.
            bug!("`EVP_CIPHER_CTX` is not initialized");
        };

        if self.cipher.is_null() {
            // TODO(eric): is it possible for `self.cipher` to be
            // null but `self.vtable` to be `Some`?
            return Err("`EVP_CIPHER_CTX` is not initialized".into());
        }

        // SAFETY:
        // - `self.cipher` is non-null and suitably aligned for
        //   the type it points to.
        // - The memory that `self.cipher` points to is
        //   initialized (see `self.cipher`'s docs).
        let nw = unsafe { (vtable.finalize)(self.cipher, out, encrypt)? };

        // TODO(eric): There are better ways of doing this
        // without actually calling `finalize` and undoing the
        // work we did if padding is disabled.
        if encrypt && nw > 0 && !self.pad {
            out.zeroize();
            return Err("partial block, but padding is disabled".into());
        }

        Ok(nw)
    }

    /// Returns the number of bytes written.
    fn encrypt(&mut self, data: Input<'_, '_>) -> Result<usize, Error> {
        self.cipher(data, true)
    }

    /// Returns the number of bytes written.
    fn decrypt(&mut self, data: Input<'_, '_>) -> Result<usize, Error> {
        self.cipher(data, false)
    }

    /// Returns the number of bytes written.
    fn cipher(&mut self, data: Input<'_, '_>, encrypt: bool) -> Result<usize, Error> {
        let Some(vtable) = self.vtable else {
            // All code paths should have checked `self.vtable`
            // by this point.
            bug!("`EVP_CIPHER_CTX` is not initialized");
        };

        if self.cipher.is_null() {
            // TODO(eric): is it possible for `self.cipher` to be
            // null but `self.vtable` to be `Some`?
            return Err("`EVP_CIPHER_CTX` is not initialized".into());
        }

        if data.is_empty() {
            // Nothing to do here.
            return Ok(0);
        }

        // SAFETY:
        // - `self.cipher` is non-null and suitably aligned for
        //   the type it points to.
        // - The memory that `self.cipher` points to is
        //   initialized (see `self.cipher`'s docs).
        let nw = unsafe { (vtable.cipher)(self.cipher, data, encrypt)? };

        Ok(nw)
    }
}

impl Default for EVP_CIPHER_CTX {
    #[inline]
    fn default() -> Self {
        Self {
            vtable: None,
            cipher: ptr::null_mut(),
            encrypt: false,
            pad: true,
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
///   [`evp_cipher_ctx_init`]
pub unsafe fn evp_cipher_ctx_cleanup(_ctx: *mut EVP_CIPHER_CTX) -> Result<(), Infallible> {
    // NB: This returns `Result<(), Infallible>` beause
    // `EVP_CIPHER_CTX_cleanup` "[always] returns one."

    todo!()
}

/// Sets `EVP_`
///
/// # Safety
///
/// - `ctx` must have been initialized with
///   [`evp_cipher_ctx_init`].
pub unsafe fn evp_cipher_ctx_ctrl(
    ctx: *mut EVP_CIPHER_CTX,
    _command: c_int,
    _arg: c_int,
    _ptr: *mut c_void,
) -> Result<(), Error> {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx` with
    //   `evp_cipher_ctx_init`.
    let _ctx = try_ptr_as_mut!(@unsafe ctx)?;

    Err("unsupported".into())
}

/// Enables or disables padding.
pub fn evp_cipher_ctx_set_padding(ctx: &mut EVP_CIPHER_CTX, pad: c_int) -> Result<(), Infallible> {
    // NB: This returns `Result<(), Infallible>` beause
    // `EVP_CIPHER_CTX_set_padding` "[always] returns one."

    ctx.pad = pad != 0;

    Ok(())
}

/// Configures `ctx`.
///
/// - `ctx` must be non-null and suitably aligned.
/// - If `cipher` is null, then `ctx` must have already been
///   initialized with an `EVP_CIPHER`.
/// - `engine` must be null.
/// - If non-null, `key` must be suitably aligned.
/// - If non-null, `iv` must be suitably aligned.
/// - TODO(eric): null/non-null requirements for `key`, `iv`
///
/// # Safety
///
/// - `ctx` must have been initialized by
///   [`evp_cipher_ctx_init`].
/// - If non-null, `cipher` must be initialized and suitably
///   aligned.
/// - If non-null, `key` must be valid for reads up to
///   [`EVP_CIPHER::key_length`] bytes.
/// - If non-null, `iv` must be valid for reads up to
///   [`EVP_CIPHER::iv_length`] bytes.
pub unsafe fn evp_cipher_init_ex(
    ctx: *mut EVP_CIPHER_CTX,
    cipher: *const EVP_CIPHER,
    engine: *const ENGINE,
    key: *const u8,
    iv: *const u8,
    enc: c_int,
) -> Result<(), Error> {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx` with
    //   `evp_cipher_ctx_init`.
    let ctx = try_ptr_as_mut!(@unsafe ctx)?;

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that, if non-null, the caller
    //   initialized `cipher`.
    let Some(vtable) = try_ptr_as_opt_ref!(@unsafe cipher)?.or_else(|| ctx.vtable) else {
        return Err(invalid_arg(
            "cipher",
            "pointer is null and no previous `EVP_CIPHER` set",
        ));
    };

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
        // - We have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `key`.
        try_from_raw_parts_opt!(@unsafe key, key_len)?
    };

    let iv = {
        let iv_len = vtable.iv_length();
        // SAFETY:
        // - We have to trust that the caller has initialized
        //   `iv`.
        // - We have to trust that `iv` is valid for reads up to
        //   `iv_len` bytes.
        // - We have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `iv`.
        try_from_raw_parts_opt!(@unsafe iv, iv_len)?
    };

    let key_iv = match (key, iv) {
        (Some(key), Some(iv)) => Some((key, iv)),
        (None, None) => None,
        _ => {
            return Err(invalid_arg(
                "key, iv",
                "one pointer is null, one pointer is non-null",
            ))
        }
    };

    let enc = EncOpt::try_from(enc).map_err(|msg| invalid_arg("enc", msg))?;

    ctx.init(vtable, key_iv, enc)?;

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

/// Encrypts `in_len` bytes to `out`. The total number of bytes
/// written to `out` is written to `out_len`.
///
/// If `ctx` is an AEAD and `out` is null, this function writes
/// exactly `in_len` bytes of additional authenticated data from
/// `in`. The additional authenticated data must be added before
/// encryption.
///
/// - `ctx` must be non-null and suitably aligned.
/// - If non-null, `out` must be suitably aligned.
/// - `out` may only be non-null if writing AAD; see above.
/// - `in_len` must be at least zero and less than
///   `min(c_int::MAX, isize::MAX)` less the block size.
///
/// # Safety
///
/// - `ctx` must have been initialized by
///   [`evp_cipher_ctx_init`].
/// - `out` must be valid for writes up to `in_len` bytes plus
///   the block size less one.
/// - `in` must be valid for reads up to `in_len` bytes.
pub unsafe fn evp_encrypt_update(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    out_len: *mut MaybeUninit<c_int>,
    in_: *const u8,
    in_len: c_int,
) -> Result<(), Error> {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx` with
    //   `evp_cipher_ctx_init`.
    let ctx = try_ptr_as_mut!(@unsafe ctx)?;

    let Some(vtable) = ctx.vtable else {
        return Err(invalid_arg("ctx", "not initialized"));
    };

    if ctx.pad {
        return Err("padding is not supported".into());
    }

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let out_len = try_ptr_as_mut!(@unsafe out_len)?;

    let Ok(in_len) = usize::try_from(in_len) else {
        return Err(invalid_arg("in_len", "less than zero"));
    };

    let Some(max_out_len) = in_len.checked_add(vtable.block_size - 1) else {
        return Err(invalid_arg("in_len", "too large"));
    };

    // Sanity check `out`, but don't convert it to a slice yet
    // because it might alias `in_`.
    pedantic_slice_checks(out, max_out_len).map_err(|msg| invalid_arg("out, max_out_len", msg))?;

    // Sanity check `in_`, but don't convert it to a slice yet
    // because it might alias `out`.
    pedantic_slice_checks(in_, in_len).map_err(|msg| invalid_arg("in_, in_len", msg))?;

    if inexact_overlap(out, max_out_len, in_, in_len) {
        return Err(invalid_arg(
            "out, in_",
            "must overlap entirely or not at all",
        ));
    }

    let nw = if out.is_null() {
        // SAFETY:
        // - We have to trust that `in_` is valid for reads up to
        //   `in_len` bytes.
        // - We checked that `in_` does not alias `out_`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `in_`.
        let in_ = try_from_raw_parts!(@unsafe in_, in_len)?;
        ctx.encrypt(Input::from_ad(in_))?
    } else {
        // SAFETY:
        // - We performed the required checks; see basically all
        //   the cove above.
        let data = unsafe { InOutBufReserved::from_raw(in_, in_len, out, max_out_len) };
        ctx.encrypt(Input::from_data(data))?
    };

    out_len.write(nw.try_into().assume("should fit in `usize`")?);

    Ok(())
}

/// Decrypts `in_len` bytes from `in_` to `out`. The total number
/// of bytes written to `out` is written to `out_len`.
///
/// If `ctx` is an AEAD and `out` is null, this function writes
/// exactly `in_len` bytes of additional authenticated data from
/// `in`. The additional authenticated data must be added before
/// encryption.
///
/// - `ctx` must be non-null and suitably aligned.
/// - If non-null, `out` must be suitably aligned.
/// - `out` may only be non-null if writing AAD; see above.
/// - `in_len` must be at least zero and less than
///   `min(c_int::MAX, isize::MAX)` less the block size.
///
/// # Safety
///
/// - `ctx` must have been initialized by
///   [`evp_cipher_ctx_init`].
/// - `out` must be valid for writes up to `in_len` bytes plus
///   the block size less one.
/// - `in` must be valid for reads up to `in_len` bytes.
pub unsafe fn evp_decrypt_update(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    out_len: *mut MaybeUninit<c_int>,
    in_: *const u8,
    in_len: c_int,
) -> Result<(), Error> {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx` with
    //   `evp_cipher_ctx_init`.
    let ctx = try_ptr_as_mut!(@unsafe ctx)?;

    let Some(vtable) = ctx.vtable else {
        return Err(invalid_arg("ctx", "not initialized"));
    };

    if ctx.pad {
        return Err("padding is not supported".into());
    }

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let out_len = try_ptr_as_mut!(@unsafe out_len)?;

    let Ok(in_len) = usize::try_from(in_len) else {
        return Err(invalid_arg("in_len", "less than zero"));
    };

    let Some(max_out_len) = in_len.checked_add(vtable.block_size) else {
        return Err(invalid_arg("in_len", "too large"));
    };

    if inexact_overlap(out, max_out_len, in_, in_len) {
        return Err(invalid_arg(
            "out, in_",
            "must overlap entirely or not at all",
        ));
    }

    let nw = if out.is_null() {
        // SAFETY:
        // - We have to trust that `in_` is valid for reads up to
        //   `in_len` bytes.
        // - We checked that `in_` does not alias `out_`, but we
        //   still have to trust that the caller upholds Rust's
        //   aliasing requirements for any other uses of `in_`.
        let in_ = try_from_raw_parts!(@unsafe in_, in_len)?;
        ctx.decrypt(Input::from_ad(in_))?
    } else {
        // SAFETY:
        // - We performed the required checks; see basically all
        //   the cove above.
        let data = unsafe { InOutBufReserved::from_raw(in_, in_len, out, max_out_len) };
        ctx.decrypt(Input::from_data(data))?
    };
    out_len.write(nw.try_into().assume("should fit in `usize`")?);

    Ok(())
}

/// Writes at most a block of ciphertext to `out` and sets
/// `out_len` to the number of bytes written.
///
/// If padding is enabled (the default), then padding is applied
/// to create the final block. Otherwise, if padding is disabled
/// with [`evp_cipher_ctx_set_padding`], any remaining partial
/// block will cause an error.
///
/// # Safety
///
/// TODO
pub unsafe fn evp_encrypt_final_ex(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    out_len: *mut MaybeUninit<c_int>,
) -> Result<(), Error> {
    // SAFETY: See the function's safety docs.
    unsafe { evp_xcrypt_final_ex(ctx, out, out_len, true) }
}

/// Writes at most a block of plaintext to `out` and sets
/// `out_len` to the number of bytes written.
///
/// If padding is enabled (the default), then padding is removed
/// from the final block.
///
/// # Safety
///
/// TODO
pub unsafe fn evp_decrypt_final_ex(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    out_len: *mut MaybeUninit<c_int>,
) -> Result<(), Error> {
    // SAFETY: See the function's safety docs.
    unsafe { evp_xcrypt_final_ex(ctx, out, out_len, false) }
}

/// # Safety
///
/// TODO
unsafe fn evp_xcrypt_final_ex(
    ctx: *mut EVP_CIPHER_CTX,
    out: *mut u8,
    out_len: *mut MaybeUninit<c_int>,
    encrypt: bool,
) -> Result<(), Error> {
    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    // - We have to trust that the caller initialized `ctx` with
    //   `evp_cipher_ctx_init`.
    let ctx = try_ptr_as_mut!(@unsafe ctx)?;

    let Some(vtable) = ctx.vtable else {
        return Err(invalid_arg("ctx", "not initialized"));
    };

    // SAFETY:
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements.
    let out_len = try_ptr_as_mut!(@unsafe out_len)?;

    // SAFETY:
    // - We have to trust that `out` is valid for reads up to
    //   one block.
    // - We have to trust that the caller upholds Rust's
    //   aliasing invariants for other uses of `out`.
    let out = try_from_raw_parts_mut!(@unsafe out, vtable.block_size())?;

    let nw = ctx.finalize(out, encrypt)?;
    out_len.write(nw.try_into().assume("should fit in `usize`")?);

    Ok(())
}
