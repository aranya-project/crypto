//! AEAD support.
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
    zeroize::{zeroize_flat_type, Zeroize},
};
use typeid::ConstTypeId;

use crate::{
    error::{invalid_arg, Error},
    util::{
        any_overlap, inexact_overlap, less_or_eq, pedantic_slice_checks, try_from_raw_parts,
        try_from_raw_parts_mut, try_ptr_as_mut, try_ptr_as_ref,
    },
};

/// TODO
pub const MAX_AEAD_SIZE: usize = 1000;

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
    /// The type of the `Aead`.
    type_id: ConstTypeId,

    /// Initializes `ctx.inner` with [`Aead::new`].
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for the
    ///   `Aead` it will point to.
    init: unsafe fn(
        // A pointer to the uninitialized `Aead`.
        ptr: *mut MaybeUninit<ManuallyDrop<()>>,
        key: &[u8],
    ) -> Result<(), ImportError>,

    /// Drops `ptr`.
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for `Aead`
    ///   it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   `Aead` that matches `type_id`.
    /// - `ptr` must not be used after this function is called.
    cleanup: unsafe fn(ptr: *mut ManuallyDrop<()>),

    /// [`Aead::seal`].
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for `Aead`
    ///   it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   `Aead` that matches `type_id`.
    #[allow(clippy::type_complexity)]
    seal: unsafe fn(
        // A pointer to the `Aead`.
        ptr: *const (),
        dst: &mut [u8],
        nonce: &[u8],
        plaintext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), SealError>,

    /// [`Aead::seal_in_place`].
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for `Aead`
    ///   it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   `Aead` that matches `type_id`.
    #[allow(clippy::type_complexity)]
    seal_in_place: unsafe fn(
        // A pointer to the `Aead`.
        ptr: *const (),
        nonce: &[u8],
        data: &mut [u8],
        overhead: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), SealError>,

    /// [`Aead::open`].
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for `Aead`
    ///   it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   `Aead` that matches `type_id`.
    #[allow(clippy::type_complexity)]
    open: unsafe fn(
        // A pointer to the `Aead`.
        ptr: *const (),
        dst: &mut [u8],
        nonce: &[u8],
        ciphertext: &[u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError>,

    /// [`Aead::open_in_place`].
    ///
    /// # Safety
    ///
    /// - `ptr` must be non-null and suitably aligned for `Aead`
    ///   it points to.
    /// - The memory that `ptr` points to must be an initialized
    ///   `Aead` that matches `type_id`.
    #[allow(clippy::type_complexity)]
    open_in_place: unsafe fn(
        // A pointer to the `Aead`.
        ptr: *const (),
        nonce: &[u8],
        data: &mut [u8],
        overhead: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError>,
}

impl EVP_AEAD {
    #[doc(hidden)]
    pub const fn new<A: Aead>() -> Self {
        // TODO
        // const {
        //     assert!(
        //         size_of::<EVP_AEAD_CTX>() >= size_of::<EvpAeadCtx<A>>(),
        //         "bug: invalid size"
        //     );
        //     assert!(
        //         align_of::<EVP_AEAD_CTX>() >= align_of::<EvpAeadCtx<A>>(),
        //         "bug: invalid alignment"
        //     );
        // }

        Self {
            key_len: A::KEY_SIZE,
            nonce_len: A::NONCE_SIZE,
            overhead: A::OVERHEAD,
            p_max: A::MAX_PLAINTEXT_SIZE,
            c_max: A::MAX_CIPHERTEXT_SIZE,
            a_max: A::MAX_ADDITIONAL_DATA_SIZE,
            layout: Layout::new::<A>(),
            type_id: ConstTypeId::of::<A>(),
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
    pub fn key_length(&self) -> usize {
        self.key_len
    }

    /// Returns the size in bytes of the AEAD's nonce.
    #[doc(alias = "EVP_AEAD_nonce_length")]
    pub fn nonce_length(&self) -> usize {
        self.nonce_len
    }

    /// Returns the size in bytes of the AEAD's authentication
    /// overhead.
    #[doc(alias = "EVP_AEAD_max_overhead")]
    pub fn max_overhead(&self) -> usize {
        self.overhead
    }

    /// Returns the size in bytes of the AEAD's authentication
    /// overhead.
    #[doc(alias = "EVP_AEAD_max_tag_len")]
    pub fn max_tag_len(&self) -> usize {
        self.overhead
    }
}

/// Unused.
/// cbindgen:no-export
#[repr(C)]
#[non_exhaustive]
#[derive(Debug)]
pub struct ENGINE {}

/// TODO
pub const EVP_AEAD_CTX_SIZE: usize = 8 + MAX_AEAD_SIZE;

macro_rules! test {
    (
        AES_128_GCM => $aes_128_gcm:ty,
        AES_256_GCM => $aes_256_gcm:ty,
        AES_128_GCM_FOR_TLS13 => $aes_128_gcm_tls13:ty,
        AES_256_GCM_FOR_TLS13 => $aes_256_gcm_tls13:ty,
        CHACHA20_POLY1305 => $chacha20_poly1305:ty,
    ) => {
        #[repr(C)]
        union MyAeads {
        }

        impl Aeads for MyAeads {
            const AES_128_GCM:
        }
    };
}

// /// Supported AEADs.
// pub trait Aeads {
//     /// AES-128-GCM.
//     type Aes128Gcm;
//     /// AES-256-GCM.
//     type Aes256Gcm;
//     /// AES-128-GCM for TLS 1.3.
//     type Aes128GcmTls13;
//     /// AES-256-GCM for TLS 1.3.
//     type Aes256GcmTls13;
//     /// ChaCha20-Poly1305.
//     type ChaCha20Poly1305;
// }

/// Supported AEADs.
///
/// # Safety
///
/// - `Self` must be a `repr(C)` union.
/// - The size of `Self` must be exactly `MAX_SIZE` bytes.
/// - The alignment of `Self` must be exactly `MAX_ALIGN` bytes.
pub unsafe trait Aeads: Default + Sized {
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

/// A supported AEAD.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
enum Alg {
    Aes128Gcm,
    Aes256Gcm,
    Aes128GcmTls13,
    Aes256GcmTls13,
    ChaCha20Poly1305,
}

// /// TODO
// // `ManuallyDrop<MaybeUninit<T>>` is silly because
// // `MaybeUninit<T>` contains a `ManuallyDrop<T>`, but oh well.
// #[repr(C)]
// pub union EvpAeadCtxAead<T: Aeads> {
//     aes_128_gcm: ManuallyDrop<MaybeUninit<T::Aes128Gcm>>,
//     aes_256_gcm: ManuallyDrop<MaybeUninit<T::Aes256Gcm>>,
//     aes_128_gcm_tls13: ManuallyDrop<MaybeUninit<T::Aes128GcmTls13>>,
//     aes_256_gcm_tls13: ManuallyDrop<MaybeUninit<T::Aes256GcmTls13>>,
//     chacha20_poly1305: ManuallyDrop<MaybeUninit<T::ChaCha20Poly1305>>,
// }

// impl<T: Aeads> EvpAeadCtxAead<T> {
//     const fn uninit() -> Self {
//         Self {
//             // It doesn't really matter which field we choose
//             // since Rust unions don't have an "active field."
//             aes_128_gcm: ManuallyDrop::new(MaybeUninit::uninit()),
//         }
//     }
// }

/// An AEAD instance.
///
/// It must be initialized with [`EVP_AEAD_CTX_init`] before it
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
    /// If `self.vtable` is `Some`, then this field is initialized.
    ///
    /// # Caveats
    ///
    /// It is obviously very easy for C code to corrupt memory,
    /// so this is a best-effort attempt. We can't control what
    /// other languages do to violate Rust's invariants.
    aead: ManuallyDrop<T>,
}

impl<T: Aeads> EVP_AEAD_CTX<T> {
    /// Invokes `f` with the [`EVP_AEAD`] and a pointer to the
    /// [`Aead`].
    ///
    /// It returns [`Err(Bug)`] if `self` is not initialized or
    /// if the [`EVP_AEAD`] refers to an unknown [`Aead`].
    fn with_aead<F, R>(&self, f: F) -> Result<R, Bug>
    where
        F: FnOnce(&EVP_AEAD, *const ()) -> R,
    {
        let Some(aead) = self.vtable else {
            bug!("`EVP_AEAD_CTX` is not initialized");
        };

        // // SAFETY:
        // // - We check the type of `self.aead`.
        // // - `self.vtable` is `Some`, so `self.aead` is
        // //   initialized.
        // let ptr = unsafe {
        //     // Use `MaybeUninit::as_ptr` to avoid
        //     // `assume_init_ref` gymnastics.
        //     match aead.alg::<T>()? {
        //         Alg::Aes128Gcm => self.aead.aes_128_gcm.as_ptr().cast::<()>(),
        //         Alg::Aes256Gcm => self.aead.aes_256_gcm.as_ptr().cast::<()>(),
        //         Alg::Aes128GcmTls13 => self.aead.aes_128_gcm_tls13.as_ptr().cast::<()>(),
        //         Alg::Aes256GcmTls13 => self.aead.aes_256_gcm_tls13.as_ptr().cast::<()>(),
        //         Alg::ChaCha20Poly1305 => self.aead.chacha20_poly1305.as_ptr().cast::<()>(),
        //     }
        // };
        let ptr = ptr::addr_of!(self.vtable).cast::<()>();

        Ok(f(aead, ptr))
    }

    fn init(&mut self, aead: &'static EVP_AEAD, key: &[u8]) -> Result<(), ImportError> {
        // // SAFETY: We check the type of `self.aead`.
        // let ptr = unsafe {
        //     // Use `MaybeUninit::as_mut_ptr` to avoid
        //     // `assume_init_ref` gymnastics.
        //     match aead.alg::<T>()? {
        //         Alg::Aes128Gcm => {
        //             ptr::addr_of_mut!(self.aead.aes_128_gcm).cast::<MaybeUninit<()>>()
        //         }
        //         Alg::Aes256Gcm => {
        //             ptr::addr_of_mut!(self.aead.aes_256_gcm).cast::<MaybeUninit<()>>()
        //         }
        //         Alg::Aes128GcmTls13 => {
        //             ptr::addr_of_mut!(self.aead.aes_128_gcm_tls13).cast::<MaybeUninit<()>>()
        //         }
        //         Alg::Aes256GcmTls13 => {
        //             ptr::addr_of_mut!(self.aead.aes_256_gcm_tls13).cast::<MaybeUninit<()>>()
        //         }
        //         Alg::ChaCha20Poly1305 => {
        //             ptr::addr_of_mut!(self.aead.chacha20_poly1305).cast::<MaybeUninit<()>>()
        //         }
        //     }
        // };
        let ptr = ptr::addr_of_mut!(self.vtable).cast::<MaybeUninit<ManuallyDrop<()>>>();

        // SAFETY: `ptr` is non-null and suitably aligned for
        // the `Aead`.
        unsafe { (aead.init)(ptr, key)? }

        // Only set `self.vtable` after we've initialized
        // `self.aead` since this field indicates whether
        // `self.aead` is initialized.
        self.vtable = Some(aead);

        Ok(())
    }

    fn cleanup(&mut self) -> Result<(), Bug> {
        let Some(aead) = self.vtable.take() else {
            bug!("`EVP_AEAD_CTX` is not initialized");
        };

        // // SAFETY:
        // // - We check the type of `self.aead`.
        // // - `self.vtable` is (well, was) `Some`, so `self.aead`
        // //   is initialized (see `self.aead`'s docs for
        // //   caveats).
        // unsafe {
        //     match aead.alg::<T>()? {
        //         Alg::Aes128Gcm => (&mut self.aead.aes_128_gcm).assume_init_drop(),
        //         Alg::Aes256Gcm => (&mut self.aead.aes_256_gcm).assume_init_drop(),
        //         Alg::Aes128GcmTls13 => (&mut self.aead.aes_128_gcm_tls13).assume_init_drop(),
        //         Alg::Aes256GcmTls13 => (&mut self.aead.aes_256_gcm_tls13).assume_init_drop(),
        //         Alg::ChaCha20Poly1305 => (&mut self.aead.chacha20_poly1305).assume_init_drop(),
        //     }
        // };
        let ptr = ptr::addr_of_mut!(self.vtable).cast::<ManuallyDrop<()>>();

        unsafe { (aead.cleanup)(ptr) }

        // Clobber `self.aead` in case the `Aead` isn't
        // `ZeroizeOnDrop`.
        //
        // NB: This is safe because every field in `self.aead`
        // is `MaybeUninit` and `MaybeUninit` is valid for every
        // bit pattern.
        unsafe { zeroize_flat_type(&mut self.vtable) }

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

impl<T: Default> Default for EVP_AEAD_CTX<T> {
    #[inline]
    fn default() -> Self {
        Self {
            vtable: None,
            aead: ManuallyDrop::new(T::default()),
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

/// Used when reading/writing to [`EVP_AEAD_CTX.inner`].
#[doc(hidden)]
#[repr(C)]
#[non_exhaustive]
#[derive(Debug)]
pub struct EvpAeadCtx<A> {
    /// The AEAD algorithm.
    ///
    /// The [NPO] guarantees that this is safe to use with zeroed
    /// memory.
    ///
    /// [NPO]: https://doc.rust-lang.org/std/option/index.html#representation
    aead: Option<&'static EVP_AEAD>,
    /// The `Aead` instance.
    ///
    /// If `self.vtable` is `Some`, then this field is initialized.
    ///
    /// # Caveats
    ///
    /// It is obviously very easy for C code to corrupt memory,
    /// so this is a best-effort attempt. We can't control what
    /// other languages do to violate Rust's invariants.
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
/// `ctx` must still be initialized with [`EVP_AEAD_CTX_init`]
/// before use.
///
/// It is safe to call [`EVP_AEAD_CTX_cleanup`] after calling
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
/// - `key_len` must be less than or equal to [`isize::MAX`].
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
    let aead = try_ptr_as_ref!(@unsafe aead)?;

    if !is_known_aead::<T>(aead) {
        return Err(invalid_arg("aead", "unknown `EVP_AEAD`"));
    }

    let key = {
        if key_len != aead.key_len {
            return Err(invalid_arg("key_len", "invalid key length"));
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
        return Err(invalid_arg("impl_", "pointer must be null"));
    }

    if tag_len != 0 && tag_len != aead.overhead {
        return Err(invalid_arg("tag_len", "invalid tag length"));
    }

    ctx.init(aead, key)
        .map_err(|_| "unable to initialize `Aead`")?;

    Ok(())
}

#[inline]
fn is_known_aead<T: Aeads>(aead: &EVP_AEAD) -> bool {
    aead.alg::<T>().is_ok()
}

/// Frees all resources used by `ctx`.
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

    let Some(aead) = ctx.vtable else {
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
        if nonce_len != aead.nonce_len {
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

    if !less_or_eq(in_len, aead.p_max) {
        return Err(SealError::PlaintextTooLong.into());
    }
    // Sanity check `in_`, but don't convert it to a slice yet
    // because it might alias `out`.
    pedantic_slice_checks(in_, in_len).map_err(|msg| invalid_arg("in_, in_len", msg))?;

    let additional_data = {
        if any_overlap(out, max_out_len, ad, ad_len) {
            return Err(invalid_arg("ad", "cannot overlap with `out`"));
        }
        if !less_or_eq(ad_len, aead.a_max) {
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
    let Some(nw) = in_len.checked_add(aead.overhead) else {
        return Err(SealError::Other("`in_` too large").into());
    };

    // SAFETY:
    // - We have to trust that `out` is valid for reads up to
    //   `max_out_len` bytes.
    // - We have to trust that the caller upholds Rust's aliasing
    //   requirements for any other uses of `out`.
    let out = try_from_raw_parts_mut!(@unsafe out, max_out_len)?;
    if out.len() < nw {
        return Err(SealError::BufferTooSmall(BufferTooSmallError(Some(aead.overhead))).into());
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
#[allow(clippy::too_many_arguments, reason = "I didn't come up with the API")]
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

    let Some(aead) = ctx.vtable else {
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
        if nonce_len != aead.nonce_len {
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

    if !less_or_eq(in_len, aead.p_max) {
        return Err(OpenError::PlaintextTooLong.into());
    }
    // Sanity check `in_`, but don't convert it to a slice yet
    // because it might alias `out`.
    pedantic_slice_checks(in_, in_len).map_err(|msg| invalid_arg("in_, in_len", msg))?;

    let additional_data = {
        if any_overlap(out, max_out_len, ad, ad_len) {
            return Err(invalid_arg("ad", "cannot overlap with `out`"));
        }
        if !less_or_eq(ad_len, aead.a_max) {
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
    let Some(nw) = in_len.checked_sub(aead.overhead) else {
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
        return Err(OpenError::BufferTooSmall(BufferTooSmallError(Some(aead.overhead))).into());
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
