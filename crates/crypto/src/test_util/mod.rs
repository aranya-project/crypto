//! Utilities for testing cryptography implementations.
//!
//! If you implement any traits in this crate it is **very
//! highly** recommended that you use these tests.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::expect_used)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::panic)]
#![cfg(any(test, feature = "test_util"))]
#![cfg_attr(docsrs, doc(cfg(feature = "test_util")))]
#![forbid(unsafe_code)]

pub mod aead;
pub mod hash;
pub mod hpke;
pub mod kdf;
pub mod mac;
pub mod signer;
pub mod vectors;

use core::{fmt, marker::PhantomData};

pub use aead::test_aead;
pub use hash::test_hash;
pub use hpke::test_hpke;
pub use kdf::test_kdf;
pub use mac::test_mac;
pub use signer::test_signer;
use subtle::{Choice, ConstantTimeEq};
use zeroize::ZeroizeOnDrop;

use crate::{
    aead::{Aead, Lifetime, OpenError, SealError},
    csprng::{Csprng, Random},
    import::{ExportError, Import, ImportError},
    kdf::{Kdf, KdfError, Prk},
    keys::{InvalidKey, PublicKey, SecretKey, SecretKeyBytes},
    mac::Mac,
    oid::{Identified, Oid},
    signer::{Signature, Signer, SignerError, SigningKey, VerifyingKey},
};

#[macro_export]
#[doc(hidden)]
macro_rules! __apply {
    ($callback:ident, $($tt:tt),* $(,)?) => {
        $(
            $callback!($tt);
        )*
    };
}
pub use __apply;

/// Like [`assert_eq!`], but for [`Choice`].
#[macro_export]
macro_rules! assert_ct_eq {
    ($lhs:expr, $rhs:expr) => {
        assert!(bool::from(::subtle::ConstantTimeEq::ct_eq(&$lhs, &$rhs)))
    };
    ($lhs:expr, $rhs:expr, ) => {
        $crate::assert_ct_eq!($lhs, $rhs)
    };
    ($lhs:expr, $rhs:expr, $($args:tt)+) => {
        assert!(bool::from(::subtle::ConstantTimeEq::ct_eq(&$lhs, &$rhs)), $($args)+)
    };
}
pub(super) use assert_ct_eq;

/// Like [`assert_ne!`], but for [`Choice`].
#[macro_export]
macro_rules! assert_ct_ne {
    ($lhs:expr, $rhs:expr) => {
        assert!(bool::from(::subtle::ConstantTimeEq::ct_ne(&$lhs, &$rhs)))
    };
    ($lhs:expr, $rhs:expr, ) => {
        $crate::assert_ct_ne!($lhs, $rhs)
    };
    ($lhs:expr, $rhs:expr, $($args:tt)+) => {
        assert!(bool::from(::subtle::ConstantTimeEq::ct_ne(&$lhs, &$rhs)), $($args)+)
    };
}
pub(super) use assert_ct_ne;

/// Checks that each byte in `data` is zero.
macro_rules! assert_all_zero {
    ($data:expr) => {
        let data: &[u8] = &$data.as_ref();
        for c in data {
            assert_eq!(*c, 0, "Default must return all zeros");
        }
    };
}
pub(super) use assert_all_zero;

/// A shim that declares `OS_hardware_rand` for doctests.
#[macro_export]
#[doc(hidden)]
macro_rules! __doctest_os_hardware_rand {
    () => {
        #[cfg(feature = "trng")]
        #[no_mangle]
        extern "C" fn OS_hardware_rand() -> u32 {
            use rand::RngCore;
            rand::rngs::OsRng.next_u32()
        }
    };
}

/// An [`Aead`] that that uses the default trait methods.
#[derive(Debug)]
#[cfg_attr(feature = "clone-aead", derive(Clone))]
pub struct AeadWithDefaults<T>(T);

impl<T: Aead> Aead for AeadWithDefaults<T> {
    const LIFETIME: Lifetime = T::LIFETIME;

    type KeySize = T::KeySize;
    const KEY_SIZE: usize = T::KEY_SIZE;

    type NonceSize = T::NonceSize;
    const NONCE_SIZE: usize = T::NONCE_SIZE;

    type Overhead = T::Overhead;
    const OVERHEAD: usize = T::OVERHEAD;

    const MAX_PLAINTEXT_SIZE: u64 = T::MAX_PLAINTEXT_SIZE;
    const MAX_ADDITIONAL_DATA_SIZE: u64 = T::MAX_ADDITIONAL_DATA_SIZE;
    const MAX_CIPHERTEXT_SIZE: u64 = T::MAX_CIPHERTEXT_SIZE;

    type Key = T::Key;

    fn new(key: &Self::Key) -> Self {
        Self(T::new(key))
    }

    fn seal_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &mut [u8],
        additional_data: &[u8],
    ) -> Result<(), SealError> {
        self.0.seal_in_place(nonce, data, tag, additional_data)
    }

    fn open_in_place(
        &self,
        nonce: &[u8],
        data: &mut [u8],
        tag: &[u8],
        additional_data: &[u8],
    ) -> Result<(), OpenError> {
        self.0.open_in_place(nonce, data, tag, additional_data)
    }
}

impl<T: Identified> Identified for AeadWithDefaults<T> {
    const OID: &'static Oid = T::OID;
}

/// A [`Kdf`] that that uses the default trait methods.
#[derive(Clone)]
pub struct KdfWithDefaults<T>(PhantomData<fn() -> T>);

impl<T: Kdf> Kdf for KdfWithDefaults<T> {
    type MaxOutput = T::MaxOutput;

    type PrkSize = T::PrkSize;

    fn extract_multi<'a, I>(ikm: I, salt: &[u8]) -> Prk<Self::PrkSize>
    where
        I: IntoIterator<Item = &'a [u8]>,
    {
        T::extract_multi(ikm, salt)
    }

    fn expand_multi<'a, I>(
        out: &mut [u8],
        prk: &Prk<Self::PrkSize>,
        info: I,
    ) -> Result<(), KdfError>
    where
        I: IntoIterator<Item = &'a [u8], IntoIter: Clone>,
    {
        T::expand_multi(out, prk, info)
    }
}

impl<T: Identified> Identified for KdfWithDefaults<T> {
    const OID: &'static Oid = T::OID;
}

impl<T> fmt::Debug for KdfWithDefaults<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KdfWithDefaults").finish_non_exhaustive()
    }
}

/// A [`Mac`] that that uses the default trait methods.
#[derive(Clone, Debug)]
pub struct MacWithDefaults<T>(T);

impl<T: Mac> Mac for MacWithDefaults<T> {
    type Tag = T::Tag;
    type TagSize = T::TagSize;

    type Key = T::Key;
    type KeySize = T::KeySize;
    type MinKeySize = T::MinKeySize;

    fn new(key: &Self::Key) -> Self {
        Self(T::new(key))
    }
    fn try_new(key: &[u8]) -> Result<Self, InvalidKey> {
        Ok(Self(T::try_new(key)?))
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data)
    }

    fn tag(self) -> Self::Tag {
        self.0.tag()
    }
}

impl<T: Identified> Identified for MacWithDefaults<T> {
    const OID: &'static Oid = T::OID;
}

/// A [`Signer`] that that uses the default trait methods.
#[derive(Clone, Debug)]
pub struct SignerWithDefaults<T: ?Sized>(T);

impl<T: Signer + ?Sized> Signer for SignerWithDefaults<T> {
    type SigningKey = SigningKeyWithDefaults<T>;
    type VerifyingKey = VerifyingKeyWithDefaults<T>;
    type Signature = SignatureWithDefaults<T>;
}

impl<T: Identified> Identified for SignerWithDefaults<T> {
    const OID: &'static Oid = T::OID;
}

/// A [`SigningKey`] that uses the default trait methods.
pub struct SigningKeyWithDefaults<T: Signer + ?Sized>(T::SigningKey);

impl<T: Signer + ?Sized> SigningKey<SignerWithDefaults<T>> for SigningKeyWithDefaults<T> {
    fn sign(&self, msg: &[u8]) -> Result<SignatureWithDefaults<T>, SignerError> {
        Ok(SignatureWithDefaults(self.0.sign(msg)?))
    }

    fn public(&self) -> Result<VerifyingKeyWithDefaults<T>, crate::signer::PkError> {
        Ok(VerifyingKeyWithDefaults(self.0.public()?))
    }
}

impl<T: Signer + ?Sized> SecretKey for SigningKeyWithDefaults<T> {
    type Size = <T::SigningKey as SecretKey>::Size;

    fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
        self.0.try_export_secret()
    }
}

impl<T> Random for SigningKeyWithDefaults<T>
where
    T: Signer + ?Sized,
    T::SigningKey: Random,
{
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(<T::SigningKey as Random>::random(rng))
    }
}

impl<T: Signer + ?Sized> ConstantTimeEq for SigningKeyWithDefaults<T> {
    fn ct_eq(&self, other: &Self) -> Choice {
        ConstantTimeEq::ct_eq(&self.0, &other.0)
    }
}

impl<'a, T: Signer + ?Sized> Import<&'a [u8]> for SigningKeyWithDefaults<T>
where
    T::SigningKey: Import<&'a [u8]>,
{
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        Ok(Self(T::SigningKey::import(data)?))
    }
}

impl<T: Signer + ?Sized> Clone for SigningKeyWithDefaults<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Signer + ?Sized> fmt::Debug for SigningKeyWithDefaults<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SigningKeyWithDefaults")
            .finish_non_exhaustive()
    }
}

impl<T: Signer + ?Sized> ZeroizeOnDrop for SigningKeyWithDefaults<T> {}

/// A [`VerifyingKey`] that uses the default trait methods.
pub struct VerifyingKeyWithDefaults<T: Signer + ?Sized>(T::VerifyingKey);

impl<T: Signer + ?Sized> VerifyingKey<SignerWithDefaults<T>> for VerifyingKeyWithDefaults<T> {
    fn verify(&self, msg: &[u8], sig: &SignatureWithDefaults<T>) -> Result<(), SignerError> {
        self.0.verify(msg, &sig.0)
    }
}

impl<T: Signer + ?Sized> PublicKey for VerifyingKeyWithDefaults<T> {
    type Data = <T::VerifyingKey as PublicKey>::Data;

    fn export(&self) -> Self::Data {
        self.0.export()
    }
}

impl<'a, T: Signer + ?Sized> Import<&'a [u8]> for VerifyingKeyWithDefaults<T> {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        Ok(Self(T::VerifyingKey::import(data)?))
    }
}

impl<T: Signer + ?Sized> Clone for VerifyingKeyWithDefaults<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Signer + ?Sized> fmt::Debug for VerifyingKeyWithDefaults<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<T: Signer + ?Sized> Eq for VerifyingKeyWithDefaults<T> {}
impl<T: Signer + ?Sized> PartialEq for VerifyingKeyWithDefaults<T> {
    fn eq(&self, other: &Self) -> bool {
        PartialEq::eq(&self.0, &other.0)
    }
}

/// [`Signer::Signature`] that uses the default trait methods.
pub struct SignatureWithDefaults<T: Signer + ?Sized>(T::Signature);

impl<T: Signer + ?Sized> Signature<SignerWithDefaults<T>> for SignatureWithDefaults<T> {
    type Data = <T::Signature as Signature<T>>::Data;

    fn export(&self) -> Self::Data {
        self.0.export()
    }
}

impl<T: Signer + ?Sized> Clone for SignatureWithDefaults<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Signer + ?Sized> fmt::Debug for SignatureWithDefaults<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<'a, T: Signer + ?Sized> Import<&'a [u8]> for SignatureWithDefaults<T> {
    fn import(data: &'a [u8]) -> Result<Self, ImportError> {
        Ok(Self(T::Signature::import(data)?))
    }
}
