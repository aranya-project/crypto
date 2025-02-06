//! Utilities for testing cryptography implementations.
//!
//! If you implement any traits in this crate it is **very
//! highly** recommended that you use these tests.

#![allow(clippy::arithmetic_side_effects)]
#![allow(clippy::panic)]
#![cfg(any(test, feature = "test_util"))]
#![cfg_attr(docsrs, doc(cfg(feature = "test_util")))]

pub mod acvp;
pub mod aead;
pub mod ecdh;
pub mod hash;
pub mod hpke;
pub mod kdf;
pub mod mac;
pub mod signer;
pub mod wycheproof;

use core::{error, fmt, marker::PhantomData};

pub use aead::test_aead;
pub use ecdh::test_ecdh;
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
    hash::{Digest, Hash},
    hpke::{AeadId, AlgId, KdfId},
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

/// Used to "match" `&Oid`, which can't be used in a match
/// pattern because (as of 1.81), `rustc` does not allow
/// non-slice unsized constants in match patterns. See [issue
/// 87046] and [THIR].
///
/// [issue 87046]: https://github.com/rust-lang/rust/issues/87046
/// [THIR]: https://github.com/rust-lang/rust/blob/d4bdd1ed551fed0c951eb47b4be2c79d7a02d181/compiler/rustc_mir_build/src/thir/pattern/const_to_pat.rs#L304-L308
macro_rules! try_map {
    (
        $value:expr;
        $($lhs:expr => $rhs:expr),+ $(,)?
    ) => {
        match &$value {
            value => {
                if false { None }
                $(
                    else if $lhs == *value {
                        Some($rhs)
                    }
                )+
                else { None }
            }
        }
    }
}
pub(crate) use try_map;

/// The algorithm ID is unknown.
#[derive(Debug)]
pub struct UnknownAlgId(pub(crate) &'static Oid);

impl error::Error for UnknownAlgId {}

impl fmt::Display for UnknownAlgId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown algorithm ID: {}", self.0)
    }
}

/// An [`Aead`] that that uses the default trait methods.
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

impl<T: AlgId<AeadId>> AlgId<AeadId> for AeadWithDefaults<T> {
    const ID: AeadId = T::ID;
}

/// A [`Hash`] that that uses the default trait methods.
#[derive(Clone)]
pub struct HashWithDefaults<T>(T);

impl<T: Hash> Hash for HashWithDefaults<T> {
    type DigestSize = <T as Hash>::DigestSize;
    const DIGEST_SIZE: usize = <T as Hash>::DIGEST_SIZE;

    fn new() -> Self {
        Self(T::new())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }

    fn digest(self) -> Digest<Self::DigestSize> {
        self.0.digest()
    }
}

impl<T: Identified> Identified for HashWithDefaults<T> {
    const OID: &'static Oid = T::OID;
}

/// A [`Kdf`] that that uses the default trait methods.
pub struct KdfWithDefaults<T>(PhantomData<T>);

impl<T: Kdf> Kdf for KdfWithDefaults<T> {
    type MaxOutput = T::MaxOutput;

    type PrkSize = T::PrkSize;

    fn extract_multi<I>(ikm: I, salt: &[u8]) -> Prk<Self::PrkSize>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        T::extract_multi(ikm, salt)
    }

    fn expand_multi<I>(out: &mut [u8], prk: &Prk<Self::PrkSize>, info: I) -> Result<(), KdfError>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
        I::IntoIter: Clone,
    {
        T::expand_multi(out, prk, info)
    }
}

impl<T: Identified> Identified for KdfWithDefaults<T> {
    const OID: &'static Oid = T::OID;
}

impl<T: AlgId<KdfId>> AlgId<KdfId> for KdfWithDefaults<T> {
    const ID: KdfId = T::ID;
}

/// A [`Mac`] that that uses the default trait methods.
#[derive(Clone)]
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

impl<T: Signer + Identified + ?Sized> Identified for SignatureWithDefaults<T> {
    const OID: &'static Oid = T::OID;
}
