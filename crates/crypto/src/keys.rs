//! Basic keys and key material.

use core::{borrow::Borrow, fmt, iter::IntoIterator, mem, result::Result};

use generic_array::{ArrayLength, GenericArray, IntoArrayLength};
use subtle::{Choice, ConstantTimeEq};
use typenum::{generic_const_mappings::Const, IsLess, U65536};

use crate::{
    csprng::{Csprng, Random},
    import::{ExportError, Import},
    kdf::{Expand, Kdf, KdfError, Prk},
    zeroize::{zeroize_flat_type, ZeroizeOnDrop},
};

/// A fixed-length secret key.
///
/// Secret keys are either symmetric keys (e.g., for AES) or
/// asymmetric private keys (e.g., for ECDH).
pub trait SecretKey:
    Clone + ConstantTimeEq + for<'a> Import<&'a [u8]> + Random + ZeroizeOnDrop
{
    /// The size in octets of the key.
    type Size: ArrayLength + 'static;

    /// Attempts to export the key's secret data.
    fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError>;
}

/// Provides access to a secret's byte encoding.
pub trait RawSecretBytes {
    /// Returns the secret's byte encoding.
    fn raw_secret_bytes(&self) -> &[u8];
}

impl<T: RawSecretBytes> RawSecretBytes for &T {
    #[inline]
    fn raw_secret_bytes(&self) -> &[u8] {
        (**self).raw_secret_bytes()
    }
}

impl RawSecretBytes for [u8] {
    #[inline]
    fn raw_secret_bytes(&self) -> &[u8] {
        self
    }
}

/// A fixed-length byte encoding of a [`SecretKey`]'s data.
#[derive(Clone, Default)]
#[repr(transparent)]
pub struct SecretKeyBytes<N: ArrayLength>(GenericArray<u8, N>);

impl<N: ArrayLength> fmt::Debug for SecretKeyBytes<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SecretKeyBytes").finish_non_exhaustive()
    }
}

impl<N: ArrayLength> ZeroizeOnDrop for SecretKeyBytes<N> {}
impl<N: ArrayLength> Drop for SecretKeyBytes<N> {
    fn drop(&mut self) {
        // SAFETY:
        // - `self.0` does not contain references or dynamically
        //   sized data.
        // - `self.0` does not have a `Drop` impl.
        // - `self.0` is not used after this function returns.
        // - The bit pattern of all zeros is valid for `self.0`.
        unsafe {
            zeroize_flat_type(&mut self.0);
        }
    }
}

impl<N: ArrayLength> SecretKeyBytes<N> {
    /// The size in bytes of the secret key.
    pub const SIZE: usize = N::USIZE;

    /// Creates a new secret.
    #[inline]
    pub const fn new(secret: GenericArray<u8, N>) -> Self {
        Self(secret)
    }

    /// Returns the size in bytes of the secret key.
    #[allow(clippy::len_without_is_empty)]
    #[inline]
    pub const fn len(&self) -> usize {
        N::USIZE
    }

    /// Returns a reference to the secret key bytes as an array.
    pub(crate) fn as_array<const U: usize>(&self) -> &[u8; U]
    where
        Const<U>: IntoArrayLength<ArrayLength = N>,
    {
        self.0.as_ref()
    }

    /// Returns the secret key bytes as a byte slice.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }

    /// Returns the secret as a mutable byte slice.
    pub(crate) fn as_bytes_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }

    /// Converts the secret key bytes to an array.
    #[inline]
    pub fn into_bytes(mut self) -> GenericArray<u8, N> {
        // This is fine since we're consuming the receiver. If
        // the receiver were an exclusive reference this would be
        // very wrong since it'd be replacing the secret key with
        // all zeros.
        mem::take(&mut self.0)
    }
}

impl<N: ArrayLength> ConstantTimeEq for SecretKeyBytes<N> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<N: ArrayLength> Random for SecretKeyBytes<N> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(Random::random(rng))
    }
}

impl<N: ArrayLength> Expand for SecretKeyBytes<N>
where
    N: IsLess<U65536>,
{
    type Size = N;

    fn expand_multi<'a, K, I>(prk: &Prk<K::PrkSize>, info: I) -> Result<Self, KdfError>
    where
        K: Kdf,
        I: IntoIterator<Item = &'a [u8]>,
        I::IntoIter: Clone,
    {
        Ok(Self(Expand::expand_multi::<K, I>(prk, info)?))
    }
}

impl<N: ArrayLength> RawSecretBytes for SecretKeyBytes<N> {
    #[inline]
    fn raw_secret_bytes(&self) -> &[u8] {
        self.as_bytes()
    }
}

/// A fixed-length asymmetric public key.
pub trait PublicKey: Clone + fmt::Debug + Eq + for<'a> Import<&'a [u8]> {
    /// The fixed-length byte encoding of the key.
    type Data: Borrow<[u8]> + Clone + Sized;

    /// Returns the byte representation of the public key.
    fn export(&self) -> Self::Data;
}

raw_key! {
    /// A generic secret key.
    pub RawKey,
}

/// Creates a "raw" (i.e., a byte array) key.
///
/// # Example
///
/// ```
/// use spideroak_crypto::raw_key;
///
/// raw_key! {
///     /// Some documentation.
///     pub MyRawKey,
///     /// Some more documentation.
///     pub AnotherKey,
/// }
/// ```
#[macro_export]
macro_rules! raw_key {
    () => {};
    (
        $(#[$meta:meta])*
        $vis:vis $name:ident,
        $($tail:tt)*
    ) => {
        $(#[$meta])*
        #[derive(::core::clone::Clone)]
        #[repr(transparent)]
        $vis struct $name<N: $crate::generic_array::ArrayLength>($crate::keys::SecretKeyBytes<N>);

        impl<N: ::generic_array::ArrayLength> $name<N> {
            /// Creates a new raw key.
            #[inline]
            pub const fn new(key: $crate::keys::SecretKeyBytes<N>) -> Self {
                Self(key)
            }

            /// Returns the length in bytes of the key.
            ///
            /// Will always be exactly `N`.
            #[allow(clippy::len_without_is_empty)]
            #[inline]
            pub const fn len(&self) -> usize {
                self.0.len()
            }

            /// Returns the raw key bytes.
            #[inline]
            pub const fn as_slice(&self) -> &[u8] {
                self.0.as_bytes()
            }

            /// Returns the raw key bytes.
            #[inline]
            pub const fn as_bytes(&self) -> &$crate::keys::SecretKeyBytes<N> {
                &self.0
            }

            /// Converts the key into its raw key bytes.
            #[inline]
            pub fn into_bytes(mut self) -> $crate::keys::SecretKeyBytes<N> {
                // This is fine since we're consuming the
                // receiver. If the receiver were an exclusive
                // reference this would be very wrong since it'd
                // be replacing the secret key with all zeros.
                ::core::mem::take(&mut self.0)
            }
        }

        impl<N: $crate::generic_array::ArrayLength> $crate::keys::SecretKey for $name<N> {
            type Size = N;

            #[inline]
            fn try_export_secret(&self) -> ::core::result::Result<
                $crate::keys::SecretKeyBytes<Self::Size>,
                $crate::import::ExportError,
            > {
                ::core::result::Result::Ok(self.0.clone())
            }
        }

        impl<N: $crate::generic_array::ArrayLength> $crate::csprng::Random for $name<N> {
            fn random<R: $crate::csprng::Csprng>(rng: &mut R) -> Self {
                let sk = <$crate::keys::SecretKeyBytes<N> as $crate::csprng::Random>::random(rng);
                Self(sk)
            }
        }

        impl<N: $crate::generic_array::ArrayLength> $crate::keys::RawSecretBytes for $name<N> {
            #[inline]
            fn raw_secret_bytes(&self) -> &[u8] {
                $crate::keys::RawSecretBytes::raw_secret_bytes(&self.0)
            }
        }

        impl<N: $crate::generic_array::ArrayLength> $crate::kdf::Expand for $name<N>
        where
            N: ::typenum::IsLess<::typenum::U65536>
        {
            type Size = N;

            fn expand_multi<'a, K, I>(
                prk: &$crate::kdf::Prk<K::PrkSize>,
                info: I,
            ) -> ::core::result::Result<Self, $crate::kdf::KdfError>
            where
                K: $crate::kdf::Kdf,
                I: ::core::iter::IntoIterator<Item = &'a [u8]>,
                I::IntoIter: ::core::clone::Clone,
            {
                ::core::result::Result::Ok(Self($crate::kdf::Expand::expand_multi::<K, I>(prk, info)?))
            }
        }

        impl<N: $crate::generic_array::ArrayLength> ::subtle::ConstantTimeEq for $name<N> {
            #[inline]
            fn ct_eq(&self, other: &Self) -> ::subtle::Choice {
                self.0.ct_eq(&other.0)
            }
        }

        impl<N, const U: usize> $crate::import::Import<[u8; U]> for $name<N>
        where
            N: $crate::generic_array::ArrayLength,
            ::typenum::generic_const_mappings::Const<U>: $crate::generic_array::IntoArrayLength<ArrayLength = N>,
        {
            #[inline]
            fn import(key: [u8; U]) -> ::core::result::Result<Self, $crate::import::ImportError> {
                let sk = $crate::keys::SecretKeyBytes::new(key.into());
                ::core::result::Result::Ok(Self(sk))
            }
        }

        impl<N: $crate::generic_array::ArrayLength> $crate::import::Import<&[u8]> for $name<N> {
            #[inline]
            fn import(data: &[u8]) -> ::core::result::Result<Self, $crate::import::ImportError> {
                let bytes = $crate::import::Import::<_>::import(data)?;
                let sk = $crate::keys::SecretKeyBytes::new(bytes);
                ::core::result::Result::Ok(Self(sk))
            }
        }

        impl<N: ::generic_array::ArrayLength> ::core::fmt::Debug for $name<N> {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                f.debug_struct(stringify!($name)).finish_non_exhaustive()
            }
        }

        impl<N: $crate::generic_array::ArrayLength> $crate::zeroize::ZeroizeOnDrop for $name<N> {}
        impl<N: $crate::generic_array::ArrayLength> Drop for $name<N> {
            fn drop(&mut self) {
                // SAFETY:
                // - `self.0` does not contain references or
                //   dynamically sized data.
                // - `self.0` does not have a `Drop` impl.
                // - `self.0` is not used after this function
                //   returns.
                // - The bit pattern of all zeros is valid for
                //   `self.0`.
                unsafe {
                    $crate::zeroize::zeroize_flat_type(&mut self.0);
                }
            }
        }

        raw_key!{ $($tail)* }
    };
}
pub(crate) use raw_key;

/// The provided key is invalid.
// TODO(eric): move this somewhere else.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[error("invalid key length")]
pub struct InvalidKey;
