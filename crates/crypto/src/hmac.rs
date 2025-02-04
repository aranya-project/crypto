//! HMAC per [FIPS PUB 198-1]
//!
//! [FIPS PUB 198-1]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf

#![forbid(unsafe_code)]

use core::cmp;

use generic_array::{ArrayLength, GenericArray, LengthError};
use subtle::{Choice, ConstantTimeEq};

use crate::{
    block::{Block, BlockSize},
    csprng::{Csprng, Random},
    hash::{Digest, Hash},
    import::{ExportError, Import, ImportError},
    keys::{SecretKey, SecretKeyBytes},
    zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing},
};

/// HMAC per [FIPS PUB 198-1] for some hash `H`.
///
/// [FIPS PUB 198-1]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf
#[derive(Clone)]
pub struct Hmac<H> {
    /// H(ipad).
    ipad: H,
    /// H(opad).
    opad: H,
}

impl<H: Hash + BlockSize> Hmac<H> {
    /// Creates an HMAC using the provided `key`.
    pub fn new(key: &HmacKey<H>) -> Self {
        let mut key = Zeroizing::new(key.0.clone());

        // Step 4: K_0 ^ ipad (0x36)
        for v in key.iter_mut() {
            *v ^= 0x36;
        }
        let mut ipad = H::new();
        ipad.update(key.as_slice());

        // Step 7: K_0 ^ opad (0x5c)
        for v in key.iter_mut() {
            *v ^= 0x36 ^ 0x5c;
        }
        let mut opad = H::new();
        opad.update(key.as_slice());

        Self { ipad, opad }
    }

    /// Writes `data` to the HMAC.
    pub fn update(&mut self, data: &[u8]) {
        // Step 5: H((K_0 ^ ipad) || text)
        self.ipad.update(data)
    }

    /// Returns the authentication tag.
    pub fn tag(mut self) -> Tag<H::DigestSize> {
        let d = self.ipad.digest();
        // Step 8: (K_0 ^ opad) || H((K_0 ^ ipad) || text)
        self.opad.update(&d);
        // Step 9: H((K_0 ^ opad) || H((K_0 ^ ipad) || text))
        Tag(self.opad.digest())
    }

    /// Computes the single-shot tag from `data` using `key`.
    pub fn mac_multi<I>(key: &HmacKey<H>, data: I) -> Tag<H::DigestSize>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        let mut h = Self::new(key);
        for s in data {
            h.update(s.as_ref());
        }
        h.tag()
    }
}

/// An [`Hmac`] authentication code.
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct Tag<N: ArrayLength>(Digest<N>);

impl<N: ArrayLength> Tag<N> {
    /// Returns the size in bytes of the tag.
    #[cfg(feature = "committing-aead")]
    #[cfg_attr(docsrs, doc(cfg(feature = "committing-aead")))]
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    // NB: this is hidden because the only safe way to use a MAC
    // is to compare it for equality using `ConstantTimeEq`. It's
    // needed by the `hkdf` module and `aranya-crypto` crates,
    // however.
    #[doc(hidden)]
    pub fn into_array(self) -> GenericArray<u8, N> {
        self.0.into_array()
    }
}

// NB: this is intentionally not public by default because the
// only safe way to use a MAC is to compare it for equality using
// `ConstantTimeEq`. It's needed by the `hkdf` module, however.
cfg_if::cfg_if! {
    if #[cfg(feature = "hazmat")] {
        impl<N: ArrayLength> Tag<N> {
            /// Returns the tag as a byte slice.
            ///
            /// # ⚠️ Warning
            /// <div class="warning">
            /// This is a low-level feature. You should not be
            /// using it unless you understand what you are
            /// doing.
            /// </div>
            #[cfg_attr(docsrs, doc(cfg(feature = "hazmat")))]
            pub const fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }
    } else {
        impl<N: ArrayLength> Tag<N> {
            pub(crate) const fn as_bytes(&self) -> &[u8] {
                self.0.as_bytes()
            }
        }
    }
}

// NB: this is hidden because the only safe way to use a MAC is
// to compare it for equality using `ConstantTimeEq`. It's needed
// by the `test_util` module, however.
#[doc(hidden)]
#[cfg(feature = "test_util")]
impl<N: ArrayLength> AsRef<[u8]> for Tag<N> {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl<N: ArrayLength> ConstantTimeEq for Tag<N> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

// Required by `crate::test_util::test_mac`.
impl<'a, N: ArrayLength> TryFrom<&'a [u8]> for Tag<N> {
    type Error = LengthError;

    fn try_from(tag: &'a [u8]) -> Result<Self, Self::Error> {
        let digest = GenericArray::try_from_slice(tag)?;
        Ok(Self(Digest::new(digest.clone())))
    }
}

/// An [`Hmac`] key.
#[repr(transparent)]
pub struct HmacKey<H: Hash + BlockSize>(Block<H>);

impl<H: Hash + BlockSize> HmacKey<H> {
    /// Creates an `HmacKey`.
    pub fn new(key: &[u8]) -> Self {
        let mut out = Block::<H>::default();
        if key.len() <= out.len() {
            // Steps 1 and 3
            out[..key.len()].copy_from_slice(key);
        } else {
            // Step 2
            let d = H::hash(key);
            let n = cmp::min(d.len(), out.len());
            out[..n].copy_from_slice(&d[..n]);
        };
        Self(out)
    }
}

impl<H: Hash + BlockSize> Clone for HmacKey<H> {
    #[inline]
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<H: Hash + BlockSize> SecretKey for HmacKey<H> {
    type Size = H::BlockSize;

    /// Exports the raw key.
    ///
    /// Note: this returns `h(k)` if the original `k` passed to
    /// [`HmacKey::new`] was longer than the block size of `h`.
    #[inline]
    fn try_export_secret(&self) -> Result<SecretKeyBytes<Self::Size>, ExportError> {
        Ok(SecretKeyBytes::new(self.0.clone()))
    }
}

impl<H: Hash + BlockSize> Random for HmacKey<H> {
    fn random<R: Csprng>(rng: &mut R) -> Self {
        Self(Block::<H>::random(rng))
    }
}

impl<H: Hash + BlockSize> Import<&[u8]> for HmacKey<H> {
    #[inline]
    fn import(data: &[u8]) -> Result<Self, ImportError> {
        Ok(Self::new(data))
    }
}

impl<H: Hash + BlockSize> ConstantTimeEq for HmacKey<H> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

impl<H: Hash + BlockSize> ZeroizeOnDrop for HmacKey<H> {}
impl<H: Hash + BlockSize> Drop for HmacKey<H> {
    #[inline]
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Implements [`Hmac`].
///
/// # Example
///
/// ```rust
/// use spideroak_crypto::{
///     block::BlockSize,
///     hash::{Digest, Hash},
///     hmac_impl,
///     oid::consts::HMAC_WITH_SHA2_256,
///     typenum::{U32, U64},
/// };
///
/// #[derive(Clone)]
/// pub struct Sha256;
///
/// impl Hash for Sha256 {
///     type DigestSize = U32;
///     fn new() -> Self {
///         Self
///     }
///     fn update(&mut self, _data: &[u8]) {
///         todo!()
///     }
///     fn digest(self) -> Digest<Self::DigestSize> {
///         todo!()
///     }
/// }
///
/// impl BlockSize for Sha256 {
///     type BlockSize = U64;
/// }
///
/// hmac_impl!(HmacSha256, "HMAC-SHA-256", Sha256, HMAC_WITH_SHA2_256);
/// ```
#[macro_export]
macro_rules! hmac_impl {
    ($name:ident, $doc:expr, $hash:ident $(, $oid:ident)? $(,)?) => {
        #[doc = concat!($doc, ".")]
        #[derive(Clone)]
        pub struct $name($crate::hmac::Hmac<$hash>);

        impl $crate::mac::Mac for $name {
            type Tag = $crate::hmac::Tag<Self::TagSize>;
            type TagSize = <$hash as $crate::hash::Hash>::DigestSize;

            type Key = $crate::hmac::HmacKey<$hash>;
            type KeySize = <$hash as $crate::block::BlockSize>::BlockSize;
            type MinKeySize = <$hash as $crate::hash::Hash>::DigestSize;

            #[inline]
            fn new(key: &Self::Key) -> Self {
                Self($crate::hmac::Hmac::new(key))
            }

            #[inline]
            fn try_new(key: &[u8]) -> ::core::result::Result<Self, $crate::keys::InvalidKey> {
                use $crate::typenum::Unsigned;

                if key.len() < Self::MinKeySize::USIZE {
                    ::core::result::Result::Err($crate::keys::InvalidKey)
                } else {
                    let key = $crate::hmac::HmacKey::<$hash>::new(key);
                    ::core::result::Result::Ok(Self::new(&key))
                }
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.0.update(data)
            }

            #[inline]
            fn tag(self) -> Self::Tag {
                self.0.tag()
            }
        }

        $(
            impl $crate::oid::Identified for $name {
                const OID: $crate::oid::Oid = $oid;
            }
        )?
    };
}
pub(crate) use hmac_impl;

#[cfg(test)]
#[allow(clippy::wildcard_imports)]
mod tests {
    macro_rules! hmac_tests {
        () => {
            use crate::{
                oid::consts::{
                    HMAC_WITH_SHA2_256,
                    HMAC_WITH_SHA2_384,
                    HMAC_WITH_SHA2_512,
                },
                test_util::test_mac,
            };

            hmac_impl!(HmacSha2_256, "HMAC-SHA256", Sha256, HMAC_WITH_SHA2_256);
            hmac_impl!(HmacSha2_384, "HMAC-SHA384", Sha384, HMAC_WITH_SHA2_384);
            hmac_impl!(HmacSha2_512, "HMAC-SHA512", Sha512, HMAC_WITH_SHA2_512);

            test_mac!(mod hmac_sha256, HmacSha2_256);
            test_mac!(mod hmac_sha384, HmacSha2_384);
            test_mac!(mod hmac_sha512, HmacSha2_512);
        };
    }

    #[cfg(feature = "bearssl")]
    mod bearssl {
        use crate::bearssl::{Sha256, Sha384, Sha512};
        hmac_tests!();
    }

    mod rust {
        use crate::rust::{Sha256, Sha384, Sha512};
        hmac_tests!();
    }
}
