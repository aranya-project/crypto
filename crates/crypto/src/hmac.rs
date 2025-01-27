//! HMAC per [FIPS PUB 198-1]
//!
//! [FIPS PUB 198-1]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.198-1.pdf

use core::{
    borrow::{Borrow, BorrowMut},
    cmp,
    marker::PhantomData,
    mem,
};

use generic_array::{ArrayLength, GenericArray, LengthError};
use subtle::{Choice, ConstantTimeEq};
use typenum::Unsigned;

use crate::{
    csprng::Csprng,
    hash::{Digest, Hash},
    import::{ExportError, Import, ImportError, InvalidSizeError},
    keys::{RawSecretBytes, SecretKey, SecretKeyBytes},
    zeroize::ZeroizeOnDrop,
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

impl<H: Hash> Hmac<H> {
    /// Creates an HMAC using the provided `key`.
    pub fn new(key: &[u8]) -> Self {
        let mut key = {
            let mut tmp = H::Block::default();
            let tmp_len = tmp.borrow().len();
            if key.len() <= tmp_len {
                // Steps 1 and 3
                tmp.borrow_mut()[..key.len()].copy_from_slice(key);
            } else {
                // Step 2
                let d = H::hash(key);
                let n = cmp::min(d.len(), tmp_len);
                tmp.borrow_mut()[..n].copy_from_slice(&d[..n]);
            };
            tmp
        };

        // Step 4: K_0 ^ ipad (0x36)
        for v in key.borrow_mut() {
            *v ^= 0x36;
        }
        let mut ipad = H::new();
        ipad.update(key.borrow());

        // Step 7: K_0 ^ opad (0x5c)
        for v in key.borrow_mut() {
            *v ^= 0x36 ^ 0x5c;
        }
        let mut opad = H::new();
        opad.update(key.borrow());

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
    pub fn mac_multi<I>(key: &[u8], data: I) -> Tag<H::DigestSize>
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
pub struct HmacKey<L> {
    _l: PhantomData<L>,
    key: [u8],
}

impl<'a, L: ArrayLength> SecretKey for HmacKey<L> {
    type Size = L;
    fn new<R: Csprng>(_rng: &mut R) -> Self {
        todo!()
    }

    type Secret = &'a [u8];
    fn try_export_secret(&self) -> Result<Self::Secret, ExportError> {
        Ok(&self.key)
    }
}

impl<L: ArrayLength> Import<&[u8]> for &HmacKey<L> {
    fn import(data: &[u8]) -> Result<Self, ImportError> {
        if data.len() < L::USIZE {
            Err(ImportError::InvalidSize(InvalidSizeError {
                got: data.len(),
                // TODO(eric): `usize::MAX` is not the correct
                // upper bound here.
                want: L::USIZE..usize::MAX,
            }))
        } else {
            // SAFETY: `&[u8]` and `Self` have the same layout in
            // memory.
            let key = unsafe { mem::transmute::<&[u8], Self>(data) };
            Ok(key)
        }
    }
}

impl<L> ConstantTimeEq for &HmacKey<L> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.key.ct_eq(&other.key)
    }
}

impl<L> ZeroizeOnDrop for HmacKey<L> {}
impl<L> Drop for HmacKey<L> {
    fn drop(&mut self) {
        // TODO
    }
}

/// Implements [`Hmac`].
///
/// # Example
///
/// ```rust
/// use spideroak_crypto::{
///     hash::{Block, Digest, Hash, HashId},
///     hmac_impl,
///     typenum::U32,
/// };
///
/// #[derive(Clone)]
/// pub struct Sha256;
///
/// impl Hash for Sha256 {
///     const ID: HashId = HashId::Sha256;
///     type DigestSize = U32;
///     type Block = Block<64>;
///     const BLOCK_SIZE: usize = 64;
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
/// hmac_impl!(HmacSha256, "HMAC-SHA-256", Sha256, HmacSha256Key);
/// ```
#[macro_export]
macro_rules! hmac_impl {
    ($name:ident, $doc:expr, $hash:ident) => {
        #[doc = concat!($doc, ".")]
        #[derive(Clone)]
        pub struct $name($crate::hmac::Hmac<$hash>);

        impl $crate::mac::Mac for $name {
            const ID: $crate::mac::MacId = $crate::mac::MacId::$name;

            // Setting len(K) = L ensures that we're always in
            // [L, B].
            type Key = $crate::hmac::HmacKey<Self::KeySize>;
            type KeySize = <$hash as $crate::hash::Hash>::DigestSize;
            type Tag = $crate::hmac::Tag<Self::TagSize>;
            type TagSize = <$hash as $crate::hash::Hash>::DigestSize;

            fn new(key: &Self::Key) -> Self {
                let key = $crate::keys::RawSecretBytes::raw_secret_bytes(key);
                Self($crate::hmac::Hmac::new(key))
            }

            fn update(&mut self, data: &[u8]) {
                self.0.update(data)
            }

            fn tag(self) -> Self::Tag {
                self.0.tag()
            }
        }
    };
}
pub(crate) use hmac_impl;

#[cfg(test)]
#[allow(clippy::wildcard_imports)]
mod tests {
    macro_rules! hmac_tests {
        () => {
            use crate::test_util::test_mac;

            hmac_impl!(HmacSha256, "HMAC-SHA256", Sha256, HmacSha256Key);
            hmac_impl!(HmacSha384, "HMAC-SHA384", Sha384, HmacSha384Key);
            hmac_impl!(HmacSha512, "HMAC-SHA512", Sha512, HmacSha512Key);

            test_mac!(hmac_sha256, HmacSha256, MacTest::HmacSha256);
            test_mac!(hmac_sha384, HmacSha384, MacTest::HmacSha384);
            test_mac!(hmac_sha512, HmacSha512, MacTest::HmacSha512);
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
