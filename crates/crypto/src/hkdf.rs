//! HKDF per [RFC 5869].
//!
//! [RFC 5869]: https://www.rfc-editor.org/rfc/rfc5869

#![forbid(unsafe_code)]

use core::{fmt, marker::PhantomData};

use generic_array::GenericArray;
use typenum::{Prod, U255};

use crate::{
    block::BlockSize,
    hash::Hash,
    hmac::{Hmac, HmacKey},
    kdf::{KdfError, Prk},
    keys::SecretKeyBytes,
};

/// TODO
pub fn test123(key: &[u8], prk: &Prk<typenum::U32>) -> Result<[u8; 16], KdfError> {
    use core::hint::black_box;

    use crate::{hash::Digest, hmac::Hmac};

    #[derive(Clone, Debug)]
    struct Noop(Digest<typenum::U32>);
    impl Hash for Noop {
        type DigestSize = typenum::U32;
        fn new() -> Self {
            Self(Digest::default())
        }
        //#[inline(never)]
        fn update(&mut self, data: &[u8]) {
            black_box(data);
        }
        //#[inline(never)]
        fn digest(self) -> Digest<Self::DigestSize> {
            self.0
        }
    }
    impl BlockSize for Noop {
        type BlockSize = typenum::U0;
    }

    let key = HmacKey::new(key);
    let _expander = Hmac::<Noop>::new(&key);

    let mut out = [0u8; 16];
    //Hkdf::<crate::rust::Sha256>::expand_multi(black_box(&mut out), prk, [b"test123"])?;
    Hkdf::<Noop>::expand_multi(black_box(&mut out), prk, [b"test123"])?;
    Ok(out)
}

/// The size in octets of the maximum expanded output of HKDF.
pub type MaxOutput<D> = Prod<U255, D>;

/// HKDF for some hash `H`.
pub struct Hkdf<H>(PhantomData<fn() -> H>);

impl<H: Hash + BlockSize> Hkdf<H> {
    /// The maximum nuumber of bytes that can be expanded by
    /// [`expand`][Self::expand] and
    /// [`expand_multi`][Self::expand_multi].
    pub const MAX_OUTPUT: usize = 255 * H::DIGEST_SIZE;

    /// The size in bytes of a [`Prk`] returned by this HKDF.
    pub const PRK_SIZE: usize = H::DIGEST_SIZE;

    /// Extracts a fixed-length pseudorandom key (PRK) from the
    /// Input Keying Material (IKM) and an optional salt.
    ///
    /// It handles IKM and salts of an arbitrary length.
    #[inline]
    pub fn extract(ikm: &[u8], salt: &[u8]) -> Prk<H::DigestSize> {
        Self::extract_multi(&[ikm], salt)
    }

    /// Extracts a fixed-length pseudorandom key (PRK) from the
    /// Input Keying Material (IKM) and an optional salt.
    ///
    /// It handles IKM and salts of an arbitrary length.
    #[inline]
    pub fn extract_multi<I>(ikm: I, salt: &[u8]) -> Prk<H::DigestSize>
    where
        I: IntoIterator,
        I::Item: AsRef<[u8]>,
    {
        // Section 2.2
        //
        // salt: optional salt value (a non-secret random value);
        // if not provided, it is set to a string of HashLen
        // zeros.
        let salt = if salt.is_empty() {
            let zero = GenericArray::<u8, H::DigestSize>::default();
            HmacKey::new(zero.as_slice())
        } else {
            HmacKey::new(salt)
        };

        // PRK = HMAC-Hash(salt, IKM)
        let prk = Hmac::<H>::mac_multi(&salt, ikm).into_array();
        Prk::new(SecretKeyBytes::new(prk))
    }

    /// Expands the PRK with an optional info parameter into
    /// a key.
    ///
    /// It handles `info` parameters of an arbitrary length and
    /// outputs up to [`MAX_OUTPUT`][Self::MAX_OUTPUT] bytes.
    ///
    /// It returns an error if the output is too large.
    #[inline]
    pub fn expand(out: &mut [u8], prk: &Prk<H::DigestSize>, info: &[u8]) -> Result<(), KdfError> {
        Self::expand_multi(out, prk, &[info])
    }

    /// Expands the PRK with an optional info parameter into
    /// a key.
    ///
    /// It handles `info` parameters of an arbitrary length and
    /// outputs up to [`MAX_OUTPUT`][Self::MAX_OUTPUT] bytes.
    ///
    /// It returns an error if the output is too large.
    pub fn expand_multi<I>(
        out: &mut [u8],
        prk: &Prk<H::DigestSize>,
        info: I,
    ) -> Result<(), KdfError>
    where
        I: IntoIterator<Item: AsRef<[u8]>, IntoIter: Clone>,
    {
        // Section 2.3
        //
        // The output OKM is calculated as follows:
        //
        // N = ceil(L/HashLen)
        // T = T(1) | T(2) | T(3) | ... | T(N)
        // OKM = first L octets of T
        //
        // where:
        // T(0) = empty string (zero length)
        // T(1) = HMAC-Hash(PRK, T(0) | info | 0x01)
        // T(2) = HMAC-Hash(PRK, T(1) | info | 0x02)
        // T(3) = HMAC-Hash(PRK, T(2) | info | 0x03)
        // ...
        if out.len() > Self::MAX_OUTPUT {
            return Err(KdfError::OutputTooLong);
        }

        let key = HmacKey::<H>::new(prk.as_bytes());
        let expander = Hmac::<H>::new(&key);
        let info = info.into_iter();

        // Invariant: n is in [0, 255].
        let mut n = 0u8;
        let mut chunks = out.chunks_exact_mut(H::DIGEST_SIZE);

        let mut prev = None;
        for chunk in chunks.by_ref() {
            // This cannot wrap because we've checked that there
            // is at most 255 chunks.
            n = n.wrapping_add(1);

            let mut expander = expander.clone();
            if let Some(prev) = prev {
                expander.update(prev);
            }
            info.clone().for_each(|s| {
                expander.update(s.as_ref());
            });
            expander.update(&[n]);
            let tag = expander.tag();
            chunk.copy_from_slice(tag.as_bytes());
            prev = Some(chunk);
        }

        let chunk = chunks.into_remainder();
        if !chunk.is_empty() {
            let mut expander = expander.clone();
            if let Some(prev) = prev {
                expander.update(prev);
            }
            info.clone().for_each(|s| {
                expander.update(s.as_ref());
            });
            // This cannot wrap; see the comment in the previous
            // loop.
            expander.update(&[n.wrapping_add(1)]);
            let tag = expander.tag();
            chunk.copy_from_slice(&tag.as_bytes()[..chunk.len()]);
        }

        Ok(())
    }
}

impl<H> fmt::Debug for Hkdf<H> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Hkdf").finish()
    }
}

/// Implements [`Hkdf`].
///
/// # Example
///
/// ```rust
/// use spideroak_crypto::{
///     block::BlockSize,
///     hash::{Digest, Hash},
///     hkdf_impl,
///     hpke::KdfId,
///     oid::consts::HKDF_WITH_SHA2_256,
///     typenum::{U32, U64},
/// };
///
/// #[derive(Clone, Debug)]
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
/// hkdf_impl!(
///     HkdfSha256,
///     "HMAC-SHA-256",
///     Sha256,
///     oid = HKDF_WITH_SHA2_256,
///     kdf_id = KdfId::HkdfSha256,
/// );
/// ```
#[macro_export]
macro_rules! hkdf_impl {
    (
        $name:ident, $doc_name:expr, $hash:ident
        $(, oid = $oid:ident )?
        $(, kdf_id = $kdf_id:expr)?
        $(,)?
    ) => {
        #[doc = concat!($doc_name, ".")]
        #[derive(Copy, Clone, Debug)]
        pub struct $name;

        impl $crate::kdf::Kdf for $name {
            type MaxOutput = $crate::hkdf::MaxOutput<<$hash as $crate::hash::Hash>::DigestSize>;

            type PrkSize = <$hash as $crate::hash::Hash>::DigestSize;

            fn extract_multi<'a, I>(ikm: I, salt: &[u8]) -> $crate::kdf::Prk<Self::PrkSize>
            where
                I: ::core::iter::IntoIterator<Item = &'a [u8]>,
            {
                $crate::hkdf::Hkdf::<$hash>::extract_multi(ikm, salt)
            }

            fn expand_multi<'a, I>(
                out: &mut [u8],
                prk: &$crate::kdf::Prk<Self::PrkSize>,
                info: I,
            ) -> Result<(), $crate::kdf::KdfError>
            where
                I: ::core::iter::IntoIterator<Item = &'a [u8]>,
                I::IntoIter: ::core::clone::Clone,
            {
                $crate::hkdf::Hkdf::<$hash>::expand_multi(out, prk, info)
            }
        }

        $(impl $crate::oid::Identified for $name {
            const OID: &$crate::oid::Oid = $oid;
        })?

        $(impl $crate::hpke::HpkeKdf for $name {
            const ID: $crate::hpke::KdfId = $kdf_id;
        })?
    };
}
pub(crate) use hkdf_impl;

#[cfg(test)]
#[allow(clippy::wildcard_imports)]
mod tests {
    macro_rules! hkdf_tests {
        () => {
            use crate::{
                hpke::KdfId,
                oid::consts::{HKDF_WITH_SHA2_256, HKDF_WITH_SHA2_384, HKDF_WITH_SHA2_512},
                test_util::test_kdf,
            };

            hkdf_impl!(
                HkdfSha256,
                "HKDF-SHA256",
                Sha256,
                oid = HKDF_WITH_SHA2_256,
                kdf_id = KdfId::HkdfSha256,
            );
            hkdf_impl!(
                HkdfSha384,
                "HKDF-SHA384",
                Sha384,
                oid = HKDF_WITH_SHA2_384,
                kdf_id = KdfId::HkdfSha384,
            );
            hkdf_impl!(
                HkdfSha512,
                "HKDF-SHA512",
                Sha512,
                oid = HKDF_WITH_SHA2_512,
                kdf_id = KdfId::HkdfSha512,
            );

            test_kdf!(hkdf_sha256, HkdfSha256, HkdfTest::HkdfSha256);
            test_kdf!(hkdf_sha384, HkdfSha384, HkdfTest::HkdfSha384);
            test_kdf!(hkdf_sha512, HkdfSha512, HkdfTest::HkdfSha512);
        };
    }

    #[cfg(feature = "bearssl")]
    mod bearssl {
        use crate::bearssl::{Sha256, Sha384, Sha512};
        hkdf_tests!();
    }

    mod rust {
        use crate::rust::{Sha256, Sha384, Sha512};
        hkdf_tests!();
    }
}
