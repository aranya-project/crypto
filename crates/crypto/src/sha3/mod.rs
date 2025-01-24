//! SHA-3 per [FIPS 202].
//!
//! [FIPS 202]: https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.202.pdf

use crypto_common::OutputSizeUser;
use typenum::Unsigned;

use crate::hash::{Digest, Hash, HashId};

macro_rules! impl_sha3 {
    ($name:ident, $doc:expr) => {
        #[doc = concat!($doc, ".")]
        #[derive(Clone, Debug, Default)]
        pub(crate) struct $name(sha3::$name);

        impl Hash for $name {
            const ID: HashId = HashId::$name;

            type DigestSize = <sha3::$name as OutputSizeUser>::OutputSize;
            const DIGEST_SIZE: usize =
                <<sha3::$name as OutputSizeUser>::OutputSize as Unsigned>::USIZE;

            #[inline]
            fn new() -> Self {
                Self(<sha3::$name as sha3::Digest>::new())
            }

            #[inline]
            fn update(&mut self, data: &[u8]) {
                sha3::Digest::update(&mut self.0, data)
            }

            #[inline]
            fn digest(self) -> Digest<Self::DigestSize> {
                Digest::from_array(sha3::Digest::finalize(self.0).into())
            }

            #[inline]
            fn hash(data: &[u8]) -> Digest<Self::DigestSize> {
                Digest::from_array(<sha3::$name as sha3::Digest>::digest(data).into())
            }
        }
    };
}
impl_sha3!(Sha3_256, "SHA3-256");
impl_sha3!(Sha3_384, "SHA3-384");
impl_sha3!(Sha3_512, "SHA3-512");

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_util::test_hash;

    test_hash!(mod sha3_256, Sha3_256, SHA3_256);
    test_hash!(mod sha3_384, Sha3_384, SHA3_384);
    test_hash!(mod sha3_512, Sha3_512, SHA3_512);
}
