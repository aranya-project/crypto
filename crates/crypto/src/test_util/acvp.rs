//! [ACVP] test utilities.
//!
//! [ACVP]: https://pages.nist.gov/ACVP/

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, reason = "This is test code")]

pub use acvp;
use acvp::vectors::{hmac, sha2, sha3};

use crate::{
    hash::{Digest, Hash, HashId},
    mac::{Mac, MacId},
    test_util::UnknownAlgId,
};

macro_rules! map_ids {
    (
        $from:ident => $krate:ident;
        $($id:ident => $alg:ident),+ $(,)?
    ) => {
        impl TryFrom<$from> for $krate::Algorithm {
            type Error = UnknownAlgId<$from>;

            fn try_from(id: $from) -> Result<Self, Self::Error> {
                match id {
                    $(
                        $from::$id => Ok($krate::Algorithm::$alg),
                    )+
                    id => Err(UnknownAlgId(id)),
                }
            }
        }
    };
}
map_ids! {
    MacId => hmac;
    HmacSha2_256 => HmacSha2_256,
    HmacSha2_384 => HmacSha2_384,
    HmacSha2_512 => HmacSha2_512,
    HmacSha2_512_256 => HmacSha2_512_256,
    HmacSha3_256 => HmacSha3_256,
    HmacSha3_384 => HmacSha3_384,
    HmacSha3_512 => HmacSha3_512,
}
map_ids! {
    HashId => sha2;
    Sha256 => Sha2_256,
    // `acvp` currently doesn't support SHA-384.
    // Sha384 => Sha2_384,
    Sha512 => Sha2_512,
    Sha512_256 => Sha2_512_256,
}
map_ids! {
    HashId => sha3;
    Sha3_256 => Sha3_256,
    // `acvp` currently doesn't support SHA3-384 or SHA3-512.
    // Sha3_384 => Sha3_256,
    // Sha3_512 => Sha3_512,
}

/// Tests `M` against HMAC test vectors.
#[track_caller]
pub fn test_hmac<M>(vectors: &hmac::TestVectors)
where
    M: Mac,
    M::Tag: AsRef<[u8]>,
{
    hmac::test(vectors, |key, msg| Ok(M::try_mac(&key, msg)?)).unwrap();
}

/// Tests `H` against SHA-2 test vectors.
#[track_caller]
pub fn test_sha2<H: Hash>(vectors: &sha2::TestVectors) {
    sha2::test::<AcvpHash<H>>(vectors).unwrap();
}

/// Tests `H` against SHA-3 test vectors.
#[track_caller]
pub fn test_sha3<H: Hash>(vectors: &sha3::TestVectors) {
    sha3::test::<AcvpHash<H>>(vectors).unwrap();
}

#[derive(Clone, Debug)]
struct AcvpHash<H>(H);

impl<H: Hash> acvp::traits::Hash for AcvpHash<H> {
    type Digest = Digest<H::DigestSize>;

    #[inline]
    fn new() -> Self {
        Self(H::new())
    }

    #[inline]
    fn update(&mut self, msg: &[u8]) {
        self.0.update(msg);
    }

    #[inline]
    fn digest(self) -> Self::Digest {
        self.0.digest()
    }
}
