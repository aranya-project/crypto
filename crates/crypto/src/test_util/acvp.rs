//! ACVP test utilities.

#![forbid(unsafe_code)]

use acvp::vectors::{sha2, sha3};

use crate::hash::{Digest, Hash};

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

/// Tests `H` against the SHA2 test vectors.
pub fn test_sha2<H: Hash>(vectors: sha2::TestVectors) {
    sha2::test::<AcvpHash<H>>(vectors).unwrap();
}

/// Tests `H` against the SHA3 test vectors.
pub fn test_sha3<H: Hash>(vectors: sha3::TestVectors) {
    sha3::test::<AcvpHash<H>>(vectors).unwrap();
}
