//! ACVP test utilities.

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, reason = "This is test code")]

use acvp::vectors::{hmac, sha2, sha3};

use crate::{
    hash::{Digest, Hash},
    import::Import,
    mac::Mac,
};

/// Tests `M` against HMAC test vectors.
pub fn test_hmac<M>(vectors: hmac::TestVectors)
where
    M: Mac,
    M::Tag: AsRef<[u8]>,
{
    hmac::test(vectors, |key, msg| {
        let key = <M::Key as Import<_>>::import(key)?;
        Ok(M::mac(&key, msg))
    })
    .unwrap();
}

/// Tests `H` against SHA-2 test vectors.
pub fn test_sha2<H: Hash>(vectors: sha2::TestVectors) {
    sha2::test::<AcvpHash<H>>(vectors).unwrap();
}

/// Tests `H` against SHA-3 test vectors.
pub fn test_sha3<H: Hash>(vectors: sha3::TestVectors) {
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
