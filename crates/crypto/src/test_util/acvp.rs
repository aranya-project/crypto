//! [ACVP] test utilities.
//!
//! [ACVP]: https://pages.nist.gov/ACVP/

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, reason = "This is test code")]

use core::marker::PhantomData;

pub use acvp;
use acvp::vectors::{hmac, sha2, sha3};
use typenum::Unsigned;

use crate::{
    hash::{Digest, Hash},
    mac::Mac,
};

/// Tests `M` against HMAC test vectors.
#[track_caller]
pub fn test_hmac<M>(vectors: &hmac::TestVectors)
where
    M: Mac,
    M::Tag: AsRef<[u8]>,
{
    hmac::test::<AcvpMac<M>>(vectors).unwrap();
}

struct AcvpMac<M>(PhantomData<M>);

impl<M> acvp::traits::Mac for AcvpMac<M>
where
    M: Mac,
    M::Tag: AsRef<[u8]>,
{
    type Tag = M::Tag;
    fn min_key_len() -> Option<usize> {
        Some(M::MinKeySize::USIZE)
    }
    fn try_mac(key: &[u8], msg: &[u8]) -> acvp::anyhow::Result<Self::Tag> {
        Ok(M::try_mac(key, msg)?)
    }
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
