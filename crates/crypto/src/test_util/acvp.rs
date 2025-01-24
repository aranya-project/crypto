//! [ACVP] test utilities.
//!
//! [ACVP]: https://pages.nist.gov/ACVP/

#![forbid(unsafe_code)]
#![allow(clippy::unwrap_used, reason = "This is test code")]

pub use acvp;
use acvp::vectors::{hmac, sha2, sha3};

use crate::{
    hash::{Digest, Hash},
    import::Import,
    mac::Mac,
};

/// Tests a particular algorithm against the ACVP test vectors.
///
/// # Example
///
/// ```
/// use spideroak_crypto::{test_acvp, rust::{Aes256Gcm, Sha256}};
///
/// test_acvp!(Aes256Gcm, AES_256_GCM);
/// test_acvp!(Sha256, SHA2_256);
/// ```
#[macro_export]
macro_rules! test_acvp {
    // AES-GCM
    ($aead:ty, AES_128_GCM) => {};
    ($aead:ty, AES_256_GCM) => {};

    // SHA-2
    (@sha2 $name:ident, $hash:ty, $test:ident) => {
        #[test]
        fn $name() {
            use $crate::test_util::{
                acvp::acvp::vectors::sha2::{self, Algorithm},
                HashWithDefaults,
            };
            let vectors = sha2::load(Algorithm::$test)
                .expect("should be able to load SHA-2 test vectors");
            $crate::test_util::acvp::test_sha2::<$hash>(&vectors);
            $crate::test_util::acvp::test_sha2::<HashWithDefaults<$hash>>(&vectors);
        }
    };
    ($hash:ty, SHA2_256) => {
        $crate::test_acvp!(@sha2 test_sha2_256_acvp, $hash, Sha2_256);
    };
    ($hash:ty, SHA2_384) => {
        // Currently don't have any SHA2-384 test vectors.
    };
    ($hash:ty, SHA2_512) => {
        $crate::test_acvp!(@sha2 test_sha2_512_acvp, $hash, Sha2_512);
    };
    ($hash:ty, SHA2_512_256) => {
        $crate::test_acvp!(@sha2 test_sha2_512_256_acvp, $hash, Sha2_512_256);
    };

    // SHA-3
    (@sha3 $name:ident, $hash:ty, $test:ident) => {
        #[test]
        fn $name() {
            use $crate::test_util::{
                acvp::acvp::vectors::sha3::{self, Algorithm},
                HashWithDefaults,
            };
            let vectors = sha3::load(Algorithm::$test)
                .expect("should be able to load SHA-3 test vectors");
            $crate::test_util::acvp::test_sha3::<$hash>(&vectors);
            $crate::test_util::acvp::test_sha3::<HashWithDefaults<$hash>>(&vectors);
        }
    };
    ($hash:ty, SHA3_256) => {
        $crate::test_acvp!(@sha3 test_sha3_256_acvp, $hash, Sha3_256);
    };
    ($hash:ty, SHA3_384) => {
        // Currently don't have any SHA3-384 test vectors.
    };
    ($hash:ty, SHA3_512) => {
        // Currently don't have any SHA3-512 test vectors.
    };
    ($hash:ty, SHA3_512_256) => {
        $crate::test_acvp!(@sha2 test_sha3_512_256_acvp, $hash, Sha3_512_256);
    };

    ($ty:ty, $alg:expr) => {
        // Unsupported
    }
}
pub use test_acvp;

/// Tests `M` against HMAC test vectors.
#[track_caller]
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
