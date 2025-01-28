//! [`Mac`] tests.

use super::{assert_ct_eq, assert_ct_ne};
use crate::{
    csprng::{Csprng, Random},
    mac::Mac,
};

/// Invokes `callback` for each MAC test.
///
/// # Example
///
/// ```
/// use spideroak_crypto::{default::Rng, rust::HmacSha256};
///
/// # spideroak_crypto::__doctest_os_hardware_rand!();
/// macro_rules! run_test {
///     ($test:ident) => {
///         spideroak_crypto::test_util::mac::$test::<HmacSha256, _>(&mut Rng);
///     }
/// }
/// spideroak_crypto::for_each_mac_test!(run_test);
/// ```
#[macro_export]
macro_rules! for_each_mac_test {
    ($callback:ident) => {
        $crate::__apply! {
            $callback,
            test_vectors,
            test_default,
            test_update,
            test_verify,
            test_different_keys,
            test_different_data,
        }
    };
}

/// Performs MAC tests.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// # Example
///
/// ```
/// use spideroak_crypto::{test_mac, rust::HmacSha256};
///
/// test_mac!(mod hmac_sha256, HmacSha256, HMAC_SHA_256);
/// ```
#[macro_export]
macro_rules! test_mac {
    (mod $name:ident, $mac:ty, $alg:ident) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_mac!($mac, $alg);
        }
    };
    ($mac:ty, $alg:ident) => {
        macro_rules! __mac_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    use $crate::{
                        default::Rng,
                        test_util::{mac::$test, MacWithDefaults},
                    };

                    $test::<$mac, _>(&mut Rng);
                    $test::<MacWithDefaults<$mac>, _>(&mut Rng);
                }
            };
        }
        $crate::for_each_mac_test!(__mac_test);
    };
}
pub use test_mac;

const DATA: &[u8] = b"hello, world!";

/// Tests against MAC-specific vectors.
///
/// Unknown hash algorithms are ignored.
pub fn test_vectors<T, R>(_rng: &mut R)
where
    T: Mac,
    T::Tag: AsRef<[u8]>,
    R: Csprng,
{
    use acvp::vectors::hmac;

    use crate::test_util::acvp::test_hmac;

    if let Ok(alg) = T::ID.try_into() {
        let vectors = hmac::load(alg).expect("should be able to load HMAC test vectors");
        test_hmac::<T>(&vectors);
    }
}

/// Basic positive test.
pub fn test_default<T: Mac, R: Csprng>(rng: &mut R) {
    let key = Random::random(rng);
    let tag1 = T::mac(&key, DATA);
    let tag2 = T::mac(&key, DATA);
    assert_ct_eq!(tag1, tag2, "tags should be the same");
}

/// Tests that [`Mac::update`] is the same as [`Mac::mac`].
pub fn test_update<T: Mac, R: Csprng>(rng: &mut R) {
    let key = Random::random(rng);
    let tag1 = T::mac(&key, DATA);
    let tag2 = {
        let mut h = T::new(&key);
        for c in DATA {
            h.update(&[*c]);
        }
        h.tag()
    };
    assert_ct_eq!(tag1, tag2, "tags should be the same");
}

/// Test [`Mac::verify`].
pub fn test_verify<T: Mac, R: Csprng>(rng: &mut R) {
    let key = Random::random(rng);
    let tag1 = T::mac(&key, DATA);

    let mut h = T::new(&key);
    for c in DATA {
        h.update(&[*c]);
    }
    h.verify(&tag1).expect("tags should be the same");
}

/// Negative tests for different keys.
pub fn test_different_keys<T: Mac, R: Csprng>(rng: &mut R) {
    let key1 = Random::random(rng);
    let key2 = Random::random(rng);
    assert_ct_ne!(key1, key2, "keys should differ");

    let tag1 = T::mac(&key1, DATA);
    let tag2 = T::mac(&key2, DATA);
    assert_ct_ne!(tag1, tag2, "tags should differ");
}

/// Negative test for MACs of different data.
pub fn test_different_data<T: Mac, R: Csprng>(rng: &mut R) {
    let key = Random::random(rng);
    let tag1 = T::mac(&key, b"hello");
    let tag2 = T::mac(&key, b"world");
    assert_ct_ne!(tag1, tag2, "tags should differ");
}
