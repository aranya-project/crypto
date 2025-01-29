//! ECDH tests.

use crate::{csprng::Csprng, kem::Ecdh, test_util::wycheproof};

/// Invokes `callback` for each test in this module.
///
/// # Example
///
/// ```
/// use spideroak_crypto::{default::Rng, rust::P256};
///
/// # spideroak_crypto::__doctest_os_hardware_rand!();
/// macro_rules! run_test {
///     ($test:ident) => {
///         spideroak_crypto::test_util::ecdh::$test::<P256, _>(&mut Rng);
///     };
/// }
/// spideroak_crypto::for_each_ecdh_test!(run_test);
/// ```
#[macro_export]
macro_rules! for_each_ecdh_test {
    ($callback:ident) => {
        $crate::__apply! {
            $callback,
            test_vectors,
        }
    };
}
pub use for_each_ecdh_test;

/// Performs ECDH tests.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// # Example
///
/// ```
/// use spideroak_crypto::{test_signer, rust::P256};
///
/// test_signer!(mod p256, P256);
/// ```
#[macro_export]
macro_rules! test_ecdh {
    (mod $name:ident, $ecdh:ty) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_ecdh!($ecdh);
        }
    };
    ($ecdh:ty) => {
        macro_rules! __ecdh_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::ecdh::$test::<$ecdh, _>(&mut $crate::default::Rng)
                }
            };
        }
        $crate::for_each_ecdh_test!(__ecdh_test);
    };
}
pub use test_ecdh;

/// Tests against ECDH-specific vectors.
pub fn test_vectors<E: Ecdh, R: Csprng>(_rng: &mut R) {
    if let Ok(name) = wycheproof::EcdhTest::try_from(E::ID) {
        wycheproof::test_ecdh::<E>(name);
    } else if let Ok(name) = wycheproof::XdhTest::try_from(E::ID) {
        wycheproof::test_xdh::<E>(name);
    }
}
