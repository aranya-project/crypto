//! ECDH tests.

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
/// test_signer!(mod p256, P256, ECDH_secp256r1);
/// ```
#[macro_export]
macro_rules! test_ecdh {
    (mod $name:ident, $ecdh:ty, $alg:ident) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_ecdh!($ecdh, $alg);
        }
    };
    ($ecdh:ty, $alg:ident) => {
        macro_rules! __ecdh_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::ecdh::$test::<$ecdh, _>(&mut $crate::default::Rng)
                }
            };
        }
        $crate::for_each_ecdh_test!(__ecdh_test);

        $crate::test_acvp!($ecdh, $alg);
        $crate::test_wycheproof!($ecdh, $alg);
    };
}
pub use test_ecdh;
