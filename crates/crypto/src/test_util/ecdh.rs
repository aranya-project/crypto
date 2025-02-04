//! ECDH tests.

use crate::{csprng::Csprng, kem::Ecdh, oid::Identified};

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
pub fn test_vectors<E, R>(_rng: &mut R)
where
    E: Ecdh + Identified,
    R: Csprng,
{
    use crate::{
        oid::consts::{SECP256R1, SECP384R1, SECP521R1, X25519, X448},
        test_util::wycheproof::{test_ecdh, test_xdh, EcdhTest, XdhTest},
    };

    match E::OID {
        SECP256R1 => test_ecdh::<E>(EcdhTest::EcdhSecp256r1),
        SECP384R1 => test_ecdh::<E>(EcdhTest::EcdhSecp384r1),
        SECP521R1 => test_ecdh::<E>(EcdhTest::EcdhSecp521r1),
        X25519 => test_xdh::<E>(XdhTest::X25519),
        X448 => test_xdh::<E>(XdhTest::X448),
        _ => {}
    }
}
