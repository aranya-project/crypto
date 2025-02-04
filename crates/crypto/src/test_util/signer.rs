//! [`Signer`] tests.

use alloc::vec::Vec;
use core::borrow::Borrow;

use crate::{
    csprng::{Csprng, Random},
    import::Import,
    keys::RawSecretBytes,
    oid::{
        consts::{
            ECDSA_WITH_SHA2_256, ECDSA_WITH_SHA2_384, ECDSA_WITH_SHA2_512, ED25519, ED448,
            SECP256R1, SECP384R1, SECP521R1,
        },
        Identified,
    },
    signer::{Signer, SigningKey, VerifyingKey},
    test_util::{assert_ct_eq, assert_ct_ne},
};

/// Invokes `callback` for each signer test.
///
/// # Example
///
/// ```
/// use spideroak_crypto::{default::Rng, rust::P256};
///
/// # spideroak_crypto::__doctest_os_hardware_rand!();
/// macro_rules! run_test {
///     ($test:ident) => {
///         spideroak_crypto::test_util::signer::$test::<P256, _>(&mut Rng);
///     };
/// }
/// spideroak_crypto::for_each_signer_test!(run_test);
/// ```
#[macro_export]
macro_rules! for_each_signer_test {
    ($callback:ident) => {
        $crate::__apply! {
            $callback,
            test_vectors,
            test_default,
            test_pk_eq,
            test_sk_ct_eq,
            test_public,
            test_batch_simple_good,
            test_batch_simple_bad,
        }
    };
}
pub use for_each_signer_test;

/// Performs signer (digital signature) tests.
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
macro_rules! test_signer {
    (mod $name:ident, $signer:ty) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_signer!($signer);
        }
    };
    ($signer:ty) => {
        macro_rules! __signer_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::signer::$test::<$signer, _>(&mut $crate::default::Rng)
                }
            };
        }
        $crate::for_each_signer_test!(__signer_test);
    };
}
pub use test_signer;

/// Tests against signer-specific vectors.
pub fn test_vectors<T, R>(_rng: &mut R)
where
    T: Signer + Identified,
    T::Signature: Identified,
    R: Csprng,
{
    use crate::test_util::wycheproof::{test_ecdsa, test_eddsa, EcdsaTest, EddsaTest};

    match (T::OID, <T::Signature as Identified>::OID) {
        (SECP256R1, ECDSA_WITH_SHA2_256) => test_ecdsa::<T>(EcdsaTest::EcdsaSecp256r1Sha256),
        (SECP256R1, ECDSA_WITH_SHA2_512) => test_ecdsa::<T>(EcdsaTest::EcdsaSecp256r1Sha512),
        (SECP384R1, ECDSA_WITH_SHA2_384) => test_ecdsa::<T>(EcdsaTest::EcdsaSecp384r1Sha384),
        (SECP521R1, ECDSA_WITH_SHA2_512) => test_ecdsa::<T>(EcdsaTest::EcdsaSecp521r1Sha512),
        _ => {}
    }
    match T::OID {
        ED25519 => test_eddsa::<T>(EddsaTest::Ed25519),
        ED448 => test_eddsa::<T>(EddsaTest::Ed448),
        _ => {}
    }
}

/// The base positive test.
pub fn test_default<T: Signer, R: Csprng>(rng: &mut R) {
    const MSG: &[u8] = b"hello, world!";
    let sk = T::SigningKey::random(rng);
    let sig = sk.sign(MSG).expect("unable to create signature");
    sk.public()
        .expect("signing key should be valid")
        .verify(MSG, &sig)
        .expect("unable to verify signature");
}

/// Test `Signer::SigningKey::ct_eq`.
///
/// It also tests `Signer::SigningKey::import`.
pub fn test_sk_ct_eq<T: Signer, R: Csprng>(rng: &mut R) {
    let sk1 = T::SigningKey::random(rng);
    let sk2 = T::SigningKey::random(rng);

    fn same_key<T: Signer, K: SigningKey<T> + for<'a> Import<&'a [u8]>>(k: K) {
        let data = match k.try_export_secret() {
            Ok(data) => data,
            Err(_) => {
                // Can't export the secret, so skip the test.
                return;
            }
        };
        let sk1 = K::import(data.raw_secret_bytes()).expect("should be able to import key");
        let sk2 = K::import(data.raw_secret_bytes()).expect("should be able to import key");
        assert_ct_eq!(sk1, sk2);
    }

    // The two keys should be different.
    assert_ct_ne!(sk1, sk2);
    // But each key should be equal to itself.
    same_key(sk1);
    same_key(sk2);
}

/// Test `Signer::VerifyingKey::eq`.
///
/// It also tests `Signer::VerifyingKey::import`.
pub fn test_pk_eq<T: Signer, R: Csprng>(rng: &mut R) {
    let pk1 = T::SigningKey::random(rng)
        .public()
        .expect("signing key should be valid");
    let pk2 = T::SigningKey::random(rng)
        .public()
        .expect("signing key should be valid");

    fn same_key<T: Signer, K: VerifyingKey<T>>(k: K) {
        let pk1 = K::import(k.export().borrow()).expect("should be able to import key");
        let pk2 = K::import(k.export().borrow()).expect("should be able to import key");
        assert_eq!(pk1, pk2);
    }

    // The two keys should be different.
    assert_ne!(pk1, pk2);
    // But each key should be equal to itself.
    same_key(pk1);
    same_key(pk2);
}

/// [`SigningKey::public`] should always return the same key.
pub fn test_public<T: Signer, R: Csprng>(rng: &mut R) {
    let sk = T::SigningKey::random(rng);
    assert_eq!(sk.public(), sk.public());
}

/// Simple positive test for [`Signer::verify_batch`].
pub fn test_batch_simple_good<T: Signer, R: Csprng>(rng: &mut R) {
    const MSGS: &[&[u8]] = &[
        b"hello",
        b"world",
        b"!",
        b"a longer message",
        b"",
        b"test_batch_simple_good",
        b"message #7",
        b"message #9",
        b"off by one",
    ];
    let (pks, sigs): (Vec<_>, Vec<_>) = MSGS
        .iter()
        .map(|msg| {
            let sk = T::SigningKey::random(rng);
            let sig = sk.sign(msg).expect("should not fail");
            (sk.public().expect("signer key should be valid"), sig)
        })
        .unzip();
    T::verify_batch(MSGS, &sigs[..], &pks[..]).expect("should not fail")
}

/// Simple negative test for [`Signer::verify_batch`].
pub fn test_batch_simple_bad<T: Signer, R: Csprng>(rng: &mut R) {
    let msgs: &mut [&[u8]] = &mut [
        b"hello",
        b"world",
        b"!",
        b"a longer message",
        b"",
        b"test_batch_simple_bad",
        b"message #7",
        b"message #9",
        b"off by one",
    ];
    let (pks, sigs): (Vec<_>, Vec<_>) = msgs
        .iter()
        .map(|msg| {
            let sk = T::SigningKey::random(rng);
            let sig = sk.sign(msg).expect("should not fail");
            (sk.public().expect("signing key should be valid"), sig)
        })
        .unzip();
    msgs[msgs.len() / 2] = b"AAAAAAAAAAAAA";
    T::verify_batch(msgs, &sigs[..], &pks[..]).expect_err("should fail");
}
