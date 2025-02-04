//! [`Hpke`] tests.

use alloc::vec;

use generic_array::GenericArray;
use typenum::U64;

use crate::{
    aead::{Aead, IndCca2},
    csprng::{Csprng, Random},
    hpke::{AeadId, AlgId, Hpke, KdfId, KemId, Mode, OpenCtx, SealCtx},
    kdf::{Expand, Kdf, KdfError, Prk},
    kem::{DecapKey, Kem},
};

/// Invokes `callback` for each HPKE test.
///
/// # Example
///
/// ```
/// use spideroak_crypto::{
///     default::Rng,
///     rust::{
///         Aes256Gcm,
///         DhKemP256HkdfSha256,
///         HkdfSha256,
///     },
///     test_hpke,
/// };
///
/// # spideroak_crypto::__doctest_os_hardware_rand!();
/// macro_rules! run_test {
///     ($test:ident) => {
///         spideroak_crypto::test_util::hpke::$test::<
///             DhKemP256HkdfSha256,
///             HkdfSha256,
///             Aes256Gcm,
///             _,
///         >(&mut Rng);
///     };
/// }
/// spideroak_crypto::for_each_hpke_test!(run_test);
/// ```
#[macro_export]
macro_rules! for_each_hpke_test {
    ($callback:ident) => {
        $crate::__apply! {
            $callback,
            test_vectors,
            test_round_trip,
            test_export,
        }
    };
}
pub use for_each_hpke_test;

/// Performs all of the tests in this module.
///
/// This macro expands into a bunch of individual `#[test]`
/// functions.
///
/// # Example
///
/// ```
/// use spideroak_crypto::{
///     rust::{
///         Aes256Gcm,
///         DhKemP256HkdfSha256,
///         HkdfSha256,
///     },
///     test_hpke,
/// };
///
/// test_hpke!(mod dhkemp256hkdfsha256_hkdfsha256_aes256gcm,
///     DhKemP256HkdfSha256,
///     HkdfSha256,
///     Aes256Gcm,
/// );
/// ```
#[macro_export]
macro_rules! test_hpke {
    (mod $name:ident, $kem:ty, $kdf:ty, $aead:ty $(,)?) => {
        mod $name {
            #[allow(unused_imports)]
            use super::*;

            $crate::test_hpke!($kem, $kdf, $aead);
        }
    };
    ($kem:ty, $kdf:ty, $aead:ty $(,)?) => {
        macro_rules! __hpke_test {
            ($test:ident) => {
                #[test]
                fn $test() {
                    $crate::test_util::hpke::$test::<$kem, $kdf, $aead, _>(
                        &mut $crate::default::Rng,
                    )
                }
            };
        }
        $crate::for_each_hpke_test!(__hpke_test);
    };
}
pub use test_hpke;

/// Tests against HPKE-specific vectors.
pub fn test_vectors<K, F, A, R>(_rng: &mut R)
where
    K: Kem + AlgId<KemId>,
    F: Kdf + AlgId<KdfId>,
    A: Aead + IndCca2 + AlgId<AeadId>,
    R: Csprng,
{
    use crate::test_util::wycheproof::test_hpke;

    let id = (K::ID, F::ID, A::ID);
    if let Some(name) = try_find_test(id.into()) {
        test_hpke::<K, F, A>(name);
    }
}

macro_rules! map_hpke_ids {
    ($($id:ident),+ $(,)?) => {
        fn try_find_test(id: $crate::test_util::wycheproof::hpke::HpkeId) -> Option<$crate::test_util::wycheproof::HpkeTest> {
            use $crate::test_util::wycheproof::{hpke::HpkeId, HpkeTest};
            match id {
                $(
                    HpkeId::$id => Some(HpkeTest::$id),
                )+
                _ => None,
            }
        }
    }
}

map_hpke_ids! {
    HpkeDhKemP256HkdfSha256HkdfSha256Aes128Gcm,
    HpkeDhKemP256HkdfSha256HkdfSha256Aes256Gcm,
    HpkeDhKemP256HkdfSha256HkdfSha256ChaCha20Poly1305,
    HpkeDhKemP256HkdfSha256HkdfSha512Aes128Gcm,
    HpkeDhKemP256HkdfSha256HkdfSha512Aes256Gcm,
    HpkeDhKemP256HkdfSha256HkdfSha512ChaCha20Poly1305,
    HpkeDhKemP521HkdfSha512HkdfSha256Aes128Gcm,
    HpkeDhKemP521HkdfSha512HkdfSha256Aes256Gcm,
    HpkeDhKemP521HkdfSha512HkdfSha256ChaCha20Poly1305,
    HpkeDhKemP521HkdfSha512HkdfSha512Aes128Gcm,
    HpkeDhKemP521HkdfSha512HkdfSha512Aes256Gcm,
    HpkeDhKemP521HkdfSha512HkdfSha512ChaCha20Poly1305,
    HpkeDhKemX25519HkdfSha256HkdfSha256Aes128Gcm,
    HpkeDhKemX25519HkdfSha256HkdfSha256Aes256Gcm,
    HpkeDhKemX25519HkdfSha256HkdfSha256ChaCha20Poly1305,
    HpkeDhKemX25519HkdfSha256HkdfSha512Aes128Gcm,
    HpkeDhKemX25519HkdfSha256HkdfSha512Aes256Gcm,
    HpkeDhKemX25519HkdfSha256HkdfSha512ChaCha20Poly1305,
    HpkeDhKemX448HkdfSha512HkdfSha256Aes128Gcm,
    HpkeDhKemX448HkdfSha512HkdfSha256Aes256Gcm,
    HpkeDhKemX448HkdfSha512HkdfSha256ChaCha20Poly1305,
    HpkeDhKemX448HkdfSha512HkdfSha512Aes128Gcm,
    HpkeDhKemX448HkdfSha512HkdfSha512Aes256Gcm,
    HpkeDhKemX448HkdfSha512HkdfSha512ChaCha20Poly1305,
}

/// Tests the full encryption-decryption cycle.
#[allow(non_snake_case)]
pub fn test_round_trip<K, F, A, R>(rng: &mut R)
where
    K: Kem + AlgId<KemId>,
    F: Kdf + AlgId<KdfId>,
    A: Aead + IndCca2 + AlgId<AeadId>,
    R: Csprng,
{
    const GOLDEN: &[u8] = b"some plaintext";
    const AD: &[u8] = b"some additional data";
    const INFO: &[u8] = b"some contextual binding";

    let skR = K::DecapKey::random(rng);
    let pkR = skR.public().expect("encap key should be valid");

    let (enc, mut send) = Hpke::<K, F, A>::setup_send(rng, Mode::Base, &pkR, INFO)
        .expect("unable to create send context");
    let mut recv = Hpke::<K, F, A>::setup_recv(Mode::Base, &enc, &skR, INFO)
        .expect("unable to create recv context");

    let ciphertext = {
        let mut dst = vec![0u8; GOLDEN.len() + SealCtx::<A>::OVERHEAD];
        send.seal(&mut dst, GOLDEN, AD).expect("encryption failed");
        dst
    };
    let plaintext = {
        let mut dst = vec![0u8; ciphertext.len() - OpenCtx::<A>::OVERHEAD];
        recv.open(&mut dst, &ciphertext, AD)
            .expect("decryption failed");
        dst
    };
    assert_eq!(plaintext, GOLDEN);
}

/// Tests that [`crate::hpke::SendCtx::export`] is the same as
/// [`crate::hpke::SendCtx::export_into`] is the same as
/// [`crate::hpke::RecvCtx::export`] is the same as
/// [`crate::hpke::RecvCtx::export_into`].
#[allow(non_snake_case)]
pub fn test_export<K, F, A, R>(rng: &mut R)
where
    K: Kem + AlgId<KemId>,
    F: Kdf + AlgId<KdfId>,
    A: Aead + IndCca2 + AlgId<AeadId>,
    R: Csprng,
{
    const INFO: &[u8] = b"some contextual binding";

    let skR = K::DecapKey::random(rng);
    let pkR = skR.public().expect("encap key should be valid");

    let (enc, send) = Hpke::<K, F, A>::setup_send(rng, Mode::Base, &pkR, INFO)
        .expect("unable to create send context");
    let recv = Hpke::<K, F, A>::setup_recv(Mode::Base, &enc, &skR, INFO)
        .expect("unable to create recv context");

    #[derive(Debug, Default, Eq, PartialEq)]
    struct Key(GenericArray<u8, U64>);
    impl Expand for Key {
        type Size = U64;

        fn expand_multi<'a, K, I>(prk: &Prk<K::PrkSize>, info: I) -> Result<Self, KdfError>
        where
            K: Kdf,
            I: IntoIterator<Item = &'a [u8]>,
            I::IntoIter: Clone,
        {
            Ok(Self(Expand::expand_multi::<K, I>(prk, info)?))
        }
    }

    const CTX: &[u8] = b"test_export";
    let got1 = send.export::<Key>(CTX).expect("`SendCtx::export` failed");
    let got2 = {
        let mut key = Key::default();
        send.export_into(&mut key.0, CTX)
            .expect("`SendCtx::export_into` failed");
        key
    };
    let got3 = recv.export::<Key>(CTX).expect("`RecvCtx::export` failed");
    let got4 = {
        let mut key = Key::default();
        recv.export_into(&mut key.0, CTX)
            .expect("`RecvCtx::export_into` failed");
        key
    };

    assert_eq!(
        got1, got2,
        "`SendCtx::export` and `SendCtx::export_into` mismatch"
    );
    assert_eq!(
        got2, got3,
        "`SendCtx::export_into` and `RecvCtx::export` mismatch"
    );
    assert_eq!(
        got3, got4,
        "`RecvCtx::export` and `RecvCtx::export_into` mismatch"
    );
}
