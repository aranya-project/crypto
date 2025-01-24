//! Test specific algorithms using test vectors.

use core::str::FromStr;

use subtle::ConstantTimeEq;

//use wycheproof::{aead, ecdh, ecdsa, eddsa, hkdf, mac};
use crate::{
    aead::{Aead, IndCca2},
    kdf::Kdf,
    kem::{Ecdh, Kem},
    mac::Mac,
    signer::Signer,
    test_util::wycheproof::{
        self, AeadTest, EcdhTest, EcdsaTest, EddsaTest, HkdfTest, HpkeTest, MacTest,
    },
};

// macro_rules! define_algs {
//     (
//         $name:ident;
//         $($alg:expr => $name:ident),* $(,)?
//     ) => {};
// }

/// Tests an [`Aead`].
pub fn test_aead<T: Aead>(alg: &str) {
    if let Ok(name) = AeadTest::from_str(alg) {
        wycheproof::test_aead::<T>(name);
    }
}

// define_algs! {
//     find_aead_alg
//     "A128CBC-HS256" => Aes128CbcHmacSha256,
//     "A192CBC-HS384" => Aes192CbcHmacSha384,
//     "A256CBC-HS512" => Aes256CbcHmacSha512,
//     "AEAD-AES-SIV-CMAC" => AesSivCmac,
//     "AEGIS128" => Aegis128,
//     "AEGIS128L" => Aegis128L,
//     "AEGIS256" => Aegis256,
//     "AES-CCM" => AesCcm,
//     "AES-EAX" => AesEax,
//     "AES-GCM" => AesGcm,
//     "AES-GCM-SIV" => AesGcmSiv,
//     "ARIA-CCM" => AriaCcm,
//     "ARIA-GCM" => AriaGcm,
//     "ASCON128" => Ascon128,
//     "ASCON128A" => Ascon128a,
//     "ASCON80PQ" => Ascon80pq,
//     "CAMELLIA-CCM" => CamelliaCcm,
//     "CAMELLIA-GCM" => CamelliaGcm,
//     "CHACHA20-POLY1305" => ChaCha20Poly1305,
//     "MORUS1280" => Morus1280,
//     "MORUS640" => Morus640,
//     "SEED-CCM" => SeedCcm,
//     "SEED-GCM" => SeedGcm,
//     "SM4-CCM" => Sm4Ccm,
//     "SM4-GCM" => Sm4Gcm,
//     "XCHACHA20-POLY1305" => XChaCha20Poly1305,
// }

/// Tests an [`Ecdh`].
pub fn test_ecdh<T: Ecdh>(alg: &str) {
    if let Ok(name) = EcdhTest::from_str(alg) {
        wycheproof::test_ecdh::<T>(name);
    }
}

/// Tests a [`Signer`].
pub fn test_ecdsa<T: Signer>(alg: &str) {
    if let Ok(name) = EcdsaTest::from_str(alg) {
        wycheproof::test_ecdsa::<T>(name);
    }
}

/// Tests a [`Signer`].
pub fn test_eddsa<T: Signer>(alg: &str) {
    if let Ok(name) = EddsaTest::from_str(alg) {
        wycheproof::test_eddsa::<T>(name);
    }
}

/// Tests a [`Kdf`].
pub fn test_hkdf<T: Kdf>(alg: &str) {
    if let Ok(name) = HkdfTest::from_str(alg) {
        wycheproof::test_hkdf::<T>(name);
    }
}

/// Tests an [`Hpke`].
pub fn test_hpke<K, F, A>(alg: &str)
where
    K: Kem,
    F: Kdf,
    A: Aead + IndCca2,
{
    if let Ok(name) = HpkeTest::from_str(alg) {
        wycheproof::test_hpke::<K, F, A>(name);
    }
}

/// Tests a [`Mac`].
pub fn test_mac<T: Mac>(alg: &str)
where
    T::Key: ConstantTimeEq,
    T::Tag: for<'a> TryFrom<&'a [u8]>,
{
    if let Ok(name) = MacTest::from_str(alg) {
        wycheproof::test_mac::<T>(name);
    }
}
