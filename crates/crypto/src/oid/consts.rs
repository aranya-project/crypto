//! Well-know OIDs.

use crate::{extend_oid, oid, oid::Oid};

macro_rules! impl_oid {
    ($($name:ident, $doc:expr => $expr:expr),+ $(,)?) => {
        $(
            #[doc = $doc]
            pub const $name: &'static Oid = $expr;
        )+
    };
}

const ANSI_X9_62: &'static Oid = oid!("1.2.840.10045");
const ANSI_X9_62_CURVES_PRIME: &'static Oid = extend_oid!(ANSI_X9_62, 3, 1);
const ANSI_X9_62_SIGNATURES_ECDSA_WITH_SHA2: &'static Oid = extend_oid!(ANSI_X9_62, 4, 3);

impl_oid! {
    // RFC 5759, RFC 5480
    SECP256R1, "secp256r1" => extend_oid!(ANSI_X9_62_CURVES_PRIME, 7),

    // RFC 5758
    ECDSA_WITH_SHA2_256, "ecdsa-with-SHA256" => extend_oid!(ANSI_X9_62_SIGNATURES_ECDSA_WITH_SHA2, 2),
    ECDSA_WITH_SHA2_384, "ecdsa-with-SHA384" => extend_oid!(ANSI_X9_62_SIGNATURES_ECDSA_WITH_SHA2, 3),
    ECDSA_WITH_SHA2_512, "ecdsa-with-SHA512" => extend_oid!(ANSI_X9_62_SIGNATURES_ECDSA_WITH_SHA2, 4),
}

const CERTICOM_ARC: &'static Oid = oid!("1.3.132");
const CERTICOM_ARC_CURVE: &'static Oid = extend_oid!(CERTICOM_ARC, 0);

impl_oid! {
    // RFC 5759, RFC 5480
    SECP384R1, "secp384r1" => extend_oid!(CERTICOM_ARC_CURVE, 34),
    SECP521R1, "secp521r1" => extend_oid!(CERTICOM_ARC_CURVE, 35),
}

const DOD: &'static Oid = oid!("1.3.6");
const DOD_PKIX_ALGS: &'static Oid = extend_oid!(DOD, 1, 5, 5, 7, 6);

impl_oid! {
    // RFC 8692
    ECDSA_WITH_SHAKE_128, "id-ecdsa-with-shake128" => extend_oid!(DOD_PKIX_ALGS, 32),
    ECDSA_WITH_SHAKE_256, "id-ecdsa-with-shake256" => extend_oid!(DOD_PKIX_ALGS, 33),
}

const NIST: &'static Oid = oid!("2.16.840.1.101.3.4");
const NIST_AES: &'static Oid = extend_oid!(NIST, 1);
const NIST_HASH_ALGS: &'static Oid = extend_oid!(NIST, 2);
const NIST_SIGN_ALGS: &'static Oid = extend_oid!(NIST, 3);
const NIST_KEMS: &'static Oid = extend_oid!(NIST, 4);

impl_oid! {
    // CSOR
    AES_128_GCM, "id-aes128-GCM" => extend_oid!(NIST_AES, 6),
    AES_192_GCM, "id-aes128-GCM" => extend_oid!(NIST_AES, 26),
    AES_256_GCM, "id-aes128-GCM" => extend_oid!(NIST_AES, 46),

    // CSOR, RFC 5758
    SHA2_256, "id-sha256" => extend_oid!(NIST_HASH_ALGS, 1),
    SHA2_384, "id-sha384" => extend_oid!(NIST_HASH_ALGS, 2),
    SHA2_512, "id-sha512" => extend_oid!(NIST_HASH_ALGS, 3),
    SHA2_512_256, "id-sha512-256" => extend_oid!(NIST_HASH_ALGS, 6),

    // CSOR
    SHA3_256, "id-sha3-256" => extend_oid!(NIST_HASH_ALGS, 8),
    SHA3_384, "id-sha3-384" => extend_oid!(NIST_HASH_ALGS, 9),
    SHA3_512, "id-sha3-512" => extend_oid!(NIST_HASH_ALGS, 10),

    // CSOR
    SHAKE_128, "id-shake128" => extend_oid!(NIST_HASH_ALGS, 11),
    SHAKE_256, "id-shake256" => extend_oid!(NIST_HASH_ALGS, 12),

    // CSOR
    KMAC_128, "id-KMAC128" => extend_oid!(NIST_HASH_ALGS, 21),
    KMAC_256, "id-KMAC256" => extend_oid!(NIST_HASH_ALGS, 22),

    // CSOR
    HMAC_WITH_SHA3_256, "id-hmacWithSHA3-256" => extend_oid!(NIST_HASH_ALGS, 14),
    HMAC_WITH_SHA3_384, "id-hmacWithSHA3-384" => extend_oid!(NIST_HASH_ALGS, 15),
    HMAC_WITH_SHA3_512, "id-hmacWithSHA3-512" => extend_oid!(NIST_HASH_ALGS, 16),

    // CSOR
    ECDSA_WITH_SHA3_256, "id-ecdsa-with-sha3-256" => extend_oid!(NIST_SIGN_ALGS, 10),
    ECDSA_WITH_SHA3_384, "id-ecdsa-with-sha3-384" => extend_oid!(NIST_SIGN_ALGS, 11),
    ECDSA_WITH_SHA3_512, "id-ecdsa-with-sha3-512" => extend_oid!(NIST_SIGN_ALGS, 12),

    // CSOR
    ML_DSA_44, "id-ml-dsa-44" => extend_oid!(NIST_SIGN_ALGS, 17),
    ML_DSA_65, "id-ml-dsa-65" => extend_oid!(NIST_SIGN_ALGS, 18),
    ML_DSA_87, "id-ml-dsa-87" => extend_oid!(NIST_SIGN_ALGS, 19),

    // CSOR
    HASH_ML_DSA_44_WITH_SHA_512, "id-hash-ml-dsa-44-with-sha512" => extend_oid!(NIST_SIGN_ALGS, 32),
    HASH_ML_DSA_65_WITH_SHA_512, "id-hash-ml-dsa-65-with-sha512" => extend_oid!(NIST_SIGN_ALGS, 33),
    HASH_ML_DSA_87_WITH_SHA_512, "id-hash-ml-dsa-87-with-sha512" => extend_oid!(NIST_SIGN_ALGS, 34),

    // CSOR
    SLH_DSA_SHA2_128S, "id-slh-dsa-sha2-128s" => extend_oid!(NIST_SIGN_ALGS, 20),
    SLH_DSA_SHA2_128F, "id-slh-dsa-sha2-128f" => extend_oid!(NIST_SIGN_ALGS, 21),
    SLH_DSA_SHA2_192S, "id-slh-dsa-sha2-192s" => extend_oid!(NIST_SIGN_ALGS, 22),
    SLH_DSA_SHA2_192F, "id-slh-dsa-sha2-192f" => extend_oid!(NIST_SIGN_ALGS, 23),
    SLH_DSA_SHA2_256S, "id-slh-dsa-sha2-256s" => extend_oid!(NIST_SIGN_ALGS, 24),
    SLH_DSA_SHA2_256F, "id-slh-dsa-sha2-256f" => extend_oid!(NIST_SIGN_ALGS, 25),
    SLH_DSA_SHAKE_128S, "id-slh-dsa-shake-128s" => extend_oid!(NIST_SIGN_ALGS, 26),
    SLH_DSA_SHAKE_128F, "id-slh-dsa-shake-128s" => extend_oid!(NIST_SIGN_ALGS, 27),
    SLH_DSA_SHAKE_192S, "id-slh-dsa-shake-192s" => extend_oid!(NIST_SIGN_ALGS, 28),
    SLH_DSA_SHAKE_192F, "id-slh-dsa-shake-192f" => extend_oid!(NIST_SIGN_ALGS, 29),
    SLH_DSA_SHAKE_256S, "id-slh-dsa-shake-256s" => extend_oid!(NIST_SIGN_ALGS, 30),
    SLH_DSA_SHAKE_256F, "id-slh-dsa-shake-256f" => extend_oid!(NIST_SIGN_ALGS, 31),

    // CSOR
    HASH_SLH_DSA_SHA2_128S_WITH_SHA2_256, "id-hash-slh-dsa-sha2-128s-with-sha256" => extend_oid!(NIST_SIGN_ALGS, 35),
    HASH_SLH_DSA_SHA2_128F_WITH_SHA2_256, "id-hash-slh-dsa-sha2-128f-with-sha256" => extend_oid!(NIST_SIGN_ALGS, 36),
    HASH_SLH_DSA_SHA2_192S_WITH_SHA2_512, "id-hash-slh-dsa-sha2-192s-with-sha512" => extend_oid!(NIST_SIGN_ALGS, 37),
    HASH_SLH_DSA_SHA2_192F_WITH_SHA2_512, "id-hash-slh-dsa-sha2-192f-with-sha512" => extend_oid!(NIST_SIGN_ALGS, 38),
    HASH_SLH_DSA_SHA2_256S_WITH_SHA2_512, "id-hash-slh-dsa-sha2-256s-with-sha512" => extend_oid!(NIST_SIGN_ALGS, 39),
    HASH_SLH_DSA_SHA2_256F_WITH_SHA2_512, "id-hash-slh-dsa-sha2-256f-with-sha512" => extend_oid!(NIST_SIGN_ALGS, 40),
    HASH_SLH_DSA_SHAKE_128S_WITH_SHAKE_128, "id-hash-slh-dsa-shake-128s-with-shake128" => extend_oid!(NIST_SIGN_ALGS, 41),
    HASH_SLH_DSA_SHAKE_128F_WITH_SHAKE_128, "id-hash-slh-dsa-shake-128s-with-shake128" => extend_oid!(NIST_SIGN_ALGS, 42),
    HASH_SLH_DSA_SHAKE_192S_WITH_SHAKE_256, "id-hash-slh-dsa-shake-192s-with-shake256" => extend_oid!(NIST_SIGN_ALGS, 43),
    HASH_SLH_DSA_SHAKE_192F_WITH_SHAKE_256, "id-hash-slh-dsa-shake-192f-with-shake256" => extend_oid!(NIST_SIGN_ALGS, 44),
    HASH_SLH_DSA_SHAKE_256S_WITH_SHAKE_256, "id-hash-slh-dsa-shake-256s-with-shake256" => extend_oid!(NIST_SIGN_ALGS, 45),
    HASH_SLH_DSA_SHAKE_256F_WITH_SHAKE_256, "id-hash-slh-dsa-shake-256f-with-shake256" => extend_oid!(NIST_SIGN_ALGS, 46),

    // CSOR
    ML_KEM_512, "id-ml-kem-512" => extend_oid!(NIST_KEMS, 1),
    ML_KEM_768, "id-ml-kem-768" => extend_oid!(NIST_KEMS, 2),
    ML_KEM_1024, "id-ml-kem-1024" => extend_oid!(NIST_KEMS, 3),
}

const RSADSI: &'static Oid = oid!("1.2.840.113549");
const RSADSI_DIGEST_ALG: &'static Oid = extend_oid!(RSADSI, 2);
const RSADSI_PKCS9_SMIME_ALG: &'static Oid = extend_oid!(RSADSI, 1, 9, 16, 3);

impl_oid! {
    // RFC 4231, RFC 8018
    HMAC_WITH_SHA2_256, "id-hmacWithSHA256" => extend_oid!(RSADSI_DIGEST_ALG, 9),
    HMAC_WITH_SHA2_384, "id-hmacWithSHA384" => extend_oid!(RSADSI_DIGEST_ALG, 10),
    HMAC_WITH_SHA2_512, "id-hmacWithSHA512" => extend_oid!(RSADSI_DIGEST_ALG, 11),
    HMAC_WITH_SHA2_512_256, "id-hmacWithSHA512-256" => extend_oid!(RSADSI_DIGEST_ALG, 13),

    // RFC 8619
    HKDF_WITH_SHA2_256, "id-alg-hkdf-with-sha256" => extend_oid!(RSADSI_PKCS9_SMIME_ALG, 28),
    HKDF_WITH_SHA2_384, "id-alg-hkdf-with-sha384" => extend_oid!(RSADSI_PKCS9_SMIME_ALG, 29),
    HKDF_WITH_SHA2_512, "id-alg-hkdf-with-sha512" => extend_oid!(RSADSI_PKCS9_SMIME_ALG, 30),

    // RFC 8103
    CHACHA20_POLY1305, "id_alg_AEADChaCha20Poly1305" => extend_oid!(RSADSI_PKCS9_SMIME_ALG, 18),
}

// TODO(eric): Replace `12345` once our IANA request is accepted.
const SPIDEROAK: &'static Oid = oid!("1.3.6.1.4.1.32473");
const SPIDEROAK_AEAD: &'static Oid = extend_oid!(SPIDEROAK, 0);
const SPIDEROAK_CMT_AEAD: &'static Oid = extend_oid!(SPIDEROAK_AEAD, 0);

impl_oid! {
    UTC_AES_256_GCM, "id-utc-aes-256-gcm" => extend_oid!(SPIDEROAK_CMT_AEAD, 0),
    HTE_AES_256_GCM, "id-hte-aes-256-gcm" => extend_oid!(SPIDEROAK_CMT_AEAD, 1),
}

const THAWTE: &'static Oid = oid!("1.3.101");

impl_oid! {
    // RFC 8410
    X25519, "id-X25519" => extend_oid!(THAWTE, 110),
    X448, "id-X25519" => extend_oid!(THAWTE, 111),
    ED25519, "id-Ed25519" => extend_oid!(THAWTE, 112),
    ED448, "id-Ed449" => extend_oid!(THAWTE, 113),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_consts() {
        const TESTS: &[(&Oid, &str)] = &[
            // AES
            (AES_128_GCM, "2.16.840.1.101.3.4.1.6"),
            (AES_192_GCM, "2.16.840.1.101.3.4.1.26"),
            (AES_256_GCM, "2.16.840.1.101.3.4.1.46"),
            // HMAC
            (HMAC_WITH_SHA2_256, "1.2.840.113549.2.9"),
            (HMAC_WITH_SHA2_384, "1.2.840.113549.2.10"),
            (HMAC_WITH_SHA2_512, "1.2.840.113549.2.11"),
            (HMAC_WITH_SHA2_512_256, "1.2.840.113549.2.13"),
            // HKDF
            (HKDF_WITH_SHA2_256, "1.2.840.113549.1.9.16.3.28"),
            (HKDF_WITH_SHA2_384, "1.2.840.113549.1.9.16.3.29"),
            (HKDF_WITH_SHA2_512, "1.2.840.113549.1.9.16.3.30"),
            // TODO(eric): Add more tests.
        ];
        for (i, (oid, want)) in TESTS.iter().enumerate() {
            let got = oid.to_string();
            assert_eq!(got, *want, "#{i}");
        }
    }
}
