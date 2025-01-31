//! ISO/IEC [OID]s.
//!
//! [OID]: https://en.wikipedia.org/wiki/Object_identifier

use core::{fmt, hash::Hash, iter::FusedIterator};

/// Creates an [`Oid`] at compile time.
#[macro_export]
macro_rules! oid {
    ($oid:expr) => {{
        match $crate::oid::Oid::try_parse($oid) {
            ::core::result::Result::Ok(oid) => oid,
            ::core::result::Result::Err(_) => ::core::panic!("invalid OID"),
        }
    }};
}

/// Extends an [`Oid`] at compile time.
#[macro_export]
macro_rules! extend_oid {
    ($oid:expr, $($arcs:expr),+) => {{
        match $oid {
            oid => match oid.try_extend(&[$($arcs),+]) {
                ::core::result::Result::Ok(oid) => oid,
                ::core::result::Result::Err(_) => ::core::panic!("invalid OID"),
            }
        }
    }};
}

/// Well-know OIDs.
pub mod consts {
    const ANSI_X9_62: Oid = oid!("1.2.840.10045");
    const ANSI_X9_62_CURVES: Oid = extend_oid!(ANSI_X9_62, 3);
    const ANSI_X9_62_CURVES_PRIME: Oid = extend_oid!(ANSI_X9_62_CURVES, 1);
    const ANSI_X9_62_SIGNATURES: Oid = extend_oid!(ANSI_X9_62, 4);
    const ANSI_X9_62_SIGNATURES_ECDSA_WITH_SHA2: Oid = extend_oid!(ANSI_X9_62_SIGNATURES, 3);

    const CERTICOM_ARC: Oid = oid!("1.3.132");
    const CERTICOM_ARC_CURVE: Oid = extend_oid!(CERTICOM_ARC, 0);

    const DOD: Oid = oid!("1.3.6");
    const DOD_PKIX_ALGS: Oid = extend_oid!(DOD, 1, 5, 5, 7, 6);

    const NIST: Oid = oid!("2.16.840.1.101.3.4");
    const NIST_AES: Oid = extend_oid!(NIST, 1);
    const NIST_HASH_ALGS: Oid = extend_oid!(NIST, 2);
    const NIST_SIGN_ALGS: Oid = extend_oid!(NIST, 3);
    const NIST_KEMS: Oid = extend_oid!(NIST, 4);

    const RSADSI: Oid = oid!("1.2.840.113549");
    const RSADSI_DIGEST_ALG: Oid = extend_oid!(RSADSI, 2);

    const THAWTE: Oid = oid!("1.3.101");

    macro_rules! impl_oid {
        ($($name:ident, $doc:expr => $expr:expr),+ $(,)?) => {
            use crate::oid::Oid;

            $(
                #[doc = $doc]
                pub const $name: Oid = $expr;
            )+
        };
    }
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

        // RFC 4231
        HMAC_WITH_SHA2_256, "id-hmacWithSHA256" => extend_oid!(RSADSI_DIGEST_ALG, 9),
        HMAC_WITH_SHA2_384, "id-hmacWithSHA384" => extend_oid!(RSADSI_DIGEST_ALG, 10),
        HMAC_WITH_SHA2_512, "id-hmacWithSHA512" => extend_oid!(RSADSI_DIGEST_ALG, 11),

        // CSOR
        HMAC_WITH_SHA3_256, "id-hmacWithSHA3-256" => extend_oid!(NIST_HASH_ALGS, 14),
        HMAC_WITH_SHA3_384, "id-hmacWithSHA3-384" => extend_oid!(NIST_HASH_ALGS, 15),
        HMAC_WITH_SHA3_512, "id-hmacWithSHA3-512" => extend_oid!(NIST_HASH_ALGS, 16),

        // RFC 5758
        ECDSA_WITH_SHA2_256, "ecdsa-with-SHA256" => extend_oid!(ANSI_X9_62_SIGNATURES_ECDSA_WITH_SHA2, 2),
        ECDSA_WITH_SHA2_384, "ecdsa-with-SHA384" => extend_oid!(ANSI_X9_62_SIGNATURES_ECDSA_WITH_SHA2, 3),
        ECDSA_WITH_SHA2_512, "ecdsa-with-SHA512" => extend_oid!(ANSI_X9_62_SIGNATURES_ECDSA_WITH_SHA2, 4),

        // CSOR
        ECDSA_WITH_SHA3_256, "id-ecdsa-with-sha3-256" => extend_oid!(NIST_SIGN_ALGS, 10),
        ECDSA_WITH_SHA3_384, "id-ecdsa-with-sha3-384" => extend_oid!(NIST_SIGN_ALGS, 11),
        ECDSA_WITH_SHA3_512, "id-ecdsa-with-sha3-512" => extend_oid!(NIST_SIGN_ALGS, 12),

        // RFC 8692
        ECDSA_WITH_SHAKE_128, "id-ecdsa-with-shake128" => extend_oid!(DOD_PKIX_ALGS, 32),
        ECDSA_WITH_SHAKE_256, "id-ecdsa-with-shake256" => extend_oid!(DOD_PKIX_ALGS, 33),

        // RFC 8410
        X25519, "id-X25519" => extend_oid!(THAWTE, 110),
        X448, "id-X25519" => extend_oid!(THAWTE, 111),
        ED25519, "id-Ed25519" => extend_oid!(THAWTE, 112),
        ED448, "id-Ed449" => extend_oid!(THAWTE, 113),

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

        // RFC 5759, RFC 5480
        SECP256R1, "secp256r1" => extend_oid!(ANSI_X9_62_CURVES_PRIME, 7),
        SECP384R1, "secp384r1" => extend_oid!(CERTICOM_ARC_CURVE, 34),
        SECP521R1, "secp521r1" => extend_oid!(CERTICOM_ARC_CURVE, 35),
    }
}

const MAX_SIZE: usize = 39;

/// An OID.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Oid {
    len: u8,
    der: [u8; MAX_SIZE],
}

impl Oid {
    /// Parses an OID from its text representation.
    pub const fn try_parse(s: &str) -> Result<Self, InvalidOid> {
        let s = s.as_bytes();
        if s.is_empty() {
            return Err(invalid_oid("empty string"));
        }

        let (arc1, s) = match parse_digits(s) {
            Ok(arc) => arc,
            Err(err) => return Err(err),
        };
        let Some((&b'.', s)) = s.split_first() else {
            return Err(invalid_oid("missing first dot"));
        };
        let (arc2, mut s) = match parse_digits(s) {
            Ok(arc) => arc,
            Err(err) => return Err(err),
        };
        if arc1 > 2 || (arc1 < 2 && arc2 >= 40) {
            return Err(invalid_oid("first arc out of range"));
        }

        let mut buf = EncBuf::new();

        let arc = (arc1 * 40) + arc2;
        buf = match buf.encode(arc) {
            Some(b) => b,
            None => return Err(invalid_oid("input too long")),
        };

        while let Some((&b'.', rest)) = s.split_first() {
            let (arc, rest) = match parse_digits(rest) {
                Ok(arc) => arc,
                Err(err) => return Err(err),
            };
            buf = match buf.encode(arc) {
                Some(b) => b,
                None => return Err(invalid_oid("input too long")),
            };
            s = rest;
        }
        if !s.is_empty() {
            return Err(invalid_oid("invalid character"));
        }

        Ok(Oid {
            len: buf.idx as u8,
            der: buf.buf,
        })
    }

    /// Creates an OID from its arcs.
    pub const fn try_from_arcs(arcs: &[Arc]) -> Result<Self, InvalidOid> {
        let mut buf = EncBuf::new();
        let (&arc1, arcs) = match arcs.split_first() {
            Some(arc) => arc,
            None => return Err(invalid_oid("missing first arc")),
        };
        let (&arc2, mut arcs) = match arcs.split_first() {
            Some(arc) => arc,
            None => return Err(invalid_oid("missing second arc")),
        };

        let arc = (arc1 * 40) + arc2;
        buf = match buf.encode(arc) {
            Some(b) => b,
            None => return Err(invalid_oid("input too long")),
        };

        while let Some((&arc, rest)) = arcs.split_first() {
            arcs = rest;
            buf = match buf.encode(arc) {
                Some(b) => b,
                None => return Err(invalid_oid("input too long")),
            };
        }

        Ok(Oid {
            len: buf.idx as u8,
            der: buf.buf,
        })
    }

    /// Extends the OID with more arcs.
    pub const fn try_extend(self, mut arcs: &[Arc]) -> Result<Self, InvalidOid> {
        let mut buf = EncBuf {
            buf: self.der,
            idx: self.len as usize,
        };
        while let Some((&arc, rest)) = arcs.split_first() {
            arcs = rest;
            buf = match buf.encode(arc) {
                Some(b) => b,
                None => return Err(invalid_oid("input too long")),
            };
        }
        Ok(Oid {
            len: buf.idx as u8,
            der: buf.buf,
        })
    }

    /// Reports whether `self` starts with `other`.
    pub const fn starts_with(&self, other: &Self) -> bool {
        if self.len < other.len {
            return false;
        }
        let mut i = 0;
        while i < other.len as usize {
            if other.der[i] != self.der[i] {
                return false;
            }
            i += 1;
        }
        true
    }

    /// Returns an iterator over the arcs in an [`Oid`].
    pub fn arcs(&self) -> Arcs<'_> {
        Arcs {
            der: &self.der[..self.len as usize],
        }
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let arcs = self.arcs();
        for (i, arc) in arcs.enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

/// An iterator over the arcs in an [`Oid`].
#[derive(Clone, Debug)]
pub struct Arcs<'a> {
    der: &'a [u8],
}

impl Iterator for Arcs<'_> {
    type Item = Arc;

    fn next(&mut self) -> Option<Self::Item> {
        let mut arc = 0;
        let mut s = 0;
        while let Some((&v, rest)) = self.der.split_first() {
            self.der = rest;
            if v < 0x80 {
                arc |= <Arc>::from(v) << s;
                return Some(arc);
            }
            arc |= <Arc>::from(v & 0x7f) << s;
            s += 7;
        }
        None
    }
}

impl FusedIterator for Arcs<'_> {}

/// An OID arc.
pub type Arc = u64;

/// Encodes [`Arc`]s.
#[derive(Clone, Debug)]
struct EncBuf {
    buf: [u8; MAX_SIZE],
    /// Invariant: `idx` is always a valid index into `buf`.
    idx: usize,
}

impl EncBuf {
    const fn new() -> Self {
        Self {
            buf: [0; MAX_SIZE],
            idx: 0,
        }
    }

    /// Encodes `arc` and returns the updated buffer.
    ///
    /// It returns [`None`] if there is not enough room to encode
    /// `arc`.
    const fn encode(mut self, arc: Arc) -> Option<Self> {
        if self.idx >= self.buf.len() {
            return None;
        }

        if arc == 0 {
            self.buf[self.idx] = 0;
            self.idx += 1;
            return Some(self);
        }

        let nbytes = base128_len(arc);

        let remaining = self.buf.len() - self.idx;
        if remaining < nbytes {
            return None;
        }

        // Coping `self.idx` and updating it later helps the
        // compiler elide the bounds check when assigning to
        // `self.buf`.
        //
        // TODO(eric): open an issue for this.
        let mut idx = self.idx;

        let mut i = 0;
        while i < nbytes {
            let s = (nbytes - 1 - i) * 7;
            let mut v = ((arc >> s) as u8) & 0x7f;
            if i < nbytes - 1 {
                v |= 0x80;
            }
            self.buf[idx] = v;
            idx += 1;
            i += 1;
        }

        self.idx = idx;

        Some(self)
    }
}

const fn base128_len(arc: Arc) -> usize {
    if arc == 0 {
        1
    } else {
        (((bitlen(arc)) + 6) / 7) as usize
    }
}

const fn bitlen(arc: Arc) -> u32 {
    <Arc>::BITS - arc.leading_zeros()
}

/// Parses digits from `s`, stopping at the first non-digit.
///
/// It returns the parsed digits and the unparsed digits.
const fn parse_digits(s: &[u8]) -> Result<(Arc, &[u8]), InvalidOid> {
    let mut rest: &[u8] = s;
    let mut x: Arc = 0;
    while let Some((c @ (b'0'..=b'9'), tmp)) = rest.split_first() {
        let d = (*c - b'0') as Arc;
        x = match x.checked_mul(10) {
            Some(x) => x,
            None => return Err(invalid_oid("mul overflow")),
        };
        x = match x.checked_add(d) {
            Some(x) => x,
            None => return Err(invalid_oid("add overflow")),
        };
        rest = tmp;
    }
    Ok((x, rest))
}

/// An OID is invalid.
#[derive(Copy, Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[cfg_attr(debug_assertions, error("invalid OID: {reason}"))]
#[cfg_attr(not(debug_assertions), error("invalid OID"))]
pub struct InvalidOid {
    #[cfg(debug_assertions)]
    reason: &'static str,
    #[cfg(not(debug_assertions))]
    reason: (),
}

const fn invalid_oid(_reason: &'static str) -> InvalidOid {
    cfg_if::cfg_if! {
        if #[cfg(debug_assertions)] {
            InvalidOid { reason: _reason }
        } else {
            InvalidOid { reason: () }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type Test = (&'static [u8], bool, &'static str, &'static [Arc]);
    static TESTS: &[Test] = &[
        (&[], false, "", &[]),
        (&[0x80, 0x01], false, "", &[]),
        (&[0x01, 0x80, 0x01], false, "", &[]),
        (&[1, 2, 3], true, "0.1.2.3", &[0, 1, 2, 3]),
        (&[41, 2, 3], true, "1.1.2.3", &[1, 1, 2, 3]),
        (&[86, 2, 3], true, "2.6.2.3", &[2, 6, 2, 3]),
        (
            &[41, 255, 255, 255, 127],
            true,
            "1.1.268435455",
            &[1, 1, 268435455],
        ),
        (
            &[41, 0x87, 255, 255, 255, 127],
            true,
            "1.1.2147483647",
            &[1, 1, 2147483647],
        ),
        (
            &[41, 255, 255, 255, 255, 127],
            true,
            "1.1.34359738367",
            &[1, 1, 34359738367],
        ),
        (
            &[42, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "1.2.9223372036854775807",
            &[1, 2, 9223372036854775807],
        ),
        (
            &[43, 0x81, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "1.3.18446744073709551615",
            &[1, 3, 18446744073709551615],
        ),
        (&[255, 255, 255, 127], true, "2.268435375", &[2, 268435375]),
        (
            &[0x87, 255, 255, 255, 127],
            true,
            "2.2147483567",
            &[2, 2147483567],
        ),
        (&[255, 127], true, "2.16303", &[2, 16303]),
        (
            &[255, 255, 255, 255, 127],
            true,
            "2.34359738287",
            &[2, 34359738287],
        ),
        (
            &[255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "2.9223372036854775727",
            &[2, 9223372036854775727],
        ),
        (
            &[0x81, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "2.18446744073709551535",
            &[2, 18446744073709551535],
        ),
        (
            &[41, 0x80 | 66, 0x80 | 44, 0x80 | 11, 33],
            true,
            "1.1.139134369",
            &[1, 1, 139134369],
        ),
        (
            &[0x80 | 66, 0x80 | 44, 0x80 | 11, 33],
            true,
            "2.139134289",
            &[2, 139134289],
        ),
    ];

    #[test]
    fn test_parse() {
        for (i, (data, valid, str, arcs)) in TESTS.iter().enumerate() {
            let result = Oid::try_parse(str);
            if !valid {
                assert!(result.is_err(), "#{i}");
                continue;
            }
            let want = Oid {
                len: data.len() as u8,
                der: {
                    let mut b = [0u8; MAX_SIZE];
                    b[..data.len()].copy_from_slice(data);
                    b
                },
            };

            let got = result.unwrap();
            assert_eq!(got, want, "#{i}: parse `{str}` (got = `{got}`)");

            let got = Oid::try_from_arcs(arcs).unwrap();
            assert_eq!(got, want, "#{i}: parse `{arcs:?}` (got = `{got}`)");
        }
    }
}
