//! ISO/IEC [OID]s.
//!
//! [OID]: https://en.wikipedia.org/wiki/Object_identifier

use core::{fmt, hash::Hash, iter::FusedIterator};

const MAX_SIZE: usize = 39;

/// An OID.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct Oid {
    len: u8,
    der: [u8; MAX_SIZE],
}

impl Oid {
    /// Parses an OID from its text representation.
    pub fn parse(s: &str) -> Result<Self, InvalidOid> {
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

    fn arcs(&self) -> Arcs<'_> {
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

struct Arcs<'a> {
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

type Arc = u64;

#[derive(Debug)]
struct EncBuf {
    buf: [u8; MAX_SIZE],
    idx: usize,
}

impl EncBuf {
    const fn new() -> Self {
        Self {
            buf: [0; MAX_SIZE],
            idx: 0,
        }
    }

    fn encode(mut self, mut n: Arc) -> Option<Self> {
        if self.idx >= self.buf.len() {
            return None;
        }

        if n == 0 {
            self.buf[self.idx] = 0;
            self.idx += 1;
            return Some(self);
        }

        let len = base128_len(n);
        if self.buf.len() - self.idx < len {
            return None;
        }

        if true {
            let s = n.leading_zeros() / 8;
            n <<= s * 8;
        } else {
            let mut i = 0;
            while i < len - 1 {
                let s = (len - i - 1) * 7;
                self.buf[self.idx] = ((n >> s) as u8) | 0x80;
                self.idx += 1;
                i += 1;
            }
            self.buf[self.idx] = (n & 0x7f) as u8;
            self.idx += 1;
        }

        Some(self)
    }
}

const fn base128_len(n: Arc) -> usize {
    if n == 0 {
        1
    } else {
        (((<Arc>::BITS - n.leading_zeros()) + 6) / 7) as usize
    }
}

/// Parses digits from `s`, stopping at the first non-digit.
///
/// It returns the parsed digits and the unparsed digits.
fn parse_digits(s: &[u8]) -> Result<(Arc, &[u8]), InvalidOid> {
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

    type Test = (&'static [u8], bool, &'static str);
    static TESTS: &[Test] = &[
        (&[], false, ""),
        (&[0x80, 0x01], false, ""),
        (&[0x01, 0x80, 0x01], false, ""),
        (&[1, 2, 3], true, "0.1.2.3"),
        (&[41, 2, 3], true, "1.1.2.3"),
        (&[86, 2, 3], true, "2.6.2.3"),
        (&[41, 255, 255, 255, 127], true, "1.1.268435455"),
        (&[41, 0x87, 255, 255, 255, 127], true, "1.1.2147483647"),
        (&[41, 255, 255, 255, 255, 127], true, "1.1.34359738367"),
        (
            &[42, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "1.2.9223372036854775807",
        ),
        (
            &[43, 0x81, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "1.3.18446744073709551615",
        ),
        // (
        //     &[44, 0x83, 255, 255, 255, 255, 255, 255, 255, 255, 127],
        //     true,
        //     "1.4.36893488147419103231",
        // ),
        // (
        //     &[85, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127],
        //     true,
        //     "2.5.1180591620717411303423",
        // ),
        // (
        //     &[
        //         85, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127,
        //     ],
        //     true,
        //     "2.5.19342813113834066795298815",
        // ),
        (&[255, 255, 255, 127], true, "2.268435375"),
        (&[0x87, 255, 255, 255, 127], true, "2.2147483567"),
        (&[255, 127], true, "2.16303"),
        (&[255, 255, 255, 255, 127], true, "2.34359738287"),
        (
            &[255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "2.9223372036854775727",
        ),
        (
            &[0x81, 255, 255, 255, 255, 255, 255, 255, 255, 127],
            true,
            "2.18446744073709551535",
        ),
        // (
        //     &[0x83, 255, 255, 255, 255, 255, 255, 255, 255, 127],
        //     true,
        //     "2.36893488147419103151",
        // ),
        // (
        //     &[255, 255, 255, 255, 255, 255, 255, 255, 255, 127],
        //     true,
        //     "2.1180591620717411303343",
        // ),
        // (
        //     &[255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 127],
        //     true,
        //     "2.19342813113834066795298735",
        // ),
        (
            &[41, 0x80 | 66, 0x80 | 44, 0x80 | 11, 33],
            true,
            "1.1.139134369",
        ),
        (&[0x80 | 66, 0x80 | 44, 0x80 | 11, 33], true, "2.139134289"),
    ];

    #[test]
    fn test_parse() {
        for (i, (data, valid, str)) in TESTS.iter().enumerate() {
            let result = Oid::parse(str);
            if !valid {
                assert!(result.is_err(), "#{i}");
                continue;
            }
            let got = result.unwrap();
            let want = Oid {
                len: data.len() as u8,
                der: {
                    let mut b = [0u8; MAX_SIZE];
                    b[..data.len()].copy_from_slice(data);
                    b
                },
            };
            assert_eq!(got, want, "#{i}: `{str}` (got = `{got}`)");
        }
    }
}
