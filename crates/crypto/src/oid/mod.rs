//! ISO/IEC [OID]s.
//!
//! [OID]: https://en.wikipedia.org/wiki/Object_identifier

pub mod consts;

use core::{fmt, hash::Hash, iter::FusedIterator, ops::Deref, slice};

macro_rules! const_try {
    ($expr:expr $(,)?) => {
        match $expr {
            ::core::result::Result::Ok(val) => val,
            ::core::result::Result::Err(err) => {
                return ::core::result::Result::Err(err);
            }
        }
    };
}

/// Associates an OID with a cryptographic algorithm.
pub trait Identified {
    /// The algorithm's OID.
    const OID: &'static Oid;
}

/// Creates a constant [`Oid`] at compile time.
///
/// # Examples
///
/// ```rust
/// use spideroak_crypto::{oid, oid::Oid};
///
/// const NIST: Oid = oid!("2.16.840.1.101.3.4");
/// let nist = oid!("2.16.840.1.101.3.4");
/// assert_eq!(nist, NIST);
///
/// let nist = Oid::try_from_arcs(&[2, 16, 840, 1, 101, 3, 4]);
/// assert_eq!(nist, Ok(NIST));
/// ```
#[macro_export]
macro_rules! oid {
    ($oid:expr) => {{
        const OUTPUT: &'static $crate::oid::Oid =
            match $crate::oid::Oid::try_from_bytes($crate::spideroak_crypto_derive::oid!($oid)) {
                ::core::result::Result::Ok(oid) => oid,
                ::core::result::Result::Err(_) => ::core::panic!("invalid OID"),
            };
        OUTPUT
    }};
}

/// Extends a constant [`Oid`] at compile time.
///
/// # Examples
///
/// ```rust
/// use spideroak_crypto::{extend_oid, oid, oid::Oid};
///
/// const NIST: Oid = oid!("2.16.840.1.101.3.4");
/// const NIST_AES: Oid = oid!("2.16.840.1.101.3.4.1");
///
/// let nist_aes = extend_oid!(NIST, 1);
/// assert_eq!(nist_aes, NIST_AES);
///
/// let nist_aes = NIST.try_extend(&[1]);
/// assert_eq!(nist_aes, Ok(NIST_AES));
/// ```
#[macro_export]
macro_rules! extend_oid {
    ($oid:expr, $($arcs:expr),+) => {{
        const LEN: usize = {
            let mut n = $oid.len();
            $( n += $crate::oid::base128_len($arcs); )+
            n
        };
        const OUTPUT: $crate::oid::OidBuf<{ LEN }> = match $oid {
            oid => match oid.try_extend::<{ LEN }>(&[$($arcs),+]) {
                ::core::result::Result::Ok(oid) => oid,
                ::core::result::Result::Err(_) => ::core::panic!("invalid OID"),
            }
        };
        OUTPUT.as_oid()
    }};
}

/// An OID.
#[derive(Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
#[repr(transparent)]
pub struct Oid([u8]);

impl Oid {
    /// Converts the DER-encoded OID into an `Oid`.
    #[inline]
    pub const fn try_from_bytes(der: &[u8]) -> Result<&Self, InvalidOid> {
        // TODO: validate
        let oid = Self::from_bytes_unchecked(der);
        Ok(oid)
    }

    /// Converts the DER-encoded OID into an `Oid`.
    const fn from_bytes_unchecked(der: &[u8]) -> &Self {
        // SAFETY: `Oid` and `[u8]` have the same layout in
        // memory since `Oid` is a `#[repr(transparent)]` wrapper
        // around `[u8]`.
        unsafe { &*(der as *const [u8] as *const Self) }
    }

    /// Returns the size in bytes of the DER encoded object
    /// identifier.
    #[inline]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the DER encoded object identifier.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Extends the OID with additional arcs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use spideroak_crypto::{extend_oid, oid, oid::Oid};
    ///
    /// const NIST: Oid = oid!("2.16.840.1.101.3.4");
    /// const NIST_AES: Oid = oid!("2.16.840.1.101.3.4.1");
    ///
    /// let nist_aes = NIST.try_extend(&[1]);
    /// assert_eq!(nist_aes, Ok(NIST_AES));
    /// ```
    pub const fn try_extend<const N: usize>(&self, arcs: &[Arc]) -> Result<OidBuf<N>, InvalidOid> {
        self.to_owned().try_extend(arcs)
    }

    /// Converts the OID into an `OidBuf`.
    pub const fn to_owned<const N: usize>(&self) -> OidBuf<N> {
        assert!(N >= self.len());

        let der = self.as_bytes();

        let mut out = [0; N];
        let mut i = 0;
        while i < der.len() {
            out[i] = der[i];
            i += 1;
        }
        OidBuf {
            len: i as u8,
            der: out,
        }
    }

    /// Reports whether `self` starts with `other`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use spideroak_crypto::{extend_oid, oid, oid::Oid};
    ///
    /// const NIST: Oid = oid!("2.16.840.1.101.3.4");
    /// const NIST_AES: Oid = oid!("2.16.840.1.101.3.4.1");
    ///
    /// assert!(NIST_AES.starts_with(&NIST));
    /// ```
    pub const fn starts_with(&self, other: &Self) -> bool {
        let lhs = self.as_bytes();
        let rhs = other.as_bytes();
        if lhs.len() < rhs.len() {
            // `a` cannot start with `b` if `a` is shorter than
            // `b`.
            return false;
        }
        let mut i = 0;
        while i < rhs.len() {
            if lhs[i] != rhs[i] {
                return false;
            }
            // Cannot overflow, but avoids a lint.
            i = i.wrapping_add(1)
        }
        true
    }

    /// Returns an iterator over the arcs in an [`Oid`].
    pub const fn arcs(&self) -> Arcs<'_> {
        Arcs {
            der: self.as_bytes(),
            idx: 0,
        }
    }
}

impl PartialEq<Oid> for [u8] {
    fn eq(&self, other: &Oid) -> bool {
        PartialEq::eq(other.as_bytes(), self)
    }
}

impl PartialEq<[u8]> for Oid {
    fn eq(&self, other: &[u8]) -> bool {
        PartialEq::eq(self.as_bytes(), other)
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, arc) in self.arcs().enumerate() {
            if i > 0 {
                write!(f, ".")?;
            }
            write!(f, "{arc}")?;
        }
        Ok(())
    }
}

/// The default maximum size in octets of a DER-encoded OID.
///
/// It is large enough to encode [UUID] OIDs.
///
/// [UUID]: https://itu.int/ITU-T/X.667
// NB: 23 + len (u8) pads `OidBuf` to 24 bytes, a multiple of 8.
pub const DEFAULT_MAX_ENCODED_SIZE: usize = 23;

/// An OID.
#[derive(Copy, Clone, Debug, Hash, Eq, PartialEq, Ord, PartialOrd)]
pub struct OidBuf<const N: usize = DEFAULT_MAX_ENCODED_SIZE> {
    /// Invariant: `len` is a valid index into `der`.
    len: u8,
    /// Invariant: `der[..len]` is always valid DER.
    der: [u8; N],
}

impl OidBuf {}

impl<const N: usize> OidBuf<N> {
    /// The maximum size of the buffer.
    pub const MAX_ENCODED_SIZE: usize = N;

    /// Parses an OID from its text representation.
    ///
    /// ```rust
    /// use spideroak_crypto::oid::Oid;
    ///
    /// let oid = Oid::try_parse("2.16.840.1.101.3.4").unwrap();
    /// let der = &[96, 134, 72, 1, 101, 3, 4];
    /// assert_eq!(oid.as_bytes(), der);
    /// ```
    pub const fn try_parse(s: &str) -> Result<Self, InvalidOid> {
        let s = s.as_bytes();
        if s.is_empty() {
            return Err(invalid_oid("empty string"));
        }

        let (arc1, s) = const_try!(parse_digits(s));
        let Some((&b'.', s)) = s.split_first() else {
            return Err(invalid_oid("missing first dot"));
        };
        let (arc2, mut s) = const_try!(parse_digits(s));

        let mut buf = const_try!(EncBuf::new(arc1, arc2));

        while let Some((&b'.', rest)) = s.split_first() {
            let (arc, rest) = const_try!(parse_digits(rest));
            buf = const_try!(buf.encode(arc));
            s = rest;
        }
        if !s.is_empty() {
            return Err(invalid_oid("invalid character"));
        }

        Ok(buf.build())
    }

    /// Creates an OID from its arcs.
    ///
    /// ```rust
    /// use spideroak_crypto::oid::Oid;
    ///
    /// let from_arcs = Oid::try_parse("2.16.840.1.101.3.4").unwrap();
    /// let from_str = Oid::try_from_arcs(&[2, 16, 840, 1, 101, 3, 4]).unwrap();
    /// assert_eq!(from_arcs, from_str);
    /// ```
    pub const fn try_from_arcs(arcs: &[Arc]) -> Result<Self, InvalidOid> {
        let (&arc1, arcs) = match arcs.split_first() {
            Some(arc) => arc,
            None => return Err(invalid_oid("missing first arc")),
        };
        let (&arc2, arcs) = match arcs.split_first() {
            Some(arc) => arc,
            None => return Err(invalid_oid("missing second arc")),
        };
        const_try!(EncBuf::new(arc1, arc2)).build().try_extend(arcs)
    }

    /// Returns a reference to the owned OID.
    pub const fn as_oid(&self) -> &Oid {
        Oid::from_bytes_unchecked(self.as_bytes())
    }

    /// Extends the OID with more arcs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use spideroak_crypto::{extend_oid, oid, oid::Oid};
    ///
    /// const NIST: Oid = oid!("2.16.840.1.101.3.4");
    /// const NIST_AES: Oid = oid!("2.16.840.1.101.3.4.1");
    ///
    /// let nist_aes = NIST.try_extend(&[1]);
    /// assert_eq!(nist_aes, Ok(NIST_AES));
    /// ```
    pub const fn try_extend(self, mut arcs: &[Arc]) -> Result<Self, InvalidOid> {
        let mut buf = EncBuf {
            buf: self.der,
            idx: self.len as usize,
        };
        while let Some((&arc, rest)) = arcs.split_first() {
            arcs = rest;
            buf = const_try!(buf.encode(arc));
        }
        Ok(buf.build())
    }

    const fn len(&self) -> usize {
        self.len as usize
    }

    /// Returns the DER encoded object identifier.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        // SAFETY:
        // - The pointer is coming from a slice, so all
        //   invariants are upheld.
        // - `self.len` is in [0, self.buf.len()).
        unsafe { slice::from_raw_parts(self.der.as_ptr(), self.len()) }
    }

    /// Reports whether `self` starts with `other`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use spideroak_crypto::{extend_oid, oid, oid::Oid};
    ///
    /// const NIST: Oid = oid!("2.16.840.1.101.3.4");
    /// const NIST_AES: Oid = oid!("2.16.840.1.101.3.4.1");
    ///
    /// assert!(NIST_AES.starts_with(&NIST));
    /// ```
    pub const fn starts_with(&self, other: &Self) -> bool {
        self.as_oid().starts_with(other.as_oid())
    }

    /// Returns an iterator over the arcs in the OID.
    pub const fn arcs(&self) -> Arcs<'_> {
        self.as_oid().arcs()
    }
}

impl<T, const N: usize> AsRef<T> for OidBuf<N>
where
    T: ?Sized,
    <OidBuf<N> as Deref>::Target: AsRef<T>,
{
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

impl<const N: usize> Deref for OidBuf<N> {
    type Target = Oid;

    fn deref(&self) -> &Self::Target {
        self.as_oid()
    }
}

impl<const N: usize> fmt::Display for OidBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_oid().fmt(f)
    }
}

/// An iterator over the arcs in an [`Oid`].
#[derive(Clone, Debug)]
pub struct Arcs<'a> {
    der: &'a [u8],
    // NB: This is the arc index, not an index into `der`.
    idx: usize,
}

impl Arcs<'_> {
    /// Returns the number of arcs.
    ///
    /// ```rust
    /// use spideroak_crypto::{oid, oid::Oid};
    ///
    /// const NIST: Oid = oid!("2.16.840.1.101.3.4");
    ///
    /// let mut arcs = NIST.arcs();
    /// assert_eq!(arcs.remaining(), 7);
    /// assert_eq!(arcs.next(), Some(2));
    /// assert_eq!(arcs.remaining(), 6);
    /// assert_eq!(arcs.next(), Some(16));
    /// assert_eq!(arcs.remaining(), 5);
    /// ```
    pub fn remaining(&self) -> usize {
        let mut n = 0usize;
        if self.idx == 0 {
            n = 1;
        }
        let mut der = self.der;

        // TODO(eric): Figure out whether this is worth it.
        while let Some((chunk, rest)) = der.split_first_chunk::<8>() {
            const MASK: u64 = 0x8080808080808080;
            let w = u64::from_le_bytes(
                // SAFETY: `chunk` is exactly 8 bytes and has
                // the same alignment as `*const [u8; 8]`.
                unsafe { *(chunk.as_ptr().cast::<[u8; 8]>()) },
            );
            let ones = ((w & MASK).count_ones()) as usize;
            // Cannot wrap, but avoids a lint.
            n = n.wrapping_add(8usize.wrapping_sub(ones));

            der = rest;
        }

        while let Some((&v, rest)) = der.split_first() {
            if v & 0x80 == 0 {
                n = n.wrapping_add(1);
            }
            der = rest;
        }

        n
    }
}

impl Iterator for Arcs<'_> {
    type Item = Arc;

    fn next(&mut self) -> Option<Self::Item> {
        let (arc, rest) = parse_arc(self.der)?;
        let arc = match self.idx {
            0 => {
                if arc < 80 {
                    arc / 40
                } else {
                    2
                }
            }
            1 => {
                if arc < 80 {
                    arc % 40
                } else {
                    // Cannot wrap, but avoids a lint.
                    arc.wrapping_sub(80)
                }
            }
            _ => arc,
        };
        if self.idx > 0 {
            // The first two arcs are encoded together.
            self.der = rest;
        }
        self.idx = self.idx.saturating_add(1);
        Some(arc)
    }

    #[inline]
    fn count(self) -> usize {
        self.len()
    }

    #[inline]
    fn size_hint(&self) -> (usize, Option<usize>) {
        let n = self.len();
        (n, Some(n))
    }
}

impl ExactSizeIterator for Arcs<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.remaining()
    }
}

impl FusedIterator for Arcs<'_> {}

/// An OID arc (segment, component, etc.).
pub type Arc = u128;

/// Parse a base-128 arc.
const fn parse_arc(mut der: &[u8]) -> Option<(Arc, &[u8])> {
    let mut arc = 0;
    let mut i = 0usize;
    while let Some((&v, rest)) = der.split_first() {
        // Arcs must be minimally encoded, so the leading byte
        // cannot be 0x80.
        if i == 0 && v == 0x80 {
            break;
        }
        // Cannot overflow, but avoids a lint.
        i = i.wrapping_add(1);

        arc <<= 7;
        arc |= (v as Arc) & 0x7f;
        if v & 0x80 == 0 {
            // Too many digits.
            const MAX: usize = base128_len(Arc::MAX);
            if i > MAX {
                break;
            }
            return Some((arc, rest));
        }
        der = rest;
    }
    None
}

/// Encodes [`Arc`]s.
#[derive(Clone, Debug)]
struct EncBuf<const N: usize> {
    /// Invariant: `len` is a valid index into `der`.
    idx: usize,
    /// Invariant: `buf[..len]` is always valid DER.
    buf: [u8; N],
}

impl<const N: usize> EncBuf<N> {
    const fn new(arc1: Arc, arc2: Arc) -> Result<Self, InvalidOid> {
        // There are three possible top-level arcs (ITU-T, ISO,
        // and joint-iso-itu-t), so `arc1` is in [0, 2].
        //
        // If `arc1` is in [0, 1] (ITU-T or ISO), `arc2` must be
        // in [0, 39]. Otherwise, `arc2` can be any value.
        if arc1 > 2 || (arc1 < 2 && arc2 >= 40) {
            return if arc1 > 2 {
                Err(invalid_oid("first arc out of range"))
            } else {
                Err(invalid_oid("second arc out of range"))
            };
        }

        // The first two arcs are encoded as `(arc1*40)+arc2`.
        //
        // `arc1*40` cannot overflow since `arc1` is in [0, 2].
        //
        // [1]: https://www.oss.com/asn1/resources/books-whitepapers-pubs/larmouth-asn1-book.pdf
        // [2]: https://luca.ntop.org/Teaching/Appunti/asn1.html
        #[allow(clippy::arithmetic_side_effects)]
        let arc = match (arc1 * 40).checked_add(arc2) {
            Some(arc) => arc,
            None => return Err(invalid_oid("second arc out of range")),
        };

        let mut buf = Self {
            idx: 0,
            buf: [0; N],
        };
        buf = const_try!(buf.encode(arc));

        Ok(buf)
    }

    /// Encodes `arc` and returns the updated buffer.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "All arithmetic has been checked."
    )]
    const fn encode(mut self, arc: Arc) -> Result<Self, InvalidOid> {
        if self.idx >= self.buf.len() {
            return Err(invalid_oid("input too long"));
        }

        if arc == 0 {
            self.buf[self.idx] = 0;
            self.idx += 1;
            return Ok(self);
        }

        let nbytes = base128_len(arc);

        // We checked at the start of the method that
        // `self.buf.len() < self.idx`.
        let remaining = self.buf.len() - self.idx;
        if remaining < nbytes {
            return Err(invalid_oid("input too long"));
        }

        // Coping `self.idx` and updating it later helps the
        // compiler elide the bounds check when assigning to
        // `self.buf`.
        //
        // TODO(eric): open an issue for this.
        let mut idx = self.idx;

        let mut i = 0;
        while i < nbytes {
            // The loop condition is `i < nbytes`, so the
            // subtraction cannot wrap.
            //
            // `nbytes` is `ceil(bitlen(arc)/7)`, so the
            // multiplication cannot overflow.
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

        Ok(self)
    }

    const fn build(self) -> OidBuf<N> {
        OidBuf {
            len: self.idx as u8,
            der: self.buf,
        }
    }
}

/// Returns the number of bytes needed to represent `arc` encoded
/// as a base-128 integer.
#[allow(clippy::arithmetic_side_effects, reason = "Cannot wrap")]
#[doc(hidden)]
pub const fn base128_len(arc: Arc) -> usize {
    if arc == 0 {
        1
    } else {
        bitlen(arc).div_ceil(7) as usize
    }
}

/// Returns the number of bits needed to represent `arc`.
#[allow(clippy::arithmetic_side_effects, reason = "Cannot wrap")]
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
        #[allow(clippy::arithmetic_side_effects, reason = "`c` is at least `b'0'`")]
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
        (
            &[
                105, 131, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
                255, 255, 255, 127,
            ],
            true,
            "2.25.340282366920938463463374607431768211455",
            &[2, 25, 340282366920938463463374607431768211455],
        ),
    ];

    #[test]
    fn test_parse() {
        for (i, (data, valid, str, arcs)) in TESTS.iter().enumerate() {
            let result = OidBuf::try_parse(str);
            if !valid {
                assert!(result.is_err(), "#{i}");
                continue;
            }
            let want = OidBuf {
                len: data.len() as u8,
                der: {
                    let mut b = [0u8; DEFAULT_MAX_ENCODED_SIZE];
                    b[..data.len()].copy_from_slice(data);
                    b
                },
            };

            let got = result.unwrap();
            assert_eq!(got, want, "#{i}: `{str}` (got = `{got}`)");

            let got = OidBuf::try_from_arcs(arcs).unwrap();
            assert_eq!(got, want, "#{i}: `{arcs:?}` (got = `{got}`)");
        }
    }

    #[test]
    fn test_arcs() {
        for (i, (_, valid, str, arcs)) in TESTS.iter().enumerate() {
            if !valid {
                continue;
            }

            let oid: OidBuf = OidBuf::try_parse(str).unwrap();

            let got = oid.arcs().collect::<Vec<_>>();
            assert_eq!(&got, arcs, "#{i} `{str}`");

            let mut want = got.len();
            let mut arcs = oid.arcs();
            loop {
                let got = arcs.remaining();
                assert_eq!(got, want, "#{i}");
                if arcs.next().is_none() {
                    break;
                }
                want -= 1;
            }
        }
    }

    #[test]
    fn test_starts_with() {
        const A: &Oid = oid!("2.16.840.1.101.3.4");
        const B: &Oid = extend_oid!(A, 1);
        const C: &Oid = A;

        const TESTS: &[(&Oid, &Oid, bool)] = &[
            (A, A, true),
            (A, B, false),
            (A, C, true),
            (B, A, true),
            (B, B, true),
            (B, C, true),
            (C, A, true),
            (C, B, false),
            (C, C, true),
        ];
        for (i, (a, b, want)) in TESTS.iter().enumerate() {
            let got = a.starts_with(b);
            assert_eq!(got, *want, "#{i}");
        }
    }
}
