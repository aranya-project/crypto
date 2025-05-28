//! ISO/IEC [OID]s.
//!
//! [OID]: https://en.wikipedia.org/wiki/Object_identifier

pub mod consts;

use core::{fmt, hash::Hash, iter::FusedIterator, ops::Deref, slice, str::FromStr};

#[cfg(feature = "serde")]
use serde::{de, Deserialize, Deserializer, Serialize, Serializer};

use crate::util::const_assert;

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
/// // From a string literal.
/// const NIST1: &Oid = oid!("2.16.840.1.101.3.4");
///
/// // From a list of arcs.
/// const NIST2: &Oid = oid!(2, 16, 840, 1, 101, 3, 4);
/// # assert_eq!(NIST1, NIST2);
///
/// // From a string constant.
/// const NIST_OID_STR: &str = "2.16.840.1.101.3.4";
/// const NIST3: &Oid = oid!(NIST_OID_STR);
/// # assert_eq!(NIST2, NIST3);
///
/// // Can also be assigned to local variables.
/// let nist = oid!("2.16.840.1.101.3.4");
/// # assert_eq!(nist, NIST1);
/// ```
#[macro_export]
macro_rules! oid {
    ($oid:literal) => {{
        const OUTPUT: &'static $crate::oid::Oid =
            match $crate::oid::Oid::try_from_bytes($crate::spideroak_crypto_derive::oid!($oid)) {
                ::core::result::Result::Ok(oid) => oid,
                ::core::result::Result::Err(_) => ::core::panic!("invalid OID"),
            };
        OUTPUT
    }};
    ($oid:expr) => {{
        const LEN: usize = match $crate::oid::encoded_len($oid) {
            ::core::result::Result::Ok(n) => n,
            ::core::result::Result::Err(_) => ::core::panic!("invalid OID"),
        };
        const OUTPUT: $crate::oid::OidBuf<{ LEN }> =
            match $crate::oid::OidBuf::<{ LEN }>::try_parse($oid) {
                ::core::result::Result::Ok(oid) => oid,
                ::core::result::Result::Err(_) => ::core::panic!("invalid OID"),
            };
        OUTPUT.as_oid()
    }};
    ($($arc:expr),+ $(,)?) => {{
        const LEN: usize = {
            let mut n = 0;
            $( n += $crate::oid::vlq_len($arc); )+
            n
        };
        const OUTPUT: $crate::oid::OidBuf::<{ LEN }> =
            match $crate::oid::OidBuf::<{ LEN }>::try_from_arcs(&[$($arc),+]) {
                ::core::result::Result::Ok(oid) => oid,
                ::core::result::Result::Err(_) => ::core::panic!("invalid OID"),
            };
        OUTPUT.as_oid()
    }};
}

/// Extends a constant [`Oid`] at compile time.
///
/// # Examples
///
/// ```rust
/// use spideroak_crypto::{extend_oid, oid, oid::Oid};
///
/// const NIST: &Oid = oid!("2.16.840.1.101.3.4");
/// const NIST_AES: &Oid = extend_oid!(NIST, 1);
///
/// assert_eq!(NIST_AES, "2.16.840.1.101.3.4.1");
/// ```
#[macro_export]
macro_rules! extend_oid {
    ($oid:expr, $($arc:expr),+ $(,)?) => {{
        const LEN: usize = {
            let mut n = $oid.len();
            $( n += $crate::oid::vlq_len($arc); )+
            n
        };
        const OUTPUT: $crate::oid::OidBuf<{ LEN }> = match $oid {
            oid => match oid.try_extend::<{ LEN }>(&[$($arc),+]) {
                ::core::result::Result::Ok(oid) => oid,
                ::core::result::Result::Err(_) => ::core::panic!("invalid OID"),
            }
        };
        OUTPUT.as_oid()
    }};
}

use zerocopy::{Immutable, IntoBytes, KnownLayout, Unaligned};

/// A slice of a DER-encoded OID.
#[derive(
    Debug, Hash, Eq, PartialEq, Ord, PartialOrd, KnownLayout, Immutable, Unaligned, IntoBytes,
)]
#[repr(C)]
pub struct Oid([u8]);

impl Oid {
    /// Attempts to convert the DER-encoded OID into an `Oid`.
    #[inline]
    pub const fn try_from_bytes(der: &[u8]) -> Result<&Self, InvalidOid> {
        let last = match der.last() {
            Some(v) => *v,
            None => return Err(invalid_oid("DER is empty")),
        };
        if last & 0x80 != 0 {
            return Err(invalid_oid("last byte's continuation bit is set"));
        }
        let mut tmp = der;
        loop {
            tmp = const_try!(parse_arc_der(tmp)).1;
            if tmp.is_empty() {
                break;
            }
        }
        // SAFETY: We just checked that `der` is a valid DER
        // encoding of an OID.
        let oid = unsafe { Self::from_bytes_unchecked(der) };
        Ok(oid)
    }

    /// Converts the DER-encoded OID into an `Oid`.
    ///
    /// # Safety
    ///
    /// `der` must be a valid DER encoding of an OID.
    const unsafe fn from_bytes_unchecked(der: &[u8]) -> &Self {
        const_assert!(size_of::<&Oid>() == size_of::<&[u8]>());
        const_assert!(align_of::<&Oid>() == align_of::<&[u8]>());
        // SAFETY: `Oid` and `[u8]` have the same layout in
        // memory since `Oid` is newtype wrapper around `[u8]`.
        // NB: `Oid` is not `#[repr(transparent)]`, but it is
        // `#[repr(C)]`.
        unsafe { &*(der as *const [u8] as *const Self) }
    }

    /// Extends the OID with additional arcs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use spideroak_crypto::{extend_oid, oid, oid::Oid};
    ///
    /// const NIST: &Oid = oid!("2.16.840.1.101.3.4");
    /// const NIST_AES: &Oid = oid!("2.16.840.1.101.3.4.1");
    ///
    /// let nist_aes = NIST.try_extend::<{ NIST.len() + 1 }>(&[1]);
    /// assert_eq!(nist_aes.as_deref(), Ok(NIST_AES));
    /// ```
    #[must_use = "This method returns the result of the operation \
                  without modifying the original"]
    pub const fn try_extend<const N: usize>(&self, arcs: &[Arc]) -> Result<OidBuf<N>, InvalidOid> {
        self.to_oid_buf().try_extend(arcs)
    }

    /// Returns the size in bytes of the DER encoded object
    /// identifier.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "OIDs are never empty")]
    pub const fn len(&self) -> usize {
        self.0.len()
    }

    /// Returns the DER encoded object identifier.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Converts the OID into an `OidBuf`.
    ///
    /// # Panics
    ///
    /// This method panics if `N` is less than `self.len()`.
    #[allow(clippy::arithmetic_side_effects)]
    pub const fn to_oid_buf<const N: usize>(&self) -> OidBuf<N> {
        assert!(N >= self.len());

        let src = self.as_bytes();

        let mut der = [0; N];
        let mut len = 0;
        while len < src.len() {
            der[len] = src[len];
            len += 1;
        }
        OidBuf { idx: len, buf: der }
    }

    /// Reports whether `self` starts with `other`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use spideroak_crypto::{extend_oid, oid, oid::Oid};
    ///
    /// const NIST: &Oid = oid!("2.16.840.1.101.3.4");
    /// const NIST_AES: &Oid = oid!("2.16.840.1.101.3.4.1");
    ///
    /// assert!(NIST_AES.starts_with(&NIST));
    /// ```
    pub const fn starts_with(&self, other: &Self) -> bool {
        // DER encoded OIDs are canonical, so we can just do
        // a simple byte comparison.
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
    #[inline]
    pub const fn arcs(&self) -> Arcs<'_> {
        Arcs {
            der: self.as_bytes(),
            state: State::new(),
        }
    }
}

impl PartialEq<[u8]> for Oid {
    #[inline]
    fn eq(&self, other: &[u8]) -> bool {
        PartialEq::eq(self.as_bytes(), other)
    }
}

impl PartialEq<&[u8]> for Oid {
    #[inline]
    fn eq(&self, other: &&[u8]) -> bool {
        PartialEq::eq(self.as_bytes(), *other)
    }
}

impl PartialEq<Oid> for [u8] {
    #[inline]
    fn eq(&self, other: &Oid) -> bool {
        PartialEq::eq(other, self)
    }
}

// This is kinda silly, but it's ended up being useful.
impl PartialEq<str> for Oid {
    fn eq(&self, other: &str) -> bool {
        let mut lhs = self.arcs();
        let mut rhs = other.split('.');
        for (lhs, rhs) in lhs.by_ref().zip(rhs.by_ref()) {
            if !Arc::from_str(rhs).is_ok_and(|rhs| lhs == rhs) {
                return false;
            }
        }
        lhs.next().is_none() && rhs.next().is_none()
    }
}

impl PartialEq<&str> for Oid {
    fn eq(&self, other: &&str) -> bool {
        PartialEq::eq(self, *other)
    }
}

impl PartialEq<Oid> for str {
    fn eq(&self, other: &Oid) -> bool {
        PartialEq::eq(other, self)
    }
}

impl<const N: usize> PartialEq<OidBuf<N>> for Oid {
    #[inline]
    fn eq(&self, other: &OidBuf<N>) -> bool {
        PartialEq::eq(self, other.as_oid())
    }
}

impl<const N: usize> PartialEq<OidBuf<N>> for &Oid {
    #[inline]
    fn eq(&self, other: &OidBuf<N>) -> bool {
        PartialEq::eq(self, &other.as_oid())
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

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl Serialize for Oid {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        #[cfg(feature = "alloc")]
        if serializer.is_human_readable() {
            return serializer.collect_str(self);
        }
        serializer.serialize_bytes(self.as_bytes())
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de: 'a, 'a> Deserialize<'de> for &'a Oid {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            return Err(de::Error::custom("expected DER encoding of OID"));
        }
        let der = <&[u8]>::deserialize(deserializer)?;
        Oid::try_from_bytes(der).map_err(de::Error::custom)
    }
}

/// The default maximum size in octets of a DER-encoded OID.
///
/// It is large enough to encode [UUID] OIDs.
///
/// [UUID]: https://itu.int/ITU-T/X.667
const DEFAULT_MAX_ENCODED_SIZE: usize = 23;

/// An owned OID.
#[derive(Copy, Clone, Hash, Eq, Ord, PartialOrd)]
pub struct OidBuf<const N: usize = DEFAULT_MAX_ENCODED_SIZE> {
    /// Invariant: `idx` is a valid index into `buf`.
    idx: usize,
    /// Invariant: `buf[..len]` is always valid DER.
    buf: [u8; N],
}

impl<const N: usize> OidBuf<N> {
    /// The maximum size of the buffer.
    pub const MAX_ENCODED_SIZE: usize = N;

    const fn new(arc1: Arc, arc2: Arc) -> Result<Self, InvalidOid> {
        let oid = Self {
            idx: 0,
            buf: [0; N],
        };
        let arc = const_try!(combine_roots(arc1, arc2));
        oid.push(arc)
    }

    /// Parses an OID from its text representation.
    ///
    /// ```rust
    /// use spideroak_crypto::oid::OidBuf;
    ///
    /// let oid: OidBuf = OidBuf::try_parse("2.16.840.1.101.3.4").unwrap();
    /// let der = &[96, 134, 72, 1, 101, 3, 4];
    /// assert_eq!(oid.as_bytes(), der);
    /// ```
    pub const fn try_parse(s: &str) -> Result<Self, InvalidOid> {
        let s = s.as_bytes();
        if s.is_empty() {
            return Err(invalid_oid("empty string"));
        }

        let (arc1, s) = const_try!(parse_arc_digits(s));
        let Some((&b'.', s)) = s.split_first() else {
            return Err(invalid_oid("missing first dot"));
        };
        let (arc2, mut s) = const_try!(parse_arc_digits(s));

        let mut oid = const_try!(Self::new(arc1, arc2));
        while let Some((&b'.', rest)) = s.split_first() {
            let (arc, rest) = const_try!(parse_arc_digits(rest));
            oid = const_try!(oid.push(arc));
            s = rest;
        }
        if !s.is_empty() {
            return Err(invalid_oid("invalid character (expected `.`)"));
        }

        Ok(oid)
    }

    /// Creates an OID from its arcs.
    ///
    /// ```rust
    /// use spideroak_crypto::oid::OidBuf;
    ///
    /// let from_arcs: OidBuf = OidBuf::try_parse("2.16.840.1.101.3.4").unwrap();
    /// let from_str: OidBuf = OidBuf::try_from_arcs(&[2, 16, 840, 1, 101, 3, 4]).unwrap();
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
        const_try!(Self::new(arc1, arc2)).try_extend(arcs)
    }

    /// Extends the OID with more arcs.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use spideroak_crypto::{extend_oid, oid, oid::{Oid, OidBuf}};
    ///
    /// const NIST_AES: &Oid = oid!("2.16.840.1.101.3.4.1");
    ///
    /// let nist: OidBuf = OidBuf::try_from_arcs(&[2, 16, 840, 1, 101, 3]).unwrap();
    /// let nist_aes = nist.try_extend(&[4, 1]);
    /// assert_eq!(nist_aes.as_deref(), Ok(NIST_AES));
    /// ```
    #[must_use = "This method returns the result of the operation \
                  without modifying the original"]
    pub const fn try_extend(mut self, mut arcs: &[Arc]) -> Result<Self, InvalidOid> {
        while let Some((&arc, rest)) = arcs.split_first() {
            arcs = rest;
            self = const_try!(self.push(arc));
        }
        Ok(self)
    }

    /// Returns the size in bytes of the DER encoded object
    /// identifier.
    #[inline]
    #[allow(clippy::len_without_is_empty, reason = "OIDs are never empty")]
    pub const fn len(&self) -> usize {
        self.idx
    }

    /// Returns the DER encoded object identifier.
    #[inline]
    pub const fn as_bytes(&self) -> &[u8] {
        // SAFETY:
        // - The pointer is coming from a slice, so all
        //   invariants are upheld.
        // - `self.len` is in [0, self.buf.len()).
        unsafe { slice::from_raw_parts(self.buf.as_ptr(), self.len()) }
    }

    /// Returns a reference to the owned OID.
    #[inline]
    pub const fn as_oid(&self) -> &Oid {
        // SAFETY: `self.as_bytes` is a valid DER encoding of an
        // OID.
        unsafe { Oid::from_bytes_unchecked(self.as_bytes()) }
    }

    /// Reports whether `self` starts with `other`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use spideroak_crypto::{extend_oid, oid, oid::Oid};
    ///
    /// const NIST: &Oid = oid!("2.16.840.1.101.3.4");
    /// const NIST_AES: &Oid = oid!("2.16.840.1.101.3.4.1");
    ///
    /// assert!(NIST_AES.starts_with(&NIST));
    /// ```
    pub const fn starts_with(&self, other: &Self) -> bool {
        self.as_oid().starts_with(other.as_oid())
    }

    /// Returns an iterator over the arcs in the OID.
    #[inline]
    pub const fn arcs(&self) -> Arcs<'_> {
        self.as_oid().arcs()
    }

    /// Encodes `arc` and returns the updated buffer.
    #[allow(
        clippy::arithmetic_side_effects,
        reason = "All arithmetic has been checked."
    )]
    #[must_use = "This method returns the result of the operation \
                  without modifying the original"]
    const fn push(mut self, arc: Arc) -> Result<Self, InvalidOid> {
        if self.idx >= self.buf.len() {
            return Err(invalid_oid("input too long"));
        }

        if arc < 0x80 {
            self.buf[self.idx] = arc as u8;
            self.idx += 1;
            return Ok(self);
        }

        let nbytes = vlq_len(arc);

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
}

impl<T, const N: usize> PartialEq<T> for OidBuf<N>
where
    Oid: PartialEq<T>,
{
    #[inline]
    fn eq(&self, other: &T) -> bool {
        PartialEq::eq(self.as_oid(), other)
    }
}

impl<T, const N: usize> AsRef<T> for OidBuf<N>
where
    T: ?Sized,
    <OidBuf<N> as Deref>::Target: AsRef<T>,
{
    #[inline]
    fn as_ref(&self) -> &T {
        self.deref().as_ref()
    }
}

impl<const N: usize> Deref for OidBuf<N> {
    type Target = Oid;

    #[inline]
    fn deref(&self) -> &Self::Target {
        self.as_oid()
    }
}

impl<const N: usize> fmt::Debug for OidBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_oid().fmt(f)
    }
}

impl<const N: usize> fmt::Display for OidBuf<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_oid().fmt(f)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<const N: usize> Serialize for OidBuf<N> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        self.as_oid().serialize(serializer)
    }
}

#[cfg(feature = "serde")]
#[cfg_attr(docsrs, doc(cfg(feature = "serde")))]
impl<'de, const N: usize> Deserialize<'de> for OidBuf<N> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        if deserializer.is_human_readable() {
            Self::try_parse(Deserialize::deserialize(deserializer)?).map_err(de::Error::custom)
        } else {
            Oid::try_from_bytes(Deserialize::deserialize(deserializer)?)
                .map(Oid::to_oid_buf)
                .map_err(de::Error::custom)
        }
    }
}

/// An iterator over the arcs in an [`Oid`].
#[derive(Clone, Debug)]
pub struct Arcs<'a> {
    der: &'a [u8],
    // - Set to `First` before parsing the first arc.
    // - Set to `Second` after parsing the first arc.
    // - Set to `Rest` after parsing the second arc.
    state: State,
}

impl Arcs<'_> {
    /// Returns the number of arcs remaining in the iterator.
    ///
    /// ```rust
    /// use spideroak_crypto::{oid, oid::{Arc, Oid}};
    ///
    /// const NIST: &Oid = oid!("2.16.840.1.101.3.4");
    /// const ARCS: &[Arc] = &[2, 16, 840, 1, 101, 3, 4];
    ///
    /// let mut arcs = NIST.arcs();
    /// for i in 0..arcs.remaining() {
    ///     assert_eq!(arcs.remaining(), ARCS.len() - i);
    ///     assert_eq!(arcs.next(), Some(ARCS[i]));
    /// }
    /// assert_eq!(arcs.remaining(), 0);
    /// assert_eq!(arcs.next(), None);
    /// ```
    pub const fn remaining(&self) -> usize {
        let mut n = 0usize;
        if self.state.remaining() == 2 {
            n = 1;
        }
        let mut der = self.der;

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
        let (arc, rest) = parse_arc_der(self.der).ok()?;
        let idx = self.state.next();
        let arc = unpack_arc(arc, idx);
        if !idx.is_first() {
            self.der = rest;
        }
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

impl DoubleEndedIterator for Arcs<'_> {
    fn next_back(&mut self) -> Option<Self::Item> {
        let (arc, rest) = parse_arc_der_from_back(self.der).ok()?;
        if !rest.is_empty() {
            // There is still data at the start of the buffer, so
            // this is not the first or second arc.
            self.der = rest;
            return Some(arc);
        }
        let idx = self.state.next_back();
        let arc = unpack_arc(arc, idx);
        if self.state.exhausted() {
            self.der = &[];
        }
        Some(arc)
    }
}

impl ExactSizeIterator for Arcs<'_> {
    #[inline]
    fn len(&self) -> usize {
        self.remaining()
    }
}

impl FusedIterator for Arcs<'_> {}

/// Tracks which order the first two arcs are parsed in.
#[derive(Copy, Clone, Eq, PartialEq)]
struct State(u8);

impl State {
    const fn new() -> Self {
        Self(0b00)
    }

    fn next(&mut self) -> ArcIdx {
        match self.0 & 0b11 {
            // Haven't parsed any arcs.
            0b00 => {
                self.0 = 0b01;
                ArcIdx::First
            }
            // Already parsed the first arc from the front.
            0b01 => {
                self.0 = 0b11;
                ArcIdx::Second
            }
            // Already parsed the second arc from the back.
            0b10 => {
                self.0 = 0b11;
                ArcIdx::First
            }
            // Parsed all arcs.
            _ => ArcIdx::Rest,
        }
    }

    fn next_back(&mut self) -> ArcIdx {
        match self.0 & 0b11 {
            // Haven't parsed any arcs.
            0b00 => {
                self.0 = 0b10;
                ArcIdx::Second
            }
            // Already parsed the first arc from the front.
            0b01 => {
                self.0 = 0b11;
                ArcIdx::Second
            }
            // Already parsed the second arc from the back.
            0b10 => {
                self.0 = 0b11;
                ArcIdx::First
            }
            // Parsed all arcs.
            _ => ArcIdx::Rest,
        }
    }

    /// Have we parsed both the first and second arcs?
    const fn exhausted(self) -> bool {
        self.0 == 0b11
    }

    const fn remaining(self) -> usize {
        match self.0 & 0b11 {
            0b00 => 2,
            0b01 | 0b10 => 1,
            _ => 0,
        }
    }
}

impl fmt::Debug for State {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "State({:02b})", self.0)
    }
}

/// An OID arc (segment, component, etc.).
pub type Arc = u128;

/// Attempts to parse an [`Arc`] from `s`, returning the arc and
/// the remainder of `s`.
const fn parse_arc_digits(s: &[u8]) -> Result<(Arc, &[u8]), InvalidOid> {
    let mut rest = s;
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

/// Attempts to parse an [`Arc`] from `der`, returning the arc
/// and the remainder of `der`.
const fn parse_arc_der(mut der: &[u8]) -> Result<(Arc, &[u8]), InvalidOid> {
    let mut arc: Arc = 0;
    let mut i: usize = 0;
    while let Some((&v, rest)) = der.split_first() {
        // Arcs must be minimally encoded, so the leading byte
        // cannot be 0x80.
        if i == 0 && v == 0x80 {
            return Err(invalid_oid("arc not minimally encoded"));
        }
        // Cannot overflow, but avoids a lint.
        i = i.wrapping_add(1);

        arc = match arc.checked_shl(7) {
            Some(arc) => arc,
            None => return Err(invalid_oid("arc out of range (must be in [0, 2^128))")),
        };
        arc |= (v as Arc) & 0x7f;
        if v & 0x80 == 0 {
            const MAX: usize = vlq_len(Arc::MAX);
            if i > MAX {
                // Too many digits.
                return Err(invalid_oid("arc out of range (must be in [0, 2^64))"));
            }
            return Ok((arc, rest));
        }
        der = rest;
    }
    Err(invalid_oid("unexpected end of arc"))
}

/// Attempts to parse an [`Arc`] from the end of `der`, returning
/// the arc and the remainder of `der`.
const fn parse_arc_der_from_back(der: &[u8]) -> Result<(Arc, &[u8]), InvalidOid> {
    // The last byte must not have a continuation bit set.
    let [.., 0..128] = der else {
        return Err(invalid_oid("unexpected end of arc"));
    };

    #[allow(clippy::arithmetic_side_effects)]
    let mut i = der.len() - 1;
    let (head, mut tail) = loop {
        match der.split_at_checked(i) {
            // Still have a condinuation bit set for `head`, so
            // continue until we run into the preceeding arc.
            Some(([.., 128..=255], [.., 0..128])) => i = i.saturating_sub(1),
            Some((head @ ([] | [.., 0..128]), tail @ [.., 0..128])) => break (head, tail),
            _ => return Err(invalid_oid("unexpected end of arc")),
        }
    };

    if let [0x80, ..] = tail {
        return Err(invalid_oid("arc not minimally encoded"));
    }
    const MAX: usize = vlq_len(Arc::MAX);
    if i > MAX {
        // Too many digits.
        return Err(invalid_oid("arc out of range (must be in [0, 2^64))"));
    }
    let mut arc: Arc = 0;
    while let Some((&v, rest)) = tail.split_first() {
        arc = match arc.checked_shl(7) {
            Some(arc) => arc,
            None => return Err(invalid_oid("arc out of range (must be in [0, 2^128))")),
        };
        arc |= (v as Arc) & 0x7f;
        tail = rest;
    }
    Ok((arc, head))
}

/// Combines the two root arcs.
const fn combine_roots(arc1: Arc, arc2: Arc) -> Result<Arc, InvalidOid> {
    // There are three possible top-level arcs (ITU-T, ISO,
    // and joint-iso-itu-t), so `arc1` is in [0, 2].
    //
    // If `arc1` is in [0, 1] (ITU-T or ISO), `arc2` must be
    // in [0, 39]. Otherwise, `arc2` can be any value.
    if arc1 > 2 {
        return Err(invalid_oid("first arc out of range (must be in [0, 2])"));
    }
    if arc1 < 2 && arc2 >= 40 {
        return Err(invalid_oid("second arc out of range"));
    }

    // The first two arcs are encoded as a single VLQ
    //
    //    (arc1*40)+arc2
    //
    // `arc1*40` cannot overflow since `arc1` is in [0, 2].
    //
    // [1]: https://www.oss.com/asn1/resources/books-whitepapers-pubs/larmouth-asn1-book.pdf
    // [2]: https://luca.ntop.org/Teaching/Appunti/asn1.html
    #[allow(clippy::arithmetic_side_effects)]
    match (arc1 * 40).checked_add(arc2) {
        Some(arc) => Ok(arc),
        None => Err(invalid_oid("second arc out of range")),
    }
}

/// The index into a logical list of [`Arc`]s.
#[derive(Copy, Clone, Debug)]
enum ArcIdx {
    /// `arcs[0]`
    First,
    /// `arcs[1]`
    Second,
    /// `arcs[2..]`
    Rest,
}

impl ArcIdx {
    const fn is_first(self) -> bool {
        matches!(self, Self::First)
    }
}

/// Unpacks the arc at `idx`.
const fn unpack_arc(arc: Arc, idx: ArcIdx) -> Arc {
    // The first two arcs are encoded into a single initial arc
    //    arc = (arc1*40) + arc2
    // which can either take form one
    //    arc1 = [0, 1]
    //    arc2 = [0, 39]
    // or form two
    //    arc1 = 2
    //    arc2 = [0, 2^128)
    //
    // If the initial arc is less then 80 then it must be form
    // one because
    //      (arc1*40) + arc2
    //    = ([0, 1] * 40) + [0, 39]
    //    = [0, 40] + [0, 39]
    //    = [0, 79]
    //
    // Otherwise, it must be form two because
    //      (arc1*40) + arc2
    //    = (2 * 40) + [0, 2^128)
    //    = 80 + [0, 2^128)
    //    = [80, (2^128)+80)
    match idx {
        ArcIdx::First => {
            if arc < 80 {
                arc / 40
            } else {
                2
            }
        }
        ArcIdx::Second => {
            if arc < 80 {
                arc % 40
            } else {
                // Cannot wrap, but avoids a lint.
                arc.wrapping_sub(80)
            }
        }
        ArcIdx::Rest => arc,
    }
}

/// Returns the number of bytes needed to represent `arc` encoded
/// as a VLQ (base-128 integer).
#[doc(hidden)]
#[allow(clippy::arithmetic_side_effects, reason = "Cannot wrap")]
pub const fn vlq_len(arc: Arc) -> usize {
    if arc == 0 {
        1
    } else {
        // This could be `div_ceil(7)`, but the compiler can't
        // reason about the output bounds as well, which prevents
        // it from eliding bounds checks.
        ((bitlen(arc) + 6) / 7) as usize
    }
}

/// Returns the number of bits needed to represent `arc`.
#[allow(clippy::arithmetic_side_effects, reason = "Cannot wrap")]
const fn bitlen(arc: Arc) -> u32 {
    <Arc>::BITS - arc.leading_zeros()
}

/// Returns the number of bytes needed to represent to encode the
/// OID as DER.
#[doc(hidden)]
pub const fn encoded_len(s: &str) -> Result<usize, InvalidOid> {
    let s = s.as_bytes();
    if s.is_empty() {
        return Err(invalid_oid("empty string"));
    }

    let mut n: usize = 0;

    let (arc, mut s) = {
        let (arc1, s) = const_try!(parse_arc_digits(s));
        let Some((&b'.', s)) = s.split_first() else {
            return Err(invalid_oid("missing first dot"));
        };
        let (arc2, s) = const_try!(parse_arc_digits(s));
        let arc = const_try!(combine_roots(arc1, arc2));
        (arc, s)
    };

    n = match n.checked_add(vlq_len(arc)) {
        Some(n) => n,
        None => return Err(invalid_oid("OID is too large")),
    };

    while let Some((&b'.', rest)) = s.split_first() {
        let (arc, rest) = const_try!(parse_arc_digits(rest));
        n = match n.checked_add(vlq_len(arc)) {
            Some(n) => n,
            None => return Err(invalid_oid("OID is too large")),
        };
        s = rest;
    }
    if !s.is_empty() {
        return Err(invalid_oid("invalid character (expected `.`)"));
    }

    Ok(n)
}

#[cfg(test)]
mod tests {
    use serde::{
        de::Visitor,
        ser::{
            self, SerializeMap, SerializeSeq, SerializeStruct, SerializeStructVariant,
            SerializeTuple, SerializeTupleStruct, SerializeTupleVariant,
        },
    };

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
                idx: data.len(),
                buf: {
                    let mut b = [0u8; DEFAULT_MAX_ENCODED_SIZE];
                    b[..data.len()].copy_from_slice(data);
                    b
                },
            };

            let got: OidBuf = result.unwrap();
            assert_eq!(got, want, "#{i}: `{str}` (got = `{got}`)");

            let got: OidBuf = OidBuf::try_from_arcs(arcs).unwrap();
            assert_eq!(got, want, "#{i}: `{arcs:?}` (got = `{got}`)");

            // Check some `PartialEq` impls.
            assert_eq!(got, *data, "#{i}");
            assert_eq!(got, *str, "#{i}");
        }
    }

    #[test]
    fn test_arcs() {
        for (i, (_, valid, str, arcs)) in TESTS.iter().enumerate() {
            if !valid {
                continue;
            }

            let oid: OidBuf = OidBuf::try_parse(str).unwrap();

            // Test `Iterator::next`.
            let got = oid.arcs().collect::<Vec<_>>();
            assert_eq!(&got, arcs, "#{i}: `{str}`");

            // Test `Iterator::fold`.
            let got = oid.arcs().fold(Vec::new(), |mut v, arc| {
                v.push(arc);
                v
            });
            assert_eq!(&got, arcs, "#{i}: `{str}`");

            // Test `DoubleEndedIterator::next_back`.
            {
                let mut want = arcs.to_vec();
                want.reverse();
                let got = oid.arcs().rev().collect::<Vec<_>>();
                assert_eq!(got, want, "#{i}: `{str}`");
            }

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

    #[test]
    fn test_oidbuf_serde() {
        for (i, (_, valid, str, _)) in TESTS.iter().enumerate() {
            if !valid {
                continue;
            }

            let oid: OidBuf = OidBuf::try_parse(str).unwrap_or_else(|err| panic!("#{i}: {err}"));

            #[track_caller]
            fn test<T>(name: &str, i: usize, oid: T, want: DummyData)
            where
                T: fmt::Debug + PartialEq + Serialize + de::DeserializeOwned + ?Sized,
            {
                let got = oid
                    .serialize(&mut DummySer {
                        is_human_readable: matches!(want, DummyData::Str(_)),
                    })
                    .unwrap_or_else(|err| panic!("#{i}: `{name}`: {err}"));
                assert_eq!(got, want, "#{i}: `{name}`");

                let got = T::deserialize(DummyDe { data: &want })
                    .unwrap_or_else(|err| panic!("#{i}: `{name}`: {err}"));
                assert_eq!(got, oid, "#{i}: `{name}`")
            }
            test("str", i, oid, DummyData::Str(str.to_string()));
            test("bytes", i, oid, DummyData::Bytes(oid.as_bytes().to_vec()));
        }
    }

    #[test]
    fn test_oid_serde() {
        for (i, (_, valid, str, _)) in TESTS.iter().enumerate() {
            if !valid {
                continue;
            }

            let oid: OidBuf = OidBuf::try_parse(str).unwrap_or_else(|err| panic!("#{i}: {err}"));

            let want = DummyData::Str(oid.to_string());
            let got = oid
                .serialize(&mut DummySer {
                    is_human_readable: true,
                })
                .unwrap_or_else(|err| panic!("#{i}: {err}"));
            assert_eq!(got, want, "#{i}");

            <&Oid>::deserialize(DummyDe { data: &want })
                .expect_err("should not be able to deserialize str");

            let want = DummyData::Bytes(oid.as_bytes().to_vec());
            let got = oid
                .serialize(&mut DummySer {
                    is_human_readable: false,
                })
                .unwrap_or_else(|err| panic!("#{i}: {err}"));
            assert_eq!(got, want, "#{i}");

            let got = <&Oid>::deserialize(DummyDe { data: &want })
                .unwrap_or_else(|err| panic!("#{i}: {err}"));
            assert_eq!(got, oid, "#{i}")
        }
    }

    #[derive(Debug, PartialEq)]
    enum DummyData {
        Bytes(Vec<u8>),
        Str(String),
    }

    #[derive(Debug, thiserror::Error)]
    #[error("{0}")]
    struct DummyError(String);

    impl ser::Error for DummyError {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            Self(msg.to_string())
        }
    }
    impl de::Error for DummyError {
        fn custom<T: fmt::Display>(msg: T) -> Self {
            Self(msg.to_string())
        }
    }

    #[derive(Debug)]
    struct DummySer {
        is_human_readable: bool,
    }

    impl Serializer for &mut DummySer {
        type Ok = DummyData;
        type Error = DummyError;

        type SerializeSeq = Self;
        type SerializeTuple = Self;
        type SerializeTupleStruct = Self;
        type SerializeTupleVariant = Self;
        type SerializeMap = Self;
        type SerializeStruct = Self;
        type SerializeStructVariant = Self;

        fn is_human_readable(&self) -> bool {
            self.is_human_readable
        }

        fn serialize_bytes(self, v: &[u8]) -> Result<Self::Ok, Self::Error> {
            Ok(DummyData::Bytes(v.to_vec()))
        }

        fn serialize_str(self, v: &str) -> Result<Self::Ok, Self::Error> {
            Ok(DummyData::Str(v.to_string()))
        }

        fn serialize_bool(self, _v: bool) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }

        fn serialize_char(self, _v: char) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }

        fn serialize_i8(self, _v: i8) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_i16(self, _v: i16) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_i32(self, _v: i32) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_i64(self, _v: i64) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_i128(self, _v: i128) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }

        fn serialize_u8(self, _v: u8) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_u16(self, _v: u16) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_u32(self, _v: u32) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_u64(self, _v: u64) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_u128(self, _v: u128) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }

        fn serialize_f32(self, _v: f32) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_f64(self, _v: f64) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }

        fn serialize_map(self, _len: Option<usize>) -> Result<Self::SerializeMap, Self::Error> {
            unimplemented!()
        }

        fn serialize_newtype_struct<T: ?Sized>(
            self,
            _name: &'static str,
            _value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }
        fn serialize_newtype_variant<T: ?Sized>(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            _value: &T,
        ) -> Result<Self::Ok, Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }

        fn serialize_none(self) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_some<T: ?Sized>(self, _value: &T) -> Result<Self::Ok, Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }

        fn serialize_struct(
            self,
            _name: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeStruct, Self::Error> {
            unimplemented!()
        }
        fn serialize_struct_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeStructVariant, Self::Error> {
            unimplemented!()
        }

        fn serialize_seq(self, _len: Option<usize>) -> Result<Self::SerializeSeq, Self::Error> {
            unimplemented!()
        }

        fn serialize_tuple(self, _len: usize) -> Result<Self::SerializeTuple, Self::Error> {
            unimplemented!()
        }
        fn serialize_tuple_struct(
            self,
            _name: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeTupleStruct, Self::Error> {
            unimplemented!()
        }
        fn serialize_tuple_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
            _len: usize,
        ) -> Result<Self::SerializeTupleVariant, Self::Error> {
            unimplemented!()
        }

        fn serialize_unit(self) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_unit_struct(self, _name: &'static str) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
        fn serialize_unit_variant(
            self,
            _name: &'static str,
            _variant_index: u32,
            _variant: &'static str,
        ) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
    }

    impl SerializeMap for &mut DummySer {
        type Ok = DummyData;
        type Error = DummyError;

        fn serialize_key<T: ?Sized>(&mut self, _key: &T) -> Result<(), Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }

        fn serialize_value<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
    }

    impl SerializeSeq for &mut DummySer {
        type Ok = DummyData;
        type Error = DummyError;

        fn serialize_element<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
    }

    impl SerializeStruct for &mut DummySer {
        type Ok = DummyData;
        type Error = DummyError;

        fn serialize_field<T: ?Sized>(
            &mut self,
            _field: &'static str,
            _value: &T,
        ) -> Result<(), Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
    }

    impl SerializeStructVariant for &mut DummySer {
        type Ok = DummyData;
        type Error = DummyError;

        fn serialize_field<T: ?Sized>(
            &mut self,
            _field: &'static str,
            _value: &T,
        ) -> Result<(), Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
    }

    impl SerializeTuple for &mut DummySer {
        type Ok = DummyData;
        type Error = DummyError;

        fn serialize_element<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
    }

    impl SerializeTupleStruct for &mut DummySer {
        type Ok = DummyData;
        type Error = DummyError;

        fn serialize_field<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
    }

    impl SerializeTupleVariant for &mut DummySer {
        type Ok = DummyData;
        type Error = DummyError;

        fn serialize_field<T: ?Sized>(&mut self, _value: &T) -> Result<(), Self::Error>
        where
            T: Serialize,
        {
            unimplemented!()
        }

        fn end(self) -> Result<Self::Ok, Self::Error> {
            unimplemented!()
        }
    }

    #[derive(Debug)]
    struct DummyDe<'de> {
        data: &'de DummyData,
    }

    impl<'de> Deserializer<'de> for DummyDe<'de> {
        type Error = DummyError;

        fn is_human_readable(&self) -> bool {
            matches!(self.data, DummyData::Str(_))
        }

        fn deserialize_bytes<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            match &*self.data {
                DummyData::Bytes(v) => visitor.visit_borrowed_bytes(&v),
                DummyData::Str(_) => Err(<DummyError as de::Error>::custom(
                    "expected bytes, got string",
                )),
            }
        }

        fn deserialize_str<V: Visitor<'de>>(self, visitor: V) -> Result<V::Value, Self::Error> {
            match &*self.data {
                DummyData::Str(s) => visitor.visit_borrowed_str(&s),
                DummyData::Bytes(_) => Err(<DummyError as de::Error>::custom(
                    "expected string, got bytes",
                )),
            }
        }

        fn deserialize_any<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_byte_buf<V: Visitor<'de>>(
            self,
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_string<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_bool<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_char<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_i8<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_i16<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_i32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_i64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_i128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_u8<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_u16<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_u32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_u64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_u128<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_f32<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_f64<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_option<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_unit<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_unit_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_newtype_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_seq<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_tuple<V: Visitor<'de>>(
            self,
            _len: usize,
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_tuple_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            _len: usize,
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_map<V: Visitor<'de>>(self, _visitor: V) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
        fn deserialize_struct<V: Visitor<'de>>(
            self,
            _name: &'static str,
            _fields: &'static [&'static str],
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_enum<V: Visitor<'de>>(
            self,
            _name: &'static str,
            _variants: &'static [&'static str],
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_identifier<V: Visitor<'de>>(
            self,
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }

        fn deserialize_ignored_any<V: Visitor<'de>>(
            self,
            _visitor: V,
        ) -> Result<V::Value, Self::Error> {
            unimplemented!()
        }
    }
}
