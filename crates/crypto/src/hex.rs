//! Constant time hexadecimal encoding and decoding.

use core::{fmt, result::Result, str};

use subtle::{Choice, ConditionallySelectable, CtOption};

/// Encodes `T` as hexadecimal in constant time.
#[derive(Copy, Clone)]
pub struct Hex<T>(T);

impl<T> Hex<T> {
    /// Creates a new `Bytes`.
    pub const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T> fmt::Display for Hex<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl<T> fmt::Debug for Hex<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::LowerHex::fmt(self, f)
    }
}

impl<T> fmt::LowerHex for Hex<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ct_write_lower(f, self.0.as_ref())
    }
}

impl<T> fmt::UpperHex for Hex<T>
where
    T: AsRef<[u8]>,
{
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        ct_write_upper(f, self.0.as_ref())
    }
}

/// Implemented by types that can encode themselves as hex in
/// constant time.
pub trait ToHex {
    /// A hexadecimal string.
    type Output: AsRef<[u8]>;

    /// Encodes itself as a hexadecimal string.
    fn to_hex(self) -> Hex<Self::Output>;
}

impl<T> ToHex for T
where
    T: AsRef<[u8]>,
{
    type Output = T;

    fn to_hex(self) -> Hex<Self::Output> {
        Hex::new(self)
    }
}

/// Returned by [`ct_encode`] when `dst` is not twice as long as
/// `src`.
#[derive(Clone, Debug, thiserror::Error)]
#[error("invalid length")]
pub struct InvalidLength(());

/// Encodes `src` into `dst` as hexadecimal in constant time and
/// returns the number of bytes written.
///
/// `dst` must be at least twice as long as `src`.
pub fn ct_encode(dst: &mut [u8], src: &[u8]) -> Result<(), InvalidLength> {
    // The implementation is taken from
    // https://github.com/ericlagergren/subtle/blob/890d697da01053c79157a7fdfbed548317eeb0a6/hex/constant_time.go

    if dst.len() / 2 < src.len() {
        return Err(InvalidLength(()));
    }
    for (v, chunk) in src.iter().zip(dst.chunks_mut(2)) {
        chunk[0] = enc_nibble_lower(v >> 4);
        chunk[1] = enc_nibble_lower(v & 0x0f);
    }
    Ok(())
}

/// Encodes `src` to `dst` as lowercase hexadecimal in constant
/// time and returns the number of bytes written.
pub fn ct_write_lower<W>(dst: &mut W, src: &[u8]) -> Result<(), fmt::Error>
where
    W: fmt::Write,
{
    // The implementation is taken from
    // https://github.com/ericlagergren/subtle/blob/890d697da01053c79157a7fdfbed548317eeb0a6/hex/constant_time.go

    for v in src {
        dst.write_char(enc_nibble_lower(v >> 4) as char)?;
        dst.write_char(enc_nibble_lower(v & 0x0f) as char)?;
    }
    Ok(())
}

/// Encodes `src` to `dst` as uppercase hexadecimal in constant
/// time and returns the number of bytes written.
pub fn ct_write_upper<W>(dst: &mut W, src: &[u8]) -> Result<(), fmt::Error>
where
    W: fmt::Write,
{
    // The implementation is taken from
    // https://github.com/ericlagergren/subtle/blob/890d697da01053c79157a7fdfbed548317eeb0a6/hex/constant_time.go

    for v in src {
        dst.write_char(enc_nibble_upper(v >> 4) as char)?;
        dst.write_char(enc_nibble_upper(v & 0x0f) as char)?;
    }
    Ok(())
}

/// Encodes a nibble as lowercase hexadecimal.
#[inline(always)]
const fn enc_nibble_lower(c: u8) -> u8 {
    let c = c as u16;
    c.wrapping_add(87)
        .wrapping_add((c.wrapping_sub(10) >> 8) & !38) as u8
}

/// Encodes a nibble as uppercase hexadecimal.
#[inline(always)]
const fn enc_nibble_upper(c: u8) -> u8 {
    let c = enc_nibble_lower(c);
    c ^ ((c & 0x40) >> 1)
}

/// Returned by [`ct_decode`] when one of the following occur:
///
/// - `src` is not a multiple of two.
/// - `dst` is not at least half as long as `src`.
/// - `src` contains invalid hexadecimal characters.
#[derive(Clone, Debug, thiserror::Error)]
#[error("invalid hexadecimal encoding: {0}")]
pub struct InvalidEncoding(&'static str);

/// Decodes `src` into `dst` from hexadecimal in constant time
/// and returns the number of bytes written.
///
/// * The length of `src` must be a multiple of two.
/// * `dst` must be half as long (or longer) as `src`.
pub fn ct_decode(dst: &mut [u8], src: &[u8]) -> Result<usize, InvalidEncoding> {
    // The implementation is taken from
    // https://github.com/ericlagergren/subtle/blob/890d697da01053c79157a7fdfbed548317eeb0a6/hex/constant_time.go

    if src.len() % 2 != 0 {
        return Err(InvalidEncoding("`src` length not a multiple of two"));
    }
    if src.len() / 2 > dst.len() {
        return Err(InvalidEncoding(
            "`dst` length not at least half as long as `src`",
        ));
    }

    let mut valid = Choice::from(1u8);
    for (src, dst) in src.chunks_exact(2).zip(dst.iter_mut()) {
        let (hi, hi_ok) = dec_nibble(src[0]);
        let (lo, lo_ok) = dec_nibble(src[1]);

        valid &= hi_ok & lo_ok;

        let val = (hi << 4) | (lo & 0x0f);
        // Out of paranoia, do not update `dst` if `valid` is
        // false.
        *dst = u8::conditional_select(dst, &val, valid);
    }
    if bool::from(valid) {
        Ok(src.len() / 2)
    } else {
        Err(InvalidEncoding(
            "`src` contains invalid hexadecimal characters",
        ))
    }
}

/// Decode a nibble from a hexadecimal character.
#[inline(always)]
fn dec_nibble(c: u8) -> (u8, Choice) {
    let c = u16::from(c);
    // Is c in '0' ... '9'?
    //
    // This is equivalent to
    //
    //    let mut n = c ^ b'0';
    //    if n < 10 {
    //        val = n;
    //    }
    //
    // which is correct because
    //     y^(16*i) < 10 ∀ y ∈ [y, y+10)
    // and '0' == 48.
    let num = c ^ u16::from(b'0');
    // If `num` < 10, subtracting 10 produces the two's
    // complement which flips the bits in [15:4] (which are all
    // zero because `num` < 10) to all one. Shifting by 8 then
    // ensures that bits [7:0] are all set to one, resulting
    // in 0xff.
    //
    // If `num` >= 10, subtracting 10 doesn't set any bits in
    // [15:8] (which are all zero because `c` < 256) and shifting
    // by 8 shifts off any set bits, resulting in 0x00.
    let num_ok = num.wrapping_sub(10) >> 8;

    // Is c in 'a' ... 'f' or 'A' ... 'F'?
    //
    // This is equivalent to
    //
    //    const MASK: u32 = ^(1<<5); // 0b11011111
    //    let a = c&MASK;
    //    if a >= b'A' && a < b'F' {
    //        val = a-55;
    //    }
    //
    // The only difference between each uppercase and
    // lowercase ASCII pair ('a'-'A', 'e'-'E', etc.) is 32,
    // or bit #5. Masking that bit off folds the lowercase
    // letters into uppercase. The the range check should
    // then be obvious. Subtracting 55 converts the
    // hexadecimal character to binary by making 'A' = 10,
    // 'B' = 11, etc.
    let alpha = (c & !32).wrapping_sub(55);
    // If `alpha` is in [10, 15], subtracting 10 results in the
    // correct binary number, less 10. Notably, the bits in
    // [15:4] are all zero.
    //
    // If `alpha` is in [10, 15], subtracting 16 returns the
    // two's complement, flipping the bits in [15:4] (which
    // are all zero because `alpha` <= 15) to one.
    //
    // If `alpha` is in [10, 15], `(alpha-10)^(alpha-16)` sets
    // the bits in [15:4] to one. Otherwise, if `alpha` <= 9 or
    // `alpha` >= 16, both halves of the XOR have the same bits
    // in [15:4], so the XOR sets them to zero.
    //
    // We shift away the irrelevant bits in [3:0], leaving only
    // the interesting bits from the XOR.
    let alpha_ok = (alpha.wrapping_sub(10) ^ alpha.wrapping_sub(16)) >> 8;

    // Bits [3:0] are either 0xf or 0x0.
    let ok = Choice::from(((num_ok ^ alpha_ok) & 1) as u8);

    // For both `num_ok` and `alpha_ok` the bits in [3:0] are
    // either 0xf or 0x0. Therefore, the bits in [3:0] are either
    // `num` or `alpha`. The bits in [7:4] are (as mentioned
    // above), either 0xf or 0x0.
    //
    // Bits [15:4] are irrelevant and should be all zero.
    let result = ((num_ok & num) | (alpha_ok & alpha)) & 0xf;

    (result as u8, ok)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn from_hex_char(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c.wrapping_sub(b'0')),
            b'a'..=b'f' => Some(c.wrapping_sub(b'a').wrapping_add(10)),
            b'A'..=b'F' => Some(c.wrapping_sub(b'A').wrapping_add(10)),
            _ => None,
        }
    }

    fn valid_hex_char(c: u8) -> bool {
        from_hex_char(c).is_some()
    }

    fn must_from_hex_char(c: u8) -> u8 {
        from_hex_char(c).expect("should be a valid hex char")
    }

    /// Test every single byte.
    #[test]
    fn test_encode_lower_exhaustive() {
        for i in 0..256 {
            const TABLE: &[u8] = b"0123456789abcdef";
            let want = [TABLE[i >> 4], TABLE[i & 0x0f]];
            let got = [
                enc_nibble_lower((i as u8) >> 4),
                enc_nibble_lower((i as u8) & 0x0f),
            ];
            assert_eq!(want, got, "#{i}");
        }
    }

    /// Test every single byte.
    #[test]
    fn test_encode_upper_exhaustive() {
        for i in 0..256 {
            const TABLE: &[u8] = b"0123456789ABCDEF";
            let want = [TABLE[i >> 4], TABLE[i & 0x0f]];
            let got = [
                enc_nibble_upper((i as u8) >> 4),
                enc_nibble_upper((i as u8) & 0x0f),
            ];
            assert_eq!(want, got, "#{i}");
        }
    }

    /// Test every single hex character pair (fe, bb, a1, ...).
    #[test]
    fn test_decode_exhaustive() {
        for i in u16::MIN..=u16::MAX {
            let ci = i as u8;
            let cj = (i >> 8) as u8;
            let mut dst = [0u8; 1];
            let src = &[ci, cj];
            let res = ct_decode(&mut dst, src);
            if valid_hex_char(ci) && valid_hex_char(cj) {
                #[allow(clippy::panic)]
                let n = res.unwrap_or_else(|_| {
                    panic!("#{i}: should be able to decode pair '{ci:x}{cj:x}'")
                });
                assert_eq!(n, 1, "#{i}: {ci:x}{cj:x}");
                let want = (must_from_hex_char(ci) << 4) | must_from_hex_char(cj);
                assert_eq!(&dst, &[want], "#{i}: {ci:x}{cj:x}");
            } else {
                res.expect_err(&format!("#{i}: should not have decoded pair '{src:?}'"));
                assert_eq!(&dst, &[0], "#{i}: {src:?}");
            }
        }
    }
}
