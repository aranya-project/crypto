//! Compile-time formatting.

use core::{marker::PhantomData, slice, str};

/// Asserts that `$cond` is true.
#[doc(hidden)]
#[macro_export]
macro_rules! const_assert {
    ($cond:expr $(,)?) => {
        const _: () = {
            match (&$cond) {
                cond => {
                    if !*cond {
                        $crate::const_panic!("assertion failed: ", stringify!($cond));
                    }
                }
            }
        };
    };
    ($cond:expr, $($args:expr),*) => {
        const _: () = {
            match (&$cond) {
                cond => {
                    if !*cond {
                        $crate::const_panic!("assertion failed: ", $($args),+);
                    }
                }
            }
        };
    };
}

/// Like [`panic`], but with const formatting.
#[doc(hidden)]
#[macro_export]
macro_rules! const_panic {
    ($($arg:expr),* $(,)?) => {
        const ARGS: &[&$crate::const_fmt::Arg::<'_>] = &[
            $(
                &(match &$arg {
                    v => $crate::const_fmt::ConstArg::TAG.infer(v).coerce(v),
                }.to_arg())
            ),*
        ];
        const LEN: usize = {
            let mut n = 0;
            let mut i = 0;
            while i < ARGS.len() {
                n += ARGS[i].len();
                i += 1;
            }
            n
        };
        let mut buf = $crate::const_fmt::WriteBuf::<{ LEN }>::new();
        let mut i = 0usize;
        while i < ARGS.len() {
            buf = buf.write(ARGS[i]);
            i = i.wrapping_add(1);
        }
        panic!("{}", buf.as_str());
    };
}

/// Implemented by types that can be used as an argument to
/// [`const_panic`].
pub trait ConstArg {
    /// The underlying type after removing any references.
    type U: ?Sized;
    /// Used to select the correct
    const TAG: Tag<Self, Self::U> = Tag {
        _t: PhantomData,
        _u: PhantomData,
    };
}
macro_rules! impl_const_arg {
    ($($ty:ty)*) => {
        $(
            impl ConstArg for $ty {
                type U = Self;
            }
        )*
    }
}
impl_const_arg! {
    u8 u16 u32 u64 u128 usize
    i8 i16 i32 i64 i128 isize
    str
}

impl<'a, T: ConstArg + ?Sized> ConstArg for &'a T {
    type U = T::U;
}

/// h/t <https://github.com/rodrimati1992/const_panic/>
pub struct Tag<T: ?Sized, U: ?Sized> {
    _t: PhantomData<fn() -> T>,
    _u: PhantomData<fn() -> U>,
}

impl<T: ?Sized, U: ?Sized> Copy for Tag<T, U> {}
impl<T: ?Sized, U: ?Sized> Clone for Tag<T, U> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<T: ?Sized, U: ?Sized> Tag<T, U> {
    /// Called on [`ConstArg::TAG`] to create a `Tag` without
    /// explicitly listing the generic types.
    pub const fn infer(self, _: &T) -> Self {
        self
    }

    /// Auto-dereferences `&T`, `&&T`, etc. and returns a wrapper
    /// for [`Arg`].
    pub const fn coerce(self, x: &U) -> IntoArg<&U> {
        IntoArg(x)
    }
}

/// Converts generic types to [`Arg`]s.
#[derive(Copy, Clone, Debug)]
pub struct IntoArg<T>(T);

impl<'a> IntoArg<&'a str> {
    /// Converts `self` to [`Arg`].
    #[inline(always)]
    pub const fn to_arg(self) -> Arg<'a> {
        Arg::Str(self.0)
    }
}

macro_rules! impl_int_arg_type {
    ($($ty:ty)* => $variant:ident($cast:ty)) => {
        $(
            impl IntoArg<&$ty> {
                /// Converts `self` to [`Arg`].
                #[inline(always)]
                #[allow(clippy::wrong_self_convention)]
                pub const fn to_arg(&self) -> Arg<'static> {
                    Arg::$variant(*self.0 as $cast)
                }
            }
        )*
    }
}
impl_int_arg_type! { u8 u16 u32 u64 u128 usize => Uint(u128) }
impl_int_arg_type! { i8 i16 i32 i64 i128 isize => Int(i128) }

/// A constant argument.
#[derive(Copy, Clone, Debug)]
pub enum Arg<'a> {
    /// An unsigned integer.
    Uint(u128),
    /// A signer integer.
    Int(i128),
    /// A string.
    Str(&'a str),
}

impl Arg<'_> {
    /// Returns the space in bytes needed to encode this arg to
    /// a string.
    #[inline(always)]
    #[allow(clippy::arithmetic_side_effects)]
    pub const fn len(&self) -> usize {
        match self {
            Self::Uint(mut x) => {
                let mut n = 1;
                while x > 0 {
                    n += 1;
                    x /= 10;
                }
                n
            }
            Self::Int(x) => {
                let mut n = Self::Uint(x.unsigned_abs()).len();
                if *x < 0 {
                    n += 1;
                }
                n
            }
            Self::Str(x) => x.len(),
        }
    }
}

/// A buffer for writing.
#[derive(Copy, Clone, Debug)]
pub struct WriteBuf<const N: usize> {
    buf: [u8; N],
    idx: usize,
}

impl<const N: usize> WriteBuf<N> {
    /// Creates a `WriteBuf`.
    #[inline(always)]
    pub const fn new() -> Self {
        Self {
            buf: [0u8; N],
            idx: 0,
        }
    }

    /// Writes `arg` to the buffer.
    #[inline(always)]
    #[must_use]
    pub const fn write(self, arg: &Arg<'_>) -> Self {
        match *arg {
            Arg::Uint(x) => self.write_uint(x),
            Arg::Int(x) => self.write_int(x),
            Arg::Str(x) => self.write_str(x),
        }
    }

    #[inline(always)]
    #[must_use]
    #[allow(clippy::arithmetic_side_effects)]
    const fn write_uint(self, mut x: u128) -> Self {
        let mut tmp = [0u8; 39];
        let mut i = tmp.len() - 1;
        loop {
            tmp[i] = ((x % 10) as u8) + b'0';
            x /= 10;
            if i == 0 || x == 0 {
                break;
            }
            i -= 1;
        }

        // SAFETY:
        // - `i` is always a valid index into `tmp`, so
        //   `add(i)` is always valid.
        // - `tmp.len() - i` is a valid length because it is in
        //   the range [0, tmp.len()].
        let b = unsafe { slice::from_raw_parts(tmp.as_ptr().add(i), tmp.len() - i) };
        // SAFETY: We only wrote valid UTF-8 to `b`.
        let s = unsafe { str::from_utf8_unchecked(b) };
        self.write_str(s)
    }

    #[inline(always)]
    #[must_use]
    #[allow(clippy::arithmetic_side_effects, clippy::cast_sign_loss)]
    const fn write_int(mut self, n: i128) -> Self {
        if n < 0 {
            self = self.write_str("-");
        }
        self.write_uint(n.unsigned_abs())
    }

    #[inline(always)]
    #[must_use]
    #[allow(clippy::arithmetic_side_effects)]
    const fn write_str(mut self, s: &str) -> Self {
        if self.idx >= self.buf.len() {
            return self;
        }
        let s = s.as_bytes();

        let remaining = self.buf.len() - self.idx;
        if remaining < s.len() {
            return self;
        }
        let mut idx = self.idx;
        let mut i = 0;
        while i < s.len() {
            self.buf[idx] = s[i];
            idx += 1;
            i += 1;
        }
        self.idx = idx;
        self
    }

    /// Converts the buffer to a string.
    #[inline(always)]
    pub const fn as_str(&self) -> &str {
        // SAFETY: `self.idx` is always a valid index into
        // `self.buf`.
        let b = unsafe { slice::from_raw_parts(self.buf.as_ptr(), self.idx) };
        // SAFETY: We only write UTF-8 to `self.buf`.
        unsafe { str::from_utf8_unchecked(b) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const_assert_gr_eq!("test", 1i32, 1i32);
    const_assert_gr_eq!("test", 2i32, 1i32);
    const_assert_gr_eq!("test", 1u128, 1u128);
    const_assert_gr_eq!("test", 2u128, 1u128);
}
