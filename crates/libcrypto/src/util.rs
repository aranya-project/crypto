use core::{marker::PhantomData, slice, str};

pub(crate) const ISIZE_MAX: usize = isize::MAX as usize;

/// Casts `ptr` to a shared ref.
///
/// Evalutes to `Result<&T, &'static str>`.
///
/// # Safety
///
/// - You must uphold Rust's aliasing requirements.
/// - You must ensure that the referent memory is initialized.
macro_rules! try_ptr_as_ref {
    (@unsafe $ptr:expr) => {
        match $ptr {
            ptr => {
                if ptr.is_null() {
                    Err(concat!("`", stringify!($ptr), "` is null"))
                } else if !ptr.is_aligned() {
                    Err(concat!("`", stringify!($ptr), "` is not suitably aligned"))
                } else {
                    // SAFETY:
                    // - `ptr` is non-null and suitably aligned.
                    // - We have to trust the caller to uphold the
                    //   remaining invariants.
                    let xref = unsafe { &*ptr };
                    Ok(xref)
                }
            }
        }
    };
}
pub(crate) use try_ptr_as_ref;

/// Casts `ptr` to an exclusive ref.
///
/// Evalutes to `Result<&mut T, &'static str>`.
///
/// # Safety
///
/// - You must uphold Rust's aliasing requirements.
/// - You must ensure that the referent memory is initialized.
macro_rules! try_ptr_as_mut {
    (@unsafe $ptr:ident) => {
        if $ptr.is_null() {
            Err(concat!("`", stringify!($ptr), "` is null"))
        } else if !$ptr.is_aligned() {
            Err(concat!("`", stringify!($ptr), "` is not suitably aligned"))
        } else {
            // SAFETY:
            // - `$ptr` is non-null and suitably aligned.
            // - We have to trust the caller to uphold the
            //   remaining invariants.
            let xref = unsafe { &mut *$ptr };
            Ok(xref)
        }
    };
}
pub(crate) use try_ptr_as_mut;

/// Performs checks on the "slice" (ptr, len).
///
/// Evalutes to `Result<(), &'static str>`.
///
/// It returns `Err` if:
///
/// - `ptr` is non-null and not suitably aligned.
/// - `len` is greater than `isize::MAX`.
/// - `ptr` is null and `len` is non-zero.
/// - `ptr` is non-null and `len` is zero.
macro_rules! pedantic_slice_checks {
    ($ptr:ident, $len:ident) => {
        if !$ptr.is_null() && !$ptr.is_aligned() {
            Err(concat!("`", stringify!($ptr), "` is not suitably aligned"))
        } else if $len > ISIZE_MAX {
            Err(concat!("`", stringify!($len), "` > `isize::MAX`"))
        } else if $ptr.is_null() && $len != 0 {
            Err(concat!(
                "`",
                stringify!($ptr),
                "` is null but `",
                stringify!($len),
                "` is non-zero"
            ))
        } else if !$ptr.is_null() && $len == 0 {
            Err(concat!(
                "`",
                stringify!($ptr),
                "` is non-null but `",
                stringify!($len),
                "` is zero"
            ))
        } else {
            Ok(())
        }
    };
}
pub(crate) use pedantic_slice_checks;

/// Like [`slice::from_raw_parts`][core::slice::from_raw_parts]
/// but with extra checks on `ptr` and `len`.
///
/// It returns `Err` if:
///
/// - `ptr` is not suitably aligned.
/// - `len` is greater than `isize::MAX`.
/// - `ptr` is null and `len` is non-zero.
/// - `ptr` is non-null and `len` is zero.
///
/// # Safety
///
/// - `ptr` must be valid (initialized, etc.) for reads up to
///   `len` bytes.
/// - You must uphold Rust's aliasing requirements.
macro_rules! try_from_raw_parts {
    (@unsafe $ptr:ident, $len:ident ) => {
        $crate::util::pedantic_slice_checks!($ptr, $len).map(|()| {
            if $ptr.is_null() {
                &[]
            } else {
                // SAFETY:
                // - `ptr` is non-null and suitably aligned.
                // - `len` is less than `isize::MAX`.
                // - The caller guarantees the remaining
                //   invariants.
                unsafe { ::core::slice::from_raw_parts($ptr, $len) }
            }
        })
    };
}
pub(crate) use try_from_raw_parts;

/// Like [`slice::from_raw_parts_mut`][core::slice::from_raw_parts_mut]
/// but with extra checks on `ptr` and `len`.
///
/// It returns `Err` if:
///
/// - `ptr` is not suitably aligned.
/// - `len` is greater than `isize::MAX`.
/// - `ptr` is null and `len` is non-zero.
/// - `ptr` is non-null and `len` is zero.
///
/// # Safety
///
/// - `ptr` must be valid (initialized, etc.) for reads up to
///   `len` bytes.
/// - You must uphold Rust's aliasing requirements.
macro_rules! try_from_raw_parts_mut {
    (@unsafe $ptr:ident, $len:ident ) => {
        $crate::util::pedantic_slice_checks!($ptr, $len).map(|()| {
            if $ptr.is_null() {
                &mut []
            } else {
                // SAFETY:
                // - `ptr` is non-null and suitably aligned.
                // - `len` is less than `isize::MAX`.
                // - The caller guarantees the remaining
                //   invariants.
                unsafe { ::core::slice::from_raw_parts_mut($ptr, $len) }
            }
        })
    };
}
pub(crate) use try_from_raw_parts_mut;

/// Reports whether `x` and `y` inexactly overlap.
pub(crate) fn inexact_overlap<T>(x: *const T, x_len: usize, y: *const T, y_len: usize) -> bool {
    if x == y || x.is_null() || x_len == 0 || y.is_null() || y_len == 0 {
        false
    } else {
        any_overlap(x, x_len, y, y_len)
    }
}

/// Reports whether `x` and `y` overlap at all.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "The caller must check the lengths"
)]
pub(crate) fn any_overlap<T>(x: *const T, x_len: usize, y: *const T, y_len: usize) -> bool {
    if x == y || x.is_null() || x_len == 0 || y.is_null() || y_len == 0 {
        return false;
    }

    let size = size_of::<T>();

    let x_start = x as usize;
    let x_end = x_start + ((x_len * size) - 1);

    let y_start = y as usize;
    let y_end = y_start + ((y_len * size) - 1);

    x_start <= y_end && y_start <= x_end
}

/// Reports whether `n <= v`.
#[inline(always)]
pub(crate) fn less_or_eq(n: usize, v: u64) -> bool {
    u64::try_from(n).is_ok_and(|n| n <= v)
}

/// Asserts that `$lhs >= $rhs`.
macro_rules! const_assert_gr_eq {
    ($lhs:expr, $rhs:expr $(,)?) => {
        const _: () = {
            match (&$lhs, &$rhs) {
                (lhs, rhs) => {
                    if !(*lhs >= *rhs) {
                        $crate::util::const_panic!(
                            "got `",
                            $lhs,
                            "`, expected at least `",
                            $rhs,
                            "`"
                        );
                    }
                }
            }
        };
    };
    ($msg:expr, $lhs:expr, $rhs:expr $(,)?) => {
        const _: () = {
            match (&$lhs, &$rhs) {
                (lhs, rhs) => {
                    if !(*lhs >= *rhs) {
                        $crate::util::const_panic!(
                            $msg,
                            "got `",
                            $lhs,
                            "`, expected at least `",
                            $rhs,
                            "`"
                        );
                    }
                }
            }
        };
    };
}
pub(crate) use const_assert_gr_eq;

/// Like [`panic`], but better.
macro_rules! const_panic {
    ($($arg:expr),* $(,)?) => {
        const ARGS: &[&$crate::util::Arg<'_>] = &[
            $(
                &(match &$arg {
                    v => $crate::util::ConstArg::TAG.infer(v).coerce(v),
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
        let mut buf = $crate::util::WriteBuf::<{ LEN }>::new();
        let mut i = 0usize;
        while i < ARGS.len() {
            buf = buf.write(ARGS[i]);
            i = i.wrapping_add(1);
        }
        panic!("{}", buf.as_str());
    };
}
pub(crate) use const_panic;

/// Implemented by types that can be used as an argument to
/// [`const_panic`].
pub(crate) trait ConstArg {
    /// The underlying type after removing any references.
    type U: ?Sized;
    /// Used to select
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

pub(crate) struct Tag<T: ?Sized, U: ?Sized> {
    _t: PhantomData<T>,
    _u: PhantomData<U>,
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
    pub(crate) const fn infer(self, _: &T) -> Self {
        self
    }

    /// Converts
    pub(crate) const fn coerce(self, x: &U) -> IntoArg<&U> {
        IntoArg(x)
    }
}

/// Converts generic types to [`Arg`]s.
#[derive(Copy, Clone, Debug)]
pub(crate) struct IntoArg<T>(T);

impl<'a> IntoArg<&'a str> {
    pub(crate) const fn to_arg(self) -> Arg<'a> {
        Arg::Str(self.0)
    }
}

macro_rules! impl_int_arg_type {
    ($($ty:ty)* => $variant:ident($cast:ty)) => {
        $(
            impl IntoArg<&$ty> {
                #[inline(always)]
                #[allow(clippy::wrong_self_convention)]
                pub(crate) const fn to_arg(&self) -> Arg<'static> {
                    Arg::$variant(*self.0 as $cast)
                }
            }
        )*
    }
}
impl_int_arg_type! { u8 u16 u32 u64 u128 usize => Uint(u128) }
impl_int_arg_type! { i8 i16 i32 i64 i128 isize => Int(i128) }

#[derive(Copy, Clone, Debug)]
pub(crate) enum Arg<'a> {
    Uint(u128),
    Int(i128),
    Str(&'a str),
}

impl Arg<'_> {
    #[inline(always)]
    #[allow(clippy::arithmetic_side_effects)]
    pub(crate) const fn len(&self) -> usize {
        match self {
            Self::Uint(mut x) => {
                let mut n = 1;
                while x > 0 {
                    n += 1;
                    x /= 10;
                }
                n
            }
            Self::Int(mut x) => {
                let mut n = 1;
                if x < 0 {
                    n += 1;
                    x = -x;
                }
                while x > 0 {
                    n += 1;
                    x /= 10;
                }
                n
            }
            Self::Str(x) => x.len(),
        }
    }
}

#[derive(Copy, Clone, Debug)]
pub(crate) struct WriteBuf<const N: usize> {
    buf: [u8; N],
    idx: usize,
}

impl<const N: usize> WriteBuf<N> {
    #[inline(always)]
    pub(crate) const fn new() -> Self {
        Self {
            buf: [0u8; N],
            idx: 0,
        }
    }

    #[inline(always)]
    #[must_use]
    pub(crate) const fn write(self, arg: &Arg<'_>) -> Self {
        match *arg {
            Arg::Uint(x) => self.write_uint(x),
            Arg::Int(x) => self.write_int(x),
            Arg::Str(x) => self.write_str(x),
        }
    }

    #[inline(always)]
    #[must_use]
    #[allow(clippy::arithmetic_side_effects)]
    pub(crate) const fn write_uint(self, mut x: u128) -> Self {
        // TODO(eric): this writes backward
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
    pub(crate) const fn write_int(mut self, n: i128) -> Self {
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

    #[inline(always)]
    pub(crate) const fn as_str(&self) -> &str {
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

    const _: () = {
        let fmt: ::const_panic::FmtArg = ::const_panic::FmtArg::DEBUG;
        let idk1 = &match &"test" {
            reff => ::const_panic::__::PanicFmt::PROOF.infer(reff),
        };
        let _ = idk1.coerce(&&&&&"hi");
        let idk2 = &match &"test" {
            reff => ::const_panic::__::PanicFmt::PROOF.infer(reff).coerce(reff),
        };
        let idk3 = &match &"test" {
            reff => ::const_panic::StdWrapper(reff),
        };
        ::const_panic::StdWrapper(
            &match &"test" {
                reff => ::const_panic::__::PanicFmt::PROOF.infer(reff).coerce(reff),
            }
            .to_panicvals(fmt.set_display().set_alternate(false)),
        )
        .deref_panic_vals();
    };

    // const_assert_gr_eq!(1, 1);
    const_assert_gr_eq!("test", 1, 1i32);
    // const_assert_gr_eq!("test", 42u64, 12u64);
}
