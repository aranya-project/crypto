//! Utilities.

mod opaque;

/// Used as `*const Void` or `*mut Void`.
///
/// It's a little more clear than `*const ()` or `*mut ()`.
pub(crate) type Void = ();

/// Casts `ptr` to a shared ref.
///
/// Evalutes to `Result<&T, Error>`.
///
/// # Safety
///
/// - You must uphold Rust's aliasing requirements.
/// - You must ensure that the referent memory is initialized.
#[macro_export]
macro_rules! try_ptr_as_ref {
    (@unsafe $ptr:expr $(,)?) => {
        match $ptr {
            ptr => {
                if ptr.is_null() {
                    Err($crate::error::invalid_arg(
                        stringify!($ptr),
                        "pointer is null",
                    ))
                } else if !ptr.is_aligned() {
                    Err($crate::error::invalid_arg(
                        stringify!($ptr),
                        "pointer is not suitably aligned",
                    ))
                } else {
                    // SAFETY:
                    // - `ptr` is non-null and suitably aligned.
                    // - We have to trust the caller to uphold
                    //   the remaining invariants.
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
/// Evalutes to `Result<&mut T, Error>`.
///
/// # Safety
///
/// - You must uphold Rust's aliasing requirements.
/// - You must ensure that the referent memory is initialized.
#[macro_export]
macro_rules! try_ptr_as_mut {
    (@unsafe $ptr:expr $(,)?) => {
        match $ptr {
            ptr => {
                if ptr.is_null() {
                    Err($crate::error::invalid_arg(
                        stringify!($ptr),
                        "pointer is null",
                    ))
                } else if !ptr.is_aligned() {
                    Err($crate::error::invalid_arg(
                        stringify!($ptr),
                        "pointer is not suitably aligned",
                    ))
                } else {
                    // SAFETY:
                    // - `$ptr` is non-null and suitably aligned.
                    // - We have to trust the caller to uphold the
                    //   remaining invariants.
                    let xref = unsafe { &mut *ptr };
                    Ok(xref)
                }
            }
        }
    };
}
pub(crate) use try_ptr_as_mut;

/// Casts `ptr` to an optional shared ref.
///
/// Evalutes to `Result<Option<&T>, Error>`.
///
/// # Safety
///
/// - You must uphold Rust's aliasing requirements.
/// - You must ensure that, if non-null, the referent memory is
///   initialized.
#[macro_export]
macro_rules! try_ptr_as_opt_ref {
    (@unsafe $ptr:expr $(,)?) => {
        match $ptr {
            ptr => {
                if ptr.is_null() {
                    Ok(None)
                } else if !ptr.is_aligned() {
                    Err($crate::error::invalid_arg(
                        stringify!($ptr),
                        "pointer is not suitably aligned",
                    ))
                } else {
                    // SAFETY:
                    // - `ptr` is non-null and suitably aligned.
                    // - We have to trust the caller to uphold
                    //   the remaining invariants.
                    let xref = unsafe { &*ptr };
                    Ok(Some(xref))
                }
            }
        }
    };
}
pub(crate) use try_ptr_as_opt_ref;

/// Performs checks on the "slice" (ptr, len).
///
/// It returns `Err` if:
///
/// - `ptr` is non-null and not suitably aligned.
/// - `len` is greater than `isize::MAX`.
/// - `ptr` is null and `len` is non-zero.
/// - `ptr` is non-null and `len` is zero.
pub fn pedantic_slice_checks<T>(
    ptr: *const T,
    len: usize,
) -> Result<(*const T, usize), &'static str> {
    if !ptr.is_null() && !ptr.is_aligned() {
        return Err("pointer is not suitably aligned");
    }
    const ISIZE_MAX: usize = isize::MAX as usize;
    if len > ISIZE_MAX {
        return Err("length is greater than `isize::MAX`");
    }
    if ptr.is_null() && len != 0 {
        return Err("pointer is null but length is non-zero");
    }
    if !ptr.is_null() && len == 0 {
        return Err("pointer is non-null but length is zero");
    }
    Ok((ptr, len))
}

/// Performs checks on the "slice" (ptr, len).
///
/// It returns `Err` if:
///
/// - `ptr` is non-null and not suitably aligned.
/// - `len` is greater than `isize::MAX`.
/// - `ptr` is null and `len` is non-zero.
/// - `ptr` is non-null and `len` is zero.
pub fn pedantic_slice_checks_mut<T>(
    ptr: *mut T,
    len: usize,
) -> Result<(*mut T, usize), &'static str> {
    pedantic_slice_checks(ptr.cast_const(), len).map(|(ptr, len)| (ptr.cast_mut(), len))
}

/// Like [`slice::from_raw_parts`][core::slice::from_raw_parts]
/// but with extra checks on `ptr` and `len`.
///
/// It evaluates to `Err` if:
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
#[macro_export]
macro_rules! try_from_raw_parts {
    (@unsafe $ptr:expr, $len:expr $(,)?) => {{
        $crate::util::pedantic_slice_checks($ptr, $len)
            .map(|(ptr, len)| {
                if ptr.is_null() {
                    &[]
                } else {
                    // SAFETY:
                    // - `ptr` is non-null and suitably aligned.
                    // - `len` is less than `isize::MAX`.
                    // - The caller guarantees the remaining
                    //   invariants.
                    unsafe { ::core::slice::from_raw_parts(ptr, len) }
                }
            })
            .map_err(|msg| {
                $crate::error::invalid_arg(concat!(stringify!($ptr), ", ", stringify!($len)), msg)
            })
    }};
}
pub(crate) use try_from_raw_parts;

/// Like [`slice::from_raw_parts_mut`][core::slice::from_raw_parts_mut]
/// but with extra checks on `ptr` and `len`.
///
/// It evaluates to `Err` if:
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
#[macro_export]
macro_rules! try_from_raw_parts_mut {
    (@unsafe $ptr:expr, $len:expr $(,)?) => {{
        $crate::util::pedantic_slice_checks_mut($ptr, $len)
            .map(|(ptr, len)| {
                if ptr.is_null() {
                    &mut []
                } else {
                    // SAFETY:
                    // - `ptr` is non-null and suitably aligned.
                    // - `len` is less than `isize::MAX`.
                    // - The caller guarantees the remaining
                    // invariants.
                    unsafe { ::core::slice::from_raw_parts_mut(ptr, len) }
                }
            })
            .map_err(|msg| {
                $crate::error::invalid_arg(concat!(stringify!($ptr), ", ", stringify!($len)), msg)
            })
    }};
}
pub(crate) use try_from_raw_parts_mut;

/// Like [`try_from_raw_parts`], but evaluates to `Ok(None)`
/// if the resulting slice has a length of zero.
///
/// It evaluates to `Err` if:
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
#[macro_export]
macro_rules! try_from_raw_parts_opt {
    (@unsafe $ptr:expr, $len:expr $(,)?) => {{
        match $crate::util::try_from_raw_parts!(@unsafe $ptr, $len) {
            Ok(&[]) => Ok(None),
            Ok(s) => Ok(Some(s)),
            Err(err) => Err(err),
        }
    }};
}
pub(crate) use try_from_raw_parts_opt;

/// Like [`try_from_raw_parts_mut`], but evaluates to `Ok(None)`
/// if the resulting slice has a length of zero.
///
/// It evaluates to `Err` if:
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
#[macro_export]
macro_rules! try_from_raw_parts_opt_mut {
    (@unsafe $ptr:expr, $len:expr $(,)?) => {{
        match $crate::util::try_from_raw_parts_mut!(@unsafe $ptr, $len) {
            Ok(&mut []) => Ok(None),
            Ok(s) => Ok(Some(s)),
            Err(err) => Err(err),
        }
    }};
}
pub(crate) use try_from_raw_parts_opt_mut;

/// Reports whether the memory regions `x[..x_len]` and
/// `y[..y_len]` overlap at non-corresponding addresses.
pub fn inexact_overlap<T>(x: *const T, x_len: usize, y: *const T, y_len: usize) -> bool {
    if x == y || x.is_null() || x_len == 0 || y.is_null() || y_len == 0 {
        false
    } else {
        any_overlap(x, x_len, y, y_len)
    }
}

/// Reports whether the memory regions `x[..x_len]` and
/// `y[..y_len]` overlap at any address.
#[allow(
    clippy::arithmetic_side_effects,
    reason = "The caller must check the lengths"
)]
pub fn any_overlap<T>(x: *const T, x_len: usize, y: *const T, y_len: usize) -> bool {
    if x.is_null() || x_len == 0 || y.is_null() || y_len == 0 {
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
pub fn less_or_eq(n: usize, v: u64) -> bool {
    u64::try_from(n).is_ok_and(|n| n <= v)
}

#[cfg(test)]
mod tests {
    use core::ptr;

    use super::*;
    use crate::error::{invalid_arg, Error};

    #[test]
    fn test_aliasing() {
        static A: [u8; 100] = [0; 100];
        static B: [u8; 100] = [0; 100];

        // From https://github.com/golang/go/blob/e382bf5b322c9814e910212ebd19907b68606c49/src/crypto/internal/fips140test/alias_test.go#L14
        type AliasingTest<'a> = (
            &'a [u8], // x
            &'a [u8], // y
            bool,     // any overlap
            bool,     // inexact overlap
        );
        let tests: &[AliasingTest<'static>] = &[
            (&A, &B, false, false),
            (&A, &B[..50], false, false),
            (&A[40..50], &A[50..60], false, false),
            (&A[40..50], &A[60..70], false, false),
            (&A[..51], &A[50..], true, true),
            (&A[..], &A[..], true, false),
            (&A[..50], &A[..60], true, false),
            (&A[..], &[], false, false),
            (&[], &[], false, false),
            (&A[..], &A[..0], false, false),
            (&A[..10], &A[..10], true, false),
            (&A[..10], &A[5..10], true, true),
        ];
        for (i, &(x, y, any, inexact)) in tests.iter().enumerate() {
            for (j, (x, y)) in [(x, y), (y, x)].iter().enumerate() {
                let got = any_overlap(x.as_ptr(), x.len(), y.as_ptr(), y.len());
                assert_eq!(got, any, "#{i},{j}: any overlap");

                let got = inexact_overlap(x.as_ptr(), x.len(), y.as_ptr(), y.len());
                assert_eq!(got, inexact, "#{i},{j}: inexact overlap");
            }
        }
    }

    #[test]
    fn test_ptr_as_ref() {
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        #[repr(align(8))]
        struct T(u64);

        let tests: &[(*const T, Result<&T, Error>)] = &[
            (ptr::null(), Err(invalid_arg("*ptr", "pointer is null"))),
            (
                ((&T(42)) as *const T)
                    .cast::<u8>()
                    .wrapping_add(1)
                    .cast::<T>(),
                Err(invalid_arg("*ptr", "pointer is not suitably aligned")),
            ),
            ((&T(42)) as *const T, Ok(&T(42))),
        ];
        for (i, (ptr, want)) in tests.iter().enumerate() {
            let got = try_ptr_as_ref!(@unsafe *ptr);
            assert_eq!(got, *want, "#{i}");
        }
    }

    #[test]
    fn test_ptr_as_mut() {
        #[derive(Copy, Clone, Debug, Eq, PartialEq)]
        #[repr(align(8))]
        struct T(u64);

        let valid = &mut T(42);
        let tests: &[(*mut T, Result<&mut T, Error>)] = &[
            (ptr::null_mut(), Err(invalid_arg("*ptr", "pointer is null"))),
            (
                ((&mut T(42)) as *mut T)
                    .cast::<u8>()
                    .wrapping_add(1)
                    .cast::<T>(),
                Err(invalid_arg("*ptr", "pointer is not suitably aligned")),
            ),
            ((valid) as *mut T, Ok(valid)),
        ];
        for (i, (ptr, want)) in tests.iter().enumerate() {
            let got = try_ptr_as_mut!(@unsafe *ptr);
            assert_eq!(got, *want, "#{i}");
        }
    }
}
