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
