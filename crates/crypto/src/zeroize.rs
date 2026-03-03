//! Securely zero memory.

#![forbid(unsafe_code)]

pub use zeroize::{zeroize_flat_type, Zeroize, ZeroizeOnDrop, Zeroizing};

pub(crate) const fn is_zeroize_on_drop<T>(_: &T)
where
    T: ZeroizeOnDrop,
{
}
