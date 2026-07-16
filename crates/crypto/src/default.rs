//! Default implementations.

use cfg_if::cfg_if;

use crate::csprng::Csprng;

/// The default CSPRNG.
///
/// By default, it uses the system CSPRNG (see the `getrandom`
/// feature). The `trng` flag can be set to use a user space
/// CSPRNG seeded by a system TRNG instead.
///
/// If neither are available, `Rng` invokes the following
/// routine:
///
/// ```
/// extern "C" {
///     /// Reads `len` cryptographically secure bytes into
///     /// `dst`.
///     fn crypto_getrandom(dst: *mut u8, len: usize);
/// }
/// ```
///
/// In general, `Rng` should be used directly instead of being
/// created with [`Rng::new`]. For example:
///
/// ```
/// # use spideroak_crypto::csprng::Csprng;
/// use spideroak_crypto::default::Rng;
///
/// fn foo<R: Csprng>(_rng: R) {}
///
/// foo(Rng);
/// ```
#[derive(Copy, Clone, Debug, Default)]
pub struct Rng;

impl Rng {
    /// Creates a default CSPRNG.
    ///
    /// In general, `Rng` should be used directly instead of
    /// being created with this method.
    #[inline]
    pub const fn new() -> Self {
        Self
    }
}

impl Csprng for Rng {
    fn fill_bytes(&self, dst: &mut [u8]) {
        cfg_if! {
            if #[cfg(feature = "trng")] {
                crate::csprng::trng::thread_rng().fill_bytes(dst)
            } else if #[cfg(feature = "getrandom")] {
                getrandom::fill(dst).expect("should not fail")
            } else {
                extern "C" {
                    fn crypto_getrandom(dst: *mut u8, len: usize);
                }
                // SAFETY: FFI call, no invariants.
                unsafe {
                    crypto_getrandom(dst.as_mut_ptr(), dst.len())
                }
            }
        }
    }
}

#[cfg(feature = "rand_compat")]
impl rand_core::TryCryptoRng for Rng {}

#[cfg(feature = "rand_compat")]
impl rand_core::TryRng for Rng {
    type Error = core::convert::Infallible;

    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        rand_core::utils::next_word_via_fill(self)
    }

    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        rand_core::utils::next_word_via_fill(self)
    }

    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        Csprng::fill_bytes(self, dst);
        Ok(())
    }
}
