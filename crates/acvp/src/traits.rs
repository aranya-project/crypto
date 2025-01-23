//! Cryptographic algorithm traits.

use core::fmt;

/// A cryptographic hash function.
pub trait Hash: Clone {
    /// The hash digest.
    type Digest: Clone + Default + fmt::Debug + AsRef<[u8]> + PartialEq;

    /// Creates a new instance of the hash.
    fn new() -> Self;

    /// Writes `msg` to the hash.
    fn update(&mut self, msg: &[u8]);

    /// Returns the hash diget.
    fn digest(self) -> Self::Digest;

    /// Computes the digest of `msg`.
    fn hash(msg: &[u8]) -> Self::Digest {
        let mut h = Self::new();
        h.update(msg);
        h.digest()
    }
}
