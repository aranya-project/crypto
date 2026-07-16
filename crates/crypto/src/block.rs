//! Operations on blocks.

#![forbid(unsafe_code)]

use hybrid_array::{Array, ArraySize};

/// Implemented by types that operate on blocks.
///
/// For example, block ciphers or the Merkle-Damgård
/// construction.
pub trait BlockSize {
    /// The size in bytes of the block.
    type BlockSize: ArraySize;
}

/// A block.
pub type Block<S> = Array<u8, <S as BlockSize>::BlockSize>;
