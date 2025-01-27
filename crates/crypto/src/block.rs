//! Operations on blocks.

#![forbid(unsafe_code)]

use generic_array::{ArrayLength, GenericArray};

/// Implemented by types that operate on blocks.
///
/// For example, block ciphers or the Merkle-Damgård
/// construction.
pub trait BlockSize {
    /// The size in bytes of the block.
    type BlockSize: ArrayLength;
}

/// A block.
pub type Block<S> = GenericArray<u8, <S as BlockSize>::BlockSize>;
