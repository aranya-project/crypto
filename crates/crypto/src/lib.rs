//! Low level Aranya cryptography.
//!
//! # Warning
//!
//! The cryptography in this crate is low-level and can very
//! easily be misused. Unless you explicitly know what you're
//! doing, use [`aranya-crypto`] instead.
//!
//! [`aranya-crypto`]: https://docs.rs/aranya-crypto

#![allow(unstable_name_collisions)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

pub(crate) use spideroak_crypto_derive::AlgId;
pub mod aead;
pub mod asn1;
pub mod bearssl;
pub mod block;
pub mod csprng;
pub mod default;
pub mod ec;
pub mod ed25519;
pub mod hash;
pub mod hex;
pub mod hkdf;
pub mod hmac;
pub mod hpke;
pub mod import;
pub mod kdf;
pub mod kem;
pub mod keys;
pub mod mac;
pub mod oid;
pub mod rust;
pub mod signer;
pub mod test_util;
mod util;
pub mod zeroize;

pub use buggy;
pub use generic_array;
#[doc(hidden)]
pub use spideroak_crypto_derive;
pub use subtle;
pub use typenum;
