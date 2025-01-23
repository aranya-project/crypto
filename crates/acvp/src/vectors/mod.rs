//! Test vectors from [ACVP-Server].
//!
//! See [ACVP] and the [`testing`][crate::testing] module for
//! more information on how to perform the tests.
//!
//! # Example
//!
//! ```rust
//! use acvp::vectors::sha2::{self, Algorithm, Tests};
//!
//! let vectors = sha2::load(Algorithm::Sha2_256).unwrap();
//! for group in vectors.test_groups {
//!     match group.tests {
//!         Tests::Aft(tests) => {
//!             for _test in tests {}
//!         }
//!         Tests::Mct(_tests) => {}
//!         Tests::Ldt(_tests) => {}
//!     }
//! }
//! ```
//!
//! [ACVP]: https://pages.nist.gov/ACVP/
//! [ACVP-Server]: https://github.com/usnistgov/ACVP-Server/tree/203f667c26e10a1be89dfe8da7a54498fde2d848/gen-val/json-files

#![cfg(feature = "vectors")]
#![cfg_attr(docsrs, doc(cfg(feature = "vectors")))]

use alloc::{string::String, vec::Vec};

pub use anyhow::{Error, Result};
use serde::{Deserialize, Serialize};

pub mod hmac;
pub mod sha2;
pub mod sha3;

/// A set of test vectors.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Vectors<G> {
    /// Identifies the test vectors.
    pub vs_id: usize,
    /// The algorithm being tested.
    pub algorithm: String,
    /// The protocol revision.
    pub revision: String,
    /// Are these sample vectors?
    pub is_sample: bool,
    /// Groups of test vectors.
    pub test_groups: Vec<G>,
}

macro_rules! define_tests {
    ($($name:ident => $prefix:literal),* $(,)?) => {
        /// A cryptographic algorithm.
        #[derive(Copy, Clone, Debug, Eq, PartialEq, ::serde::Serialize, ::serde::Deserialize)]
        pub enum Algorithm {
            $(
                #[allow(missing_docs)]
                $name
            ),*
        }

        impl Algorithm {
            pub(crate) const fn name(self) -> &'static str {
                match self {
                    $(
                        Self::$name => concat!("data/", $prefix, ".json")
                    ),*
                }
            }
        }

        impl ::core::fmt::Display for Algorithm {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                self.name().fmt(f)
            }
        }

        static TEST_DATA: &[&str] = &[
            $(
                include_str!(concat!("data/", $prefix, ".json"))
            ),*
        ];

        /// A set of test vectors.
        pub type TestVectors = $crate::vectors::Vectors<TestGroup>;

        /// Loads a the test vectors for a particular algorithm.
        pub fn load(name: Algorithm) -> $crate::vectors::Result<TestVectors> {
            use anyhow::Context;

            let data = TEST_DATA[name as usize];
            let group = serde_json::from_str(data)
                .inspect_err(|_err| {
                    #[cfg(feature = "std")] {
                        println!("### err = {_err:#?}");
                    }
                })
                .with_context(|| ::alloc::format!("unable to deserialize `{name}`"))?;
            Ok(group)
        }
    };
}
pub(super) use define_tests;
