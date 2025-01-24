//! SHA-2 test vectors.
//!
//! See [draft-ietf-acvp-sub-sha] for more information.
//!
//! [draft-ietf-acvp-sub-sha]: https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html

#![cfg(feature = "sha2")]
#![cfg_attr(docsrs, doc(cfg(feature = "sha2")))]

use alloc::{format, string::String, vec::Vec};
use core::fmt;

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::{traits::Hash, util::ensure_eq};

super::define_tests! {
    Sha2_256 => "sha2_256",
    Sha2_512 => "sha2_512",
    Sha2_512_256 => "sha2_512_256",
}

/// A group of test vectors.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestGroup {
    /// Identifies the group.
    pub tg_id: usize,
    /// The SHA-2 function name.
    pub function: String,
    /// The size in bits of the digest.
    pub digest_size: String,
    /// MCT version.
    pub mct_version: MctVersion,
    /// The test vectors.
    #[serde(flatten)]
    pub tests: Tests,
}

/// The version of a monte carlo test.
///
/// See [`Mct`] for more information.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MctVersion {
    /// Standard.
    Standard,
    /// Alternate.
    Alternate,
}

impl MctVersion {
    /// Shorthand for `self == MctVersion::Standard`.
    pub const fn is_std(self) -> bool {
        matches!(self, Self::Standard)
    }

    /// Shorthand for `self == MctVersion::Alternate`.
    pub const fn is_alt(self) -> bool {
        matches!(self, Self::Alternate)
    }
}

impl fmt::Display for MctVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Standard => write!(f, "standard"),
            Self::Alternate => write!(f, "alternate"),
        }
    }
}

/// SHA-2 tests.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(tag = "testType", content = "tests")]
pub enum Tests {
    /// Algorithm functional tests.
    Aft(Vec<Aft>),
    /// Monte carlo tests.
    Mct(Vec<Mct>),
    /// Large data tests.
    Ldt(Vec<Ldt>),
}

/// A SHA-2 algorithm functional test (AFT).
///
/// See [draft-ietf-acvp-sub-sha] section 6.
///
/// [draft-ietf-acvp-sub-sha]: https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Aft {
    /// Identifies the test case.
    pub tc_id: usize,
    /// The message to compute the hash of.
    #[serde(with = "hex::serde")]
    pub msg: Vec<u8>,
    /// The length in bits of `msg`.
    pub len: usize,
    /// The expected digest.
    #[serde(with = "hex::serde")]
    pub md: Vec<u8>,
}

/// A SHA-2 monte carlo test (MCT).
///
/// See [draft-ietf-acvp-sub-sha] section 6.
///
/// [draft-ietf-acvp-sub-sha]: https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Mct {
    /// Identifies the test case.
    pub tc_id: usize,
    /// The initial message (seed).
    #[serde(with = "hex::serde")]
    pub msg: Vec<u8>,
    /// The length in bits of `msg`.
    pub len: usize,
    /// Per-iteration results.
    pub results_array: Vec<MctResult>,
}

/// The result of a monte carlo test iteration.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MctResult {
    /// The expected digest.
    #[serde(with = "hex::serde")]
    pub md: Vec<u8>,
    /// The size in bits of `md`.
    pub out_len: usize,
}

/// A SHA-2 large data test (LDT).
///
/// See [draft-ietf-acvp-sub-sha] section 6.
///
/// [draft-ietf-acvp-sub-sha]: https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ldt {
    /// Identifies the test case.
    pub tc_id: usize,
    /// Always zero.
    pub len: usize,
    /// The expected digest.
    #[serde(with = "hex::serde")]
    pub md: Vec<u8>,
    /// Large message parameters.
    pub large_msg: LargeMsg,
}

/// For large message tests.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LargeMsg {
    /// Data that is expanded into the full message.
    #[serde(with = "hex::serde")]
    pub content: Vec<u8>,
    /// The length of `content` in bits.
    pub content_length: usize,
    /// The total number of bits written to the hash.
    pub full_length: usize,
    /// The technique for expanding `content` into the full
    /// message.
    pub expansion_technique: ExpansionTechnique,
}

/// The technique for expanding `content` into the full message.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExpansionTechnique {
    /// Appends the number of bits specified in `content_length`
    /// until a string of exactly `full_length` has been reached.
    Repeating,
}

/// Tests `H` against the SHA-2 test vectors.
pub fn test<H: Hash>(vectors: &TestVectors) -> anyhow::Result<()> {
    use crate::testing::sha2::{LargeDataTest, MctIter};

    let mut ldt = LargeDataTest::new();

    for group in &vectors.test_groups {
        match &group.tests {
            Tests::Aft(tests) => {
                for Aft {
                    tc_id,
                    msg,
                    md,
                    len,
                } in tests.iter()
                {
                    ensure_eq!(
                        len % 8,
                        0,
                        "`len` must be padded to full bytes, got `{len}`"
                    );
                    let got = <H>::hash(msg);
                    ensure_eq!(got.as_ref(), md, "#{tc_id}");
                }
            }
            Tests::Mct(tests) => {
                for Mct {
                    tc_id,
                    msg,
                    results_array,
                    ..
                } in tests.iter()
                {
                    let mct = MctIter::<H>::new(msg, group.mct_version.is_alt());
                    for (j, (got, want)) in mct.zip(results_array).enumerate() {
                        ensure_eq!(
                            got.as_ref(),
                            want.md,
                            "#{tc_id}: j={j} vers={}",
                            group.mct_version
                        );
                    }
                }
            }
            Tests::Ldt(tests) => {
                for Ldt {
                    tc_id,
                    md,
                    large_msg,
                    ..
                } in tests.iter()
                {
                    let total_bytes = large_msg.full_length / 8;
                    let got = ldt
                        .run::<H>(&large_msg.content, total_bytes)
                        .with_context(|| format!("{tc_id}"))?;
                    ensure_eq!(got.as_ref(), md, "#{tc_id}");
                }
            }
        }
    }

    Ok(())
}
