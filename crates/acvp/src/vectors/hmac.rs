//! HMAC test vectors.
//!
//! See [draft-ietf-acvp-sub-sha] for more information.
//!
//! [draft-ietf-acvp-sub-sha]: https://pages.nist.gov/ACVP/draft-celi-acvp-sha.html

#![cfg(feature = "sha2")]
#![cfg_attr(docsrs, doc(cfg(feature = "sha2")))]

use alloc::{format, vec::Vec};

use anyhow::Context;
use serde::{Deserialize, Serialize};

use crate::util::ensure_eq;

super::define_tests! {
    HmacSha2_256 => "hmac_sha2_256",
    HmacSha2_384 => "hmac_sha2_384",
    HmacSha2_512 => "hmac_sha2_512",
    HmacSha2_512_256 => "hmac_sha2_512_256",

    HmacSha3_256 => "hmac_sha3_256",
    HmacSha3_384 => "hmac_sha3_384",
    HmacSha3_512 => "hmac_sha3_512",
}

/// A group of test vectors.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TestGroup {
    /// Identifies the group.
    pub tg_id: usize,
    /// The length in bits of the key.
    pub key_len: usize,
    /// The length in bits of the message.
    pub msg_len: usize,
    /// The length in bits of the MAC.
    pub mac_len: usize,
    /// The test vectors.
    #[serde(flatten)]
    pub tests: Tests,
}

/// HMAC tests.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
#[serde(tag = "testType", content = "tests")]
pub enum Tests {
    /// Algorithm functional tests.
    Aft(Vec<Aft>),
}

/// A HMAC algorithm functional test (AFT).
///
/// See [draft-ietf-acvp-sub-mac] section 6.
///
/// [draft-ietf-acvp-sub-mac]: https://pages.nist.gov/ACVP/draft-fussell-acvp-mac.html
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Aft {
    /// Identifies the test case.
    pub tc_id: usize,
    /// The key to initialize HMAC with.
    #[serde(with = "hex::serde")]
    pub key: Vec<u8>,
    /// The message to compute the hash of.
    #[serde(with = "hex::serde")]
    pub msg: Vec<u8>,
    /// The expected digest.
    #[serde(with = "hex::serde")]
    pub mac: Vec<u8>,
}

/// Tests `F` against the HMAC test vectors.
///
/// The first argument to `F` is the key, the second is the
/// message.
pub fn test<F, T>(vectors: &TestVectors, f: F) -> anyhow::Result<()>
where
    F: Fn(&[u8], &[u8]) -> anyhow::Result<T>,
    T: AsRef<[u8]>,
{
    use crate::vectors::hmac::{Aft, Tests};

    for group in &vectors.test_groups {
        match &group.tests {
            Tests::Aft(tests) => {
                for Aft {
                    tc_id,
                    key,
                    msg,
                    mac,
                } in tests.iter()
                {
                    let got = f(key, msg).with_context(|| format!("#{tc_id}: `F` failed"))?;
                    ensure_eq!(got.as_ref(), mac, "#{tc_id}");

                    // TODO(eric): test using `ConstantTimeEq`.
                }
            }
        }
    }

    Ok(())
}
