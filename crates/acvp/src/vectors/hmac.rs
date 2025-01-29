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

use crate::{
    traits::Mac,
    util::{dprintln, ensure_eq},
};

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

/// Tests `M` against the HMAC test vectors.
pub fn test<M: Mac>(vectors: &TestVectors) -> anyhow::Result<()> {
    use crate::vectors::hmac::{Aft, Tests};

    for group in &vectors.test_groups {
        let key_len_bytes = (group.key_len + 7) / 8;
        if M::min_key_len().is_some_and(|min| key_len_bytes < min) {
            dprintln!(
                "skipping group #{tg_id}; key size too small: {key_len_bytes} < {min:?}",
                tg_id = group.tg_id,
                min = M::min_key_len(),
            );
            continue;
        }
        match &group.tests {
            Tests::Aft(tests) => {
                for Aft {
                    tc_id,
                    key,
                    msg,
                    mac,
                } in tests.iter()
                {
                    let tag = M::try_mac(key, msg)
                        .with_context(|| format!("#{tc_id}: `try_mac` failed"))?;
                    let mac_len_bytes = (group.mac_len + 7) / 8;
                    let got = tag.as_ref().get(..mac_len_bytes).with_context(|| {
                        ::alloc::format!(
                            "#{tc_id}: tag is too short: `{} < {mac_len_bytes}` (mac = `{:?}`)",
                            tag.as_ref().len(),
                            tag.as_ref(),
                        )
                    })?;
                    ensure_eq!(got, mac, "#{tc_id}");

                    // TODO(eric): test using `ConstantTimeEq`.
                }
            }
        }
    }

    Ok(())
}
