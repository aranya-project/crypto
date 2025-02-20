//! TODO

#![cfg_attr(docsrs, feature(doc_cfg))]
//#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

use spideroak_crypto::{aead::Tls13Aead, rust::Aes256Gcm};
use spideroak_libcrypto::impl_aead;

impl_aead!(AES_256_GCM, Aes256Gcm);
impl_aead!(AES_256_GCM, Aes256Gcm);
impl_aead!(AES_256_GCM_TLS13, Tls13Aead<Aes256Gcm>);

#[cfg(test)]
mod tests {
    use spideroak_libcrypto::test_aead;

    test_aead!(all);
}
