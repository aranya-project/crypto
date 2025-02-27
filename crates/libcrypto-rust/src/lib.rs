//! `libcrypto` bindings for [`spideroak-crypto`].
//!
//! [`spideroak-crypto`]: https://crates.io/crates/spideroak-crypto

#![cfg_attr(docsrs, feature(doc_cfg))]
#![cfg_attr(not(any(test, doctest, feature = "std")), no_std)]

use spideroak_crypto::{aead::Tls13Aead, rust::Aes256Gcm};

/// ```c
#[doc = include_str!(concat!(env!("OUT_DIR"), "/openssl/__all.h"))]
/// ```
pub fn test() {}

include!(concat!(env!("OUT_DIR"), "/generated.rs"));

spideroak_libcrypto::aeads! {
    EVP_aead_aes_256_gcm => Aes256Gcm,
    EVP_aead_aes_256_gcm_tls13 => Tls13Aead<Aes256Gcm>,
}

cfg_if::cfg_if! {
    if #[cfg(any(test, doctest, feature = "std"))] {
        // OK
    } else {
        #[panic_handler]
        fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
            extern "C" {
                fn abort() -> !;
            }
            // SAFETY: FFI call, no invariants.
            unsafe { abort() }
        }
    }
}

cfg_if::cfg_if! {
    if #[cfg(any(test, doctest, feature = "std"))] {
        // OK
    } else {
        #[cfg(not(cbindgen))]
        #[no_mangle]
        extern "C" fn rust_eh_personality() {}
    }
}

// #[cfg(test)]
// mod tests {
//     use spideroak_libcrypto::test_aead;

//     #[test]
//     fn test_idk() {
//         println!("yy {}", env!("SPIDEROAK_LIBCRYPTO_MAX_AEAD_SIZE"));
//         assert!(false);
//     }

//     test_aead!(all);
// }
