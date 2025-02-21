//! Testing utilities.

#![cfg(feature = "testing")]
#![cfg_attr(docsrs, doc(cfg(feature = "testing")))]

use core::ptr;

use crate::{
    EVP_AEAD_CTX_cleanup, EVP_AEAD_CTX_init, EVP_AEAD_CTX_open, EVP_AEAD_CTX_seal,
    EVP_AEAD_key_length, EVP_AEAD_max_overhead, EVP_AEAD_nonce_length, EVP_AEAD, EVP_AEAD_CTX,
};

/// Tests AEADs.
#[macro_export]
macro_rules! test_aead {
    (all) => {
        $crate::test_aead!(EVP_aead_aes_128_gcm, test_aes_128_gcm);
        $crate::test_aead!(EVP_aead_aes_256_gcm, test_aes_256_gcm);
        $crate::test_aead!(EVP_aead_aes_128_gcm_tls13, test_aes_128_gcm_tls13);
        $crate::test_aead!(EVP_aead_aes_256_gcm_tls13, test_aes_256_gcm_tls13);
        $crate::test_aead!(EVP_aead_chacha20_poly1305, test_chacha20_poly1305);
    };
    ($aead:ident, $test:ident) => {
        #[test]
        pub fn $test() {
            assert_eq!($crate::$aead(), $crate::$aead());

            let ptr = $crate::$aead();
            if ptr.is_null() {
                return;
            }
            // SAFETY: `ptr` is non-null and (should be) suitably
            // aligned.
            let aead = unsafe { &*ptr };
            $crate::testing::test_aead(aead)
        }
    };
}

/// Tests an AEAD.
pub fn test_aead(aead: &EVP_AEAD) {
    let mut ctx = EVP_AEAD_CTX::default();
    let key = vec![0; EVP_AEAD_key_length(aead)];
    let ret = unsafe {
        EVP_AEAD_CTX_init(
            ptr::addr_of_mut!(ctx).cast(),
            aead,
            key.as_ptr(),
            key.len(),
            0,
            ptr::null(),
        )
    };
    assert_eq!(ret, 1);

    let pt = vec![b'A'; 512];
    let mut out = vec![0; pt.len() + EVP_AEAD_max_overhead(aead)];
    let mut out_len = 0;
    let nonce = vec![0; EVP_AEAD_nonce_length(aead)];
    let ad = b"some additional data...";
    let ret = unsafe {
        EVP_AEAD_CTX_seal(
            &ctx,
            out.as_mut_ptr(),
            ptr::addr_of_mut!(out_len).cast(),
            out.len(),
            nonce.as_ptr(),
            nonce.len(),
            pt.as_ptr(),
            pt.len(),
            ad.as_ptr(),
            ad.len(),
        )
    };
    assert_eq!(ret, 1);
    assert_eq!(out_len, out.len());

    let ct = out.clone();
    let mut out = vec![0; pt.len()];
    let mut out_len = 0;
    let ret = unsafe {
        EVP_AEAD_CTX_open(
            &ctx,
            out.as_mut_ptr(),
            ptr::addr_of_mut!(out_len).cast(),
            out.len(),
            nonce.as_ptr(),
            nonce.len(),
            ct.as_ptr(),
            ct.len(),
            ad.as_ptr(),
            ad.len(),
        )
    };
    assert_eq!(ret, 1);
    assert_eq!(out_len, out.len());
    assert_eq!(out, pt);

    unsafe { EVP_AEAD_CTX_cleanup(&mut ctx) }
}
