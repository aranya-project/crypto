use s2n_quic_core::crypto::{
    self, packet_protection::Error, scatter::Buffer, tls, CryptoSuite, HeaderProtectionMask,
};
use spideroak_crypto::{
    aead::{Aead, IndCca2},
    kdf::Kdf,
    rust,
    typenum::{Prod, U12, U16, U255, U32, U48},
};

#[derive(Debug)]
pub enum CipherSuite<A> {
    TlsAes256GcmSha384(TlsAes256GcmSha384<A>),
}

impl<A> CryptoSuite for CipherSuite<A> {
    type HandshakeKey = HandshakeKey;
    type HandshakeHeaderKey = HandshakeHeaderKey;
    type InitialKey = InitialKey;
    type InitialHeaderKey = InitialHeaderKey;
    type OneRttKey = OneRttKey;
    type OneRttHeaderKey = OneRttHeaderKey;
    type ZeroRttKey = ZeroRttKey;
    type ZeroRttHeaderKey = ZeroRttHeaderKey;
    type RetryKey = RetryKey;
}

macro_rules! impl_cipher_suite {
    (
        $name:ident,
        $name_caps:ident,
        $aead:ident,
        $hkdf:ident,
        confidentiality = $confidentiality:expr,
        integrity = $integrity:expr,
    ) => {
        #[doc = stringify!($name_caps)]
        #[derive(Debug)]
        pub struct $name<A> {
            aead: A,
            /// The nonce mask.
            ///
            /// NB: All three cipher suites use 12-byte nonces.
            mask: [u8; 12],
        }

        impl<A> $name<A> {
            fn nonce(&self, seq: u64) -> [u8; 12] {
                let mut nonce = self.mask;
                for (dst, src) in nonce.split_at_mut(4).1.iter_mut().zip(seq.to_be_bytes()) {
                    *dst ^= src;
                }
                nonce
            }
        }

        impl<A: $aead + Send> crypto::Key for $name<A> {
            #[inline]
            fn decrypt(
                &self,
                packet_number: u64,
                header: &[u8],
                payload: &mut [u8],
            ) -> Result<(), Error> {
                let nonce = self.nonce(packet_number);
                let (data, tag) = payload.split_at_mut(payload.len() - <A as Aead>::OVERHEAD);
                self.aead
                    .open_in_place(&nonce, data, tag, header)
                    .map_err(|_| Error::DECRYPT_ERROR)
            }

            #[inline]
            fn encrypt(
                &mut self,
                packet_number: u64,
                header: &[u8],
                payload: &mut Buffer<'_>,
            ) -> Result<(), Error> {
                let nonce = self.nonce(packet_number);
                let (data, tag) = payload.flatten().split_mut();
                self.aead
                    .seal_in_place(&nonce, data, tag, header)
                    .map_err(|_| Error::INTERNAL_ERROR)
            }

            #[inline]
            fn tag_len(&self) -> usize {
                A::OVERHEAD
            }

            #[inline]
            fn aead_confidentiality_limit(&self) -> u64 {
                $confidentiality
            }

            #[inline]
            fn aead_integrity_limit(&self) -> u64 {
                $integrity
            }

            #[inline]
            fn cipher_suite(&self) -> tls::CipherSuite {
                tls::CipherSuite::$name_caps
            }
        }
    };
}

impl_cipher_suite! {
    TlsAes256GcmSha384,
    TLS_AES_256_GCM_SHA384,
    Aes256Gcm,
    HkdfSha384,
    confidentiality = 2 << 23, // 2^32
    integrity = 2 << 52, // 2^52
}

/// A marker trait that this [`Aead`] implements AES-128-GCM.
pub trait Aes128Gcm: Aead<KeySize = U16, NonceSize = U12, Overhead = U16> + IndCca2 {}

/// A marker trait that this [`Aead`] implements AES-256-GCM.
pub trait Aes256Gcm: Aead<KeySize = U32, NonceSize = U12, Overhead = U16> + IndCca2 {}

impl Aes256Gcm for rust::Aes256Gcm {}

/// A marker trait that this [`Aead`] implements
/// ChaCha20Poly1305.
pub trait ChaCha20Poly135: Aead<KeySize = U32, NonceSize = U12, Overhead = U16> + IndCca2 {}

/// A marker trait that this [`Kdf`] implements HKDF-SHA-256.
pub trait HkdfSha256<MaxOutput = Prod<U255, U32>, PrkSize = U32>: Kdf {}

/// A marker trait that this [`Kdf`] implements HKDF-SHA-256.
pub trait HkdfSha384<MaxOutput = Prod<U255, U48>, PrkSize = U48>: Kdf {}

macro_rules! impl_key {
    ($name:ident) => {
        #[derive(Debug)]
        pub struct $name {
            seal: CipherSuite,
            open: CipherSuite,
        }

        impl crypto::$name for $name {}

        impl crypto::Key for $name {
            #[inline]
            fn decrypt(
                &self,
                packet_number: u64,
                header: &[u8],
                payload: &mut [u8],
            ) -> Result<(), Error> {
                self.open.decrypt(packet_number, header, payload)
            }

            #[inline]
            fn encrypt(
                &mut self,
                packet_number: u64,
                header: &[u8],
                payload: &mut Buffer<'_>,
            ) -> Result<(), Error> {
                self.open.open(packet_number, header, payload)
            }

            #[inline]
            fn tag_len(&self) -> usize {
                self.seal.tag_len()
            }

            #[inline]
            fn aead_confidentiality_limit(&self) -> u64 {
                self.seal.aead_confidentiality_limit()
            }

            #[inline]
            fn aead_integrity_limit(&self) -> u64 {
                self.open.aead_integrity_limit()
            }

            #[inline]
            fn cipher_suite(&self) -> tls::CipherSuite {
                self.open.cipher_suite()
            }
        }
    };
}

macro_rules! impl_header_key {
    ($name:ident) => {
        pub struct $name {
            seal: HeaderKey,
            open: HeaderKey,
        }

        impl crypto::$name for $name {}

        impl crypto::HeaderKey for $name {
            #[inline]
            fn opening_header_protection_mask(&self, sample: &[u8]) -> HeaderProtectionMask {
                self.open.header_protection_mask(sample)
            }

            #[inline]
            fn opening_sample_len(&self) -> usize {
                self.open.opening_sample_len()
            }

            #[inline]
            fn sealing_header_protection_mask(&self, sample: &[u8]) -> HeaderProtectionMask {
                self.seal.header_protection_mask(sample)
            }

            #[inline]
            fn sealing_sample_len(&self) -> usize {
                self.seal.sample_len()
            }
        }
    };
}

impl_key!(HandshakeKey);

impl_header_key!(HandshakeHeaderKey);

/// TODO
pub struct InitialKey {}

// impl crypto::Key for InitialKey {}
// impl crypto::InitialKey for InitialKey {}

/// TODO
pub struct InitialHeaderKey {}

/// TODO
pub struct OneRttKey {}

/// TODO
pub struct OneRttHeaderKey {}

/// TODO
pub struct ZeroRttKey {}

/// TODO
pub struct ZeroRttHeaderKey {}

/// TODO
pub struct RetryKey {}
