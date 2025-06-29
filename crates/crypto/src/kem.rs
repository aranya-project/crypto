//! Key Encapsulation Mechanisms.

use core::{array::TryFromSliceError, borrow::Borrow, fmt, marker::PhantomData, result::Result};

use crate::{
    csprng::{Csprng, Random},
    hpke::KemId,
    import::{Import, ImportError},
    kdf::{Kdf, KdfError, Prk},
    keys::{PublicKey, RawSecretBytes, SecretKey},
    signer::PkError,
    zeroize::{zeroize_flat_type, ZeroizeOnDrop},
};

/// An error from a [`Kem`].
#[derive(Debug, Eq, PartialEq)]
pub enum KemError {
    /// The imported secret key is invalid.
    InvalidDecapKeyFormat,
    /// The imported public key is invalid.
    InvalidEncapKeyFormat,
    /// KEM encapsulation failed.
    Encap,
    /// Unable to decapsulate the ephemeral symmetric key.
    Decapsulation,
    /// A DHKEM operation failed.
    DhKem(DhKemError),
    /// A public key could not be imported.
    Import(ImportError),
    /// A public key could not be read.
    PublicKey(PkError),
}

impl fmt::Display for KemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidDecapKeyFormat => write!(f, "invalid secret key data"),
            Self::InvalidEncapKeyFormat => write!(f, "invalid public key data"),
            Self::Encap => write!(f, "encapsulation failed"),
            Self::Decapsulation => write!(f, "unable to decapsulate symmetric key"),
            Self::DhKem(err) => write!(f, "{}", err),
            Self::Import(err) => write!(f, "{}", err),
            Self::PublicKey(err) => write!(f, "{}", err),
        }
    }
}

impl core::error::Error for KemError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::DhKem(err) => Some(err),
            Self::Import(err) => Some(err),
            _ => None,
        }
    }
}

impl From<DhKemError> for KemError {
    fn from(err: DhKemError) -> Self {
        Self::DhKem(err)
    }
}

impl From<ImportError> for KemError {
    fn from(err: ImportError) -> Self {
        Self::Import(err)
    }
}

impl From<PkError> for KemError {
    fn from(err: PkError) -> Self {
        Self::PublicKey(err)
    }
}

/// A Key Encapsulation Mechanism (KEM).
///
/// # Requirements
///
/// The KEM must:
///
/// * Have at least a 128-bit security level.
#[allow(non_snake_case)]
pub trait Kem {
    /// A local secret (private) key used to decapsulate secrets.
    type DecapKey: DecapKey<EncapKey = Self::EncapKey>;
    /// A remote public key used to encapsulate secrets.
    type EncapKey: EncapKey;

    /// An ephemeral, fixed-length symmetric key.
    ///
    /// The key must be at least 128 bits.
    type Secret: RawSecretBytes + ZeroizeOnDrop;

    /// An encapsulated [`Self::Secret`].
    type Encap: Borrow<[u8]> + for<'a> Import<&'a [u8]>;

    /// A randomized algorithm that generates an ephemeral,
    /// fixed-length symmetric key and an 'encapsulation' of that
    /// key that can be decrypted by the holder of the private
    /// half of the public key.
    fn encap<R: Csprng>(
        rng: &mut R,
        pkR: &Self::EncapKey,
    ) -> Result<(Self::Secret, Self::Encap), KemError>;

    /// A deterministic algorithm that generates an ephemeral,
    /// fixed-length symmetric key and an 'encapsulation' of that
    /// key that can be decrypted by the holder of the private
    /// half of the public key.
    ///
    /// # Warning
    ///
    /// The security of this function relies on choosing the
    /// correct value for `skE`. It is a catastrophic error if
    /// you do not ensure all of the following properties:
    ///
    /// - it must be cryptographically secure
    /// - it must never be reused with the same `pkR`
    fn encap_deterministically(
        pkR: &Self::EncapKey,
        skE: Self::DecapKey,
    ) -> Result<(Self::Secret, Self::Encap), KemError>;

    /// A deterministic algorithm that recovers the ephemeral
    /// symmetric key from its encapsulated representation.
    fn decap(enc: &Self::Encap, skR: &Self::DecapKey) -> Result<Self::Secret, KemError>;

    /// An authenticated, randomized algorithm that generates an
    /// ephemeral, fixed-length symmetric key and an
    /// 'encapsulation' of that key that can be decrypted by the
    /// holder of the private half of the public key.
    ///
    /// This function is identical to [`Kem::encap`] except that
    /// it uses `skS` to encode an assurance that the shared
    /// secret was generated by the holder of `skS`.
    fn auth_encap<R: Csprng>(
        rng: &mut R,
        pkR: &Self::EncapKey,
        skS: &Self::DecapKey,
    ) -> Result<(Self::Secret, Self::Encap), KemError>;

    /// An authenticated, deterministic algorithm that generates
    /// an ephemeral, fixed-length symmetric key and an
    /// 'encapsulation' of that key that can be decrypted by the
    /// holder of the private half of the public key.
    ///
    /// This function is identical to
    /// [`Kem::encap_deterministically`] except that it uses
    /// `skS` to encode an assurance that the shared secret was
    /// generated by the holder of `skS`.
    ///
    /// # Warning
    ///
    /// The security of this function relies on choosing the
    /// correct value for `skE`. It is a catastrophic error if
    /// you do not ensure all of the following properties:
    ///
    /// - it must be cryptographically secure
    /// - it must never be reused with the same `pkR`
    fn auth_encap_deterministically(
        pkR: &Self::EncapKey,
        skS: &Self::DecapKey,
        skE: Self::DecapKey,
    ) -> Result<(Self::Secret, Self::Encap), KemError>;

    /// An authenticated, deterministic algorithm that recovers
    /// the ephemeral symmetric key from its encapsulated
    /// representation.
    ///
    /// This function is identical to [`Kem::decap`] except that
    /// it uses `pkS` to ensure that the shared secret was
    /// generated by the holder of the private half of `pkS`.
    fn auth_decap(
        enc: &Self::Encap,
        skR: &Self::DecapKey,
        pkS: &Self::EncapKey,
    ) -> Result<Self::Secret, KemError>;
}

/// An asymmetric private key used to decapsulate keys.
pub trait DecapKey: SecretKey + Random {
    /// The corresponding public key.
    type EncapKey: EncapKey;

    /// Returns the public half of the key.
    fn public(&self) -> Result<Self::EncapKey, PkError>;
}

/// An asymmetric public key used to encapsulate keys.
pub trait EncapKey: PublicKey {}

/// An error from an [`Ecdh`].
#[derive(Debug, Eq, PartialEq)]
pub enum EcdhError {
    /// An unknown or internal error has occurred.
    Other(&'static str),
}

impl fmt::Display for EcdhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Other(msg) => write!(f, "{}", msg),
        }
    }
}

impl core::error::Error for EcdhError {}

/// Elliptic Curve Diffie Hellman key exchange.
///
/// # Requirements
///
/// The algorithm must:
///
/// * Have at least a 128-bit security level
pub trait Ecdh {
    /// The size in bytes of a scalar.
    const SCALAR_SIZE: usize;

    /// An ECDH private key.
    type PrivateKey: DecapKey<EncapKey = Self::PublicKey>;
    /// An ECDH public key.
    ///
    /// For NIST's prime order curves (P-256, P-384, and P-521),
    /// its [`PublicKey::export`] method must return the
    /// uncompressed format described in [SEC] section 2.3.3.
    ///
    /// For X25519 and X448, its [`PublicKey::export`] method
    /// must return the point as-is.
    ///
    /// For all other elliptic curves the format is unspecified.
    ///
    /// [SEC]: https://secg.org/sec1-v2.pdf
    type PublicKey: EncapKey;

    /// The shared secret (Diffie-Hellman value) computed as the
    /// result of the key exchange ([`Self::ecdh`]).
    type SharedSecret: Borrow<[u8]> + ZeroizeOnDrop;

    /// Performs ECDH with the local secret key and remote public
    /// key.
    fn ecdh(
        local: &Self::PrivateKey,
        remote: &Self::PublicKey,
    ) -> Result<Self::SharedSecret, EcdhError>;
}

/// An ECDH shared secret.
pub struct SharedSecret<const N: usize>([u8; N]);

impl<const N: usize> SharedSecret<N> {
    /// Returns a pointer to the shared secret.
    pub fn as_mut_ptr(&mut self) -> *mut u8 {
        self.0.as_mut_ptr()
    }

    /// Returns the length of the shared secret.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> usize {
        self.0.len()
    }
}

impl<const N: usize> Default for SharedSecret<N> {
    fn default() -> Self {
        Self([0u8; N])
    }
}

impl<const N: usize> Borrow<[u8]> for SharedSecret<N> {
    fn borrow(&self) -> &[u8] {
        &self.0
    }
}

impl<const N: usize> TryFrom<&[u8]> for SharedSecret<N> {
    type Error = TryFromSliceError;

    fn try_from(data: &[u8]) -> Result<Self, Self::Error> {
        Ok(Self(data.try_into()?))
    }
}

impl<const N: usize> fmt::Debug for SharedSecret<N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SharedSecret").finish_non_exhaustive()
    }
}

impl<const N: usize> ZeroizeOnDrop for SharedSecret<N> {}
impl<const N: usize> Drop for SharedSecret<N> {
    fn drop(&mut self) {
        // SAFETY:
        // - `self.0` does not contain references or dynamically
        //   sized data.
        // - `self.0` does not have a `Drop` impl.
        // - `self.0` is not used after this function returns.
        // - The bit pattern of all zeros is valid for `self.0`.
        unsafe { zeroize_flat_type(&mut self.0) }
    }
}

/// An error from a DHKEM.
#[derive(Debug, Eq, PartialEq)]
pub enum DhKemError {
    /// An ECDH operation failed.
    Ecdh(EcdhError),
    /// A KDF operation failed.
    Kdf(KdfError),
    /// A DH key could not be imported.
    Import(ImportError),
}

impl fmt::Display for DhKemError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Ecdh(err) => write!(f, "{}", err),
            Self::Kdf(err) => write!(f, "{}", err),
            Self::Import(err) => write!(f, "{}", err),
        }
    }
}

impl core::error::Error for DhKemError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Ecdh(err) => Some(err),
            Self::Kdf(err) => Some(err),
            Self::Import(err) => Some(err),
        }
    }
}

/// Implements [`Kem`] for an [`Ecdh`] and [`Kdf`].
pub struct DhKem<E, F> {
    id: KemId,
    _e: PhantomData<E>,
    _f: PhantomData<F>,
}

#[allow(non_snake_case)]
impl<E: Ecdh, F: Kdf> DhKem<E, F> {
    /// Creates a new [`DhKem`] with the provided [`KemId`].
    pub fn new(id: KemId) -> Self {
        Self {
            id,
            _e: PhantomData,
            _f: PhantomData,
        }
    }

    /// See [`Kem::encap`].
    pub fn encap<R: Csprng>(
        &self,
        rng: &mut R,
        pkR: &E::PublicKey,
    ) -> Result<(Prk<F::PrkSize>, PubKeyData<E>), KemError> {
        let skE = E::PrivateKey::random(rng);
        self.encap_deterministically(pkR, skE)
    }

    /// See [`Kem::encap_deterministically`].
    pub fn encap_deterministically(
        &self,
        pkR: &E::PublicKey,
        skE: E::PrivateKey,
    ) -> Result<(Prk<F::PrkSize>, PubKeyData<E>), KemError> {
        // def Encap(pkR):
        //   skE, pkE = GenerateKeyPair()
        //   dh = DH(skE, pkR)
        //   enc = SerializePublicKey(pkE)
        //
        //   pkRm = SerializePublicKey(pkR)
        //   kem_context = concat(enc, pkRm)
        //
        //   shared_secret = ExtractAndExpand(dh, kem_context)
        //   return shared_secret, enc
        let pkE = skE.public()?;
        let dh = (E::ecdh(&skE, pkR).map_err(DhKemError::Ecdh)?, None);
        let enc = pkE.export();

        let pkRm = pkR.export();

        let shared_secret =
            Self::extract_and_expand(&dh, &enc, &pkRm, None, self.id).map_err(DhKemError::Kdf)?;
        Ok((shared_secret, enc))
    }

    /// See [`Kem::decap`].
    pub fn decap(
        &self,
        enc: &PubKeyData<E>,
        skR: &E::PrivateKey,
    ) -> Result<Prk<F::PrkSize>, KemError> {
        // def Decap(enc, skR):
        //   pkE = DeserializePublicKey(enc)
        //   dh = DH(skR, pkE)
        //
        //   pkRm = SerializePublicKey(pk(skR))
        //   kem_context = concat(enc, pkRm)
        //
        //   shared_secret = ExtractAndExpand(dh, kem_context)
        //   return shared_secret
        let pkE = E::PublicKey::import(enc.borrow())?;
        let dh = (E::ecdh(skR, &pkE).map_err(DhKemError::Ecdh)?, None);

        let pkRm = skR.public()?.export();

        let shared_secret =
            Self::extract_and_expand(&dh, enc, &pkRm, None, self.id).map_err(DhKemError::Kdf)?;
        Ok(shared_secret)
    }

    /// See [`Kem::auth_encap`].
    pub fn auth_encap<R: Csprng>(
        &self,
        rng: &mut R,
        pkR: &E::PublicKey,
        skS: &E::PrivateKey,
    ) -> Result<(Prk<F::PrkSize>, PubKeyData<E>), KemError> {
        let skE = E::PrivateKey::random(rng);
        self.auth_encap_deterministically(pkR, skS, skE)
    }

    /// See [`Kem::auth_encap_deterministically`].
    pub fn auth_encap_deterministically(
        &self,
        pkR: &E::PublicKey,
        skS: &E::PrivateKey,
        skE: E::PrivateKey,
    ) -> Result<(Prk<F::PrkSize>, PubKeyData<E>), KemError> {
        // def AuthEncap(pkR, skS):
        //   skE, pkE = GenerateKeyPair()
        //   dh = concat(DH(skE, pkR), DH(skS, pkR))
        //   enc = SerializePublicKey(pkE)
        //
        //   pkRm = SerializePublicKey(pkR)
        //   pkSm = SerializePublicKey(pk(skS))
        //   kem_context = concat(enc, pkRm, pkSm)
        //
        //   shared_secret = ExtractAndExpand(dh, kem_context)
        //   return shared_secret, enc
        let pkE = skE.public()?;
        let dh = (
            E::ecdh(&skE, pkR).map_err(DhKemError::Ecdh)?,
            Some(E::ecdh(skS, pkR).map_err(DhKemError::Ecdh)?),
        );
        let enc = pkE.export();

        let pkRm = pkR.export();
        let pkSm = skS.public()?.export();

        let shared_secret = Self::extract_and_expand(&dh, &enc, &pkRm, Some(&pkSm), self.id)
            .map_err(DhKemError::Kdf)?;
        Ok((shared_secret, enc))
    }

    /// See [`Kem::auth_decap`].
    pub fn auth_decap(
        &self,
        enc: &PubKeyData<E>,
        skR: &E::PrivateKey,
        pkS: &E::PublicKey,
    ) -> Result<Prk<F::PrkSize>, KemError> {
        // def AuthDecap(enc, skR, pkS):
        //   pkE = DeserializePublicKey(enc)
        //   dh = concat(DH(skR, pkE), DH(skR, pkS))
        //
        //   pkRm = SerializePublicKey(pk(skR))
        //   pkSm = SerializePublicKey(pkS)
        //   kem_context = concat(enc, pkRm, pkSm)
        //
        //   shared_secret = ExtractAndExpand(dh, kem_context)
        //   return shared_secret
        let pkE = E::PublicKey::import(enc.borrow())?;
        let dh = (
            E::ecdh(skR, &pkE).map_err(DhKemError::Ecdh)?,
            Some(E::ecdh(skR, pkS).map_err(DhKemError::Ecdh)?),
        );

        let pkRm = skR.public()?.export();
        let pkSm = pkS.export();

        let shared_secret = Self::extract_and_expand(&dh, enc, &pkRm, Some(&pkSm), self.id)
            .map_err(DhKemError::Kdf)?;
        Ok(shared_secret)
    }

    /// Performs `ExtractAndExpand`.
    fn extract_and_expand(
        dh: &(E::SharedSecret, Option<E::SharedSecret>),
        enc: &PubKeyData<E>,
        pkRm: &PubKeyData<E>,
        pkSm: Option<&PubKeyData<E>>,
        id: KemId,
    ) -> Result<Prk<F::PrkSize>, KdfError> {
        // def LabeledExtract(salt, label, ikm):
        //   ...
        // def LabeledExpand(prk, label, info, L):
        //   ...
        //
        // def ExtractAndExpand(dh, kem_context):
        //   eae_prk = LabeledExtract("", "eae_prk", dh)
        //   shared_secret = LabeledExpand(eae_prk, "shared_secret",
        //                                 kem_context, Nsecret)
        //   return shared_secret
        let mut out = Prk::<F::PrkSize>::default();

        // NB: `labeled_ikm` and `labeled_info` are slices
        // instead of arrays to cut down on stack usage.
        // Additionally, `labeled_info` needs to be `Clone`, and
        // it's significantly cheaper to clone `slice::Iter` that
        // it is to clone `array::IntoIter`.

        //  labeled_ikm = concat("HPKE-v1", suite_id, label, ikm)
        let labeled_ikm: &[&[u8]] = &[
            b"HPKE-v1",
            // suite_id = concat("KEM", I2OSP(kem_id, 2))
            b"KEM",
            &id.to_be_bytes(),
            // label
            b"eae_prk",
            // ikm
            dh.0.borrow(),
            dh.1.as_ref().map_or(&[], |v| v.borrow()),
        ];

        //  labeled_info = concat(I2OSP(L, 2), "HPKE-v1", suite_id,
        //                 label, info)
        let labeled_info: &[&[u8]] = &[
            &(F::PRK_SIZE as u16).to_be_bytes()[..],
            b"HPKE-v1",
            // suite_id = concat("KEM", I2OSP(kem_id, 2))
            b"KEM",
            &id.to_be_bytes(),
            // label
            b"shared_secret",
            // kem_context
            enc.borrow(),
            pkRm.borrow(),
            pkSm.map_or(&[], |v| v.borrow()),
        ];

        F::extract_and_expand_multi(
            out.as_bytes_mut(),
            labeled_ikm.iter().copied(),
            &[],
            labeled_info.iter().copied(),
        )?;
        Ok(out)
    }
}

impl<E, F> fmt::Debug for DhKem<E, F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DhKem").field("id", &self.id).finish()
    }
}

type PubKeyData<T> = <<T as Ecdh>::PublicKey as PublicKey>::Data;

/// Implement [`Kem`] for an [`Ecdh`].
///
/// - `name`: The name of the resulting [`Kem`] impl.
/// - `doc`: A string to use for documentation.
/// - `ecdh`: The [`Ecdh`].
/// - `kdf`: The [`Kdf`][crate::kdf::Kdf] to use.
/// - `sk`: The [`DecapKey`] to use.
/// - `pk`: The [`EncapKey`] to use.
///
/// # Example
///
/// ```rust,ignore
/// use spideroak_crypto::dhkem_impl;
/// dhkem_impl! {
///     DhKemP256HkdfSha256,
///     "DHKEM(P256, HKDF-SHA256)",
///     P256,
///     HkdfSha256,
///     P256PrivateKey,
///     P256PublicKey,
/// }
/// ```
#[macro_export]
macro_rules! dhkem_impl {
    (
        $name:ident,
        $doc:expr,
        $kem_id:expr,
        $ecdh:ty,
        $kdf:ty,
        $sk:ident,
        $pk:ident
        $(, oid = $oid:ident)?
        $(,)?
    ) => {
        #[doc = concat!($doc, ".")]
        #[derive(Debug)]
        pub struct $name;

        impl $name {
            const KEM_ID: $crate::hpke::KemId = $kem_id;
        }

        #[allow(non_snake_case)]
        impl $crate::kem::Kem for $name {
            type DecapKey = $sk;
            type EncapKey = $pk;
            type Secret = $crate::kdf::Prk<<$kdf as $crate::kdf::Kdf>::PrkSize>;
            type Encap = <$pk as $crate::keys::PublicKey>::Data;

            fn encap<R: $crate::csprng::Csprng>(
                rng: &mut R,
                pkR: &Self::EncapKey,
            ) -> ::core::result::Result<(Self::Secret, Self::Encap), $crate::kem::KemError> {
                $crate::kem::DhKem::<$ecdh, $kdf>::new(Self::KEM_ID).encap(rng, pkR)
            }

            fn encap_deterministically(
                pkR: &Self::EncapKey,
                skE: Self::DecapKey,
            ) -> ::core::result::Result<(Self::Secret, Self::Encap), $crate::kem::KemError> {
                $crate::kem::DhKem::<$ecdh, $kdf>::new(Self::KEM_ID)
                    .encap_deterministically(pkR, skE)
            }

            fn decap(
                enc: &Self::Encap,
                skR: &Self::DecapKey,
            ) -> ::core::result::Result<Self::Secret, $crate::kem::KemError> {
                $crate::kem::DhKem::<$ecdh, $kdf>::new(Self::KEM_ID).decap(enc, skR)
            }

            fn auth_encap<R: $crate::csprng::Csprng>(
                rng: &mut R,
                pkR: &Self::EncapKey,
                skS: &Self::DecapKey,
            ) -> ::core::result::Result<(Self::Secret, Self::Encap), $crate::kem::KemError> {
                $crate::kem::DhKem::<$ecdh, $kdf>::new(Self::KEM_ID).auth_encap(rng, pkR, skS)
            }

            fn auth_encap_deterministically(
                pkR: &Self::EncapKey,
                skS: &Self::DecapKey,
                skE: Self::DecapKey,
            ) -> ::core::result::Result<(Self::Secret, Self::Encap), $crate::kem::KemError> {
                $crate::kem::DhKem::<$ecdh, $kdf>::new(Self::KEM_ID)
                    .auth_encap_deterministically(pkR, skS, skE)
            }

            fn auth_decap(
                enc: &Self::Encap,
                skR: &Self::DecapKey,
                pkS: &Self::EncapKey,
            ) -> ::core::result::Result<Self::Secret, $crate::kem::KemError> {
                $crate::kem::DhKem::<$ecdh, $kdf>::new(Self::KEM_ID).auth_decap(enc, skR, pkS)
            }
        }

        impl $crate::hpke::HpkeKem for $name {
            const ID: $crate::hpke::KemId = Self::KEM_ID;
        }

        $(impl $crate::oid::Identified for $name {
            const OID: &'static $crate::oid::Oid = $oid;
        })?
    };
}
pub(crate) use dhkem_impl;
