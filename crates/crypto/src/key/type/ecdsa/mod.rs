use rand::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::{
    key::{metadata::infer_algorithm, KeyGenerationFailed, KeyMetadata},
    AlgorithmInstance, Error, Options, PublicKey, SignatureVerification, Signer, SigningKey,
    Verifier, VerifyingKey,
};

use super::KeyType;

#[cfg(feature = "secp256k1")]
pub mod k256;

#[cfg(feature = "secp256r1")]
pub mod p256;

#[cfg(feature = "secp384r1")]
pub mod p384;

/// Key type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum EcdsaCurve {
    /// K-256 curve.
    ///
    /// Implementation requires the `secp256k1` feature.
    K256,

    /// P-256 curve.
    ///
    /// Implementation requires the `secp256r1` feature.
    P256,

    /// P-384 curve.
    ///
    /// Implementation requires the `secp384r1` feature.
    P384,
}

impl EcdsaCurve {
    pub fn name(&self) -> &'static str {
        match self {
            Self::K256 => "K-256",
            Self::P256 => "P-256",
            Self::P384 => "P-384",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "K-256" => Some(Self::K256),
            "P-256" => Some(Self::P256),
            "P-384" => Some(Self::P384),
            _ => None,
        }
    }

    #[allow(unused_variables)]
    pub fn generate_from(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<EcdsaSecretKey, KeyGenerationFailed> {
        match self {
            #[cfg(feature = "secp256k1")]
            Self::K256 => Ok(EcdsaSecretKey::generate_k256_from(rng)),

            #[cfg(feature = "secp256r1")]
            Self::P256 => Ok(EcdsaSecretKey::generate_p256_from(rng)),

            #[cfg(feature = "secp384r1")]
            Self::P384 => Ok(EcdsaSecretKey::generate_p384_from(rng)),

            #[allow(unreachable_patterns)]
            _ => Err(KeyGenerationFailed::UnsupportedType),
        }
    }

    pub fn default_algorithm_params(&self) -> AlgorithmInstance {
        match self {
            Self::K256 => AlgorithmInstance::Es256K,
            Self::P256 => AlgorithmInstance::Es256,
            Self::P384 => AlgorithmInstance::Es384,
        }
    }
}

impl From<EcdsaCurve> for KeyType {
    fn from(value: EcdsaCurve) -> Self {
        Self::Ecdsa(value)
    }
}

/// Public key.
#[derive(Clone)]
#[non_exhaustive]
pub enum EcdsaPublicKey {
    #[cfg(feature = "secp256k1")]
    K256(k256::K256PublicKey),

    #[cfg(feature = "secp256r1")]
    P256(p256::P256PublicKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::P384PublicKey),
}

impl EcdsaPublicKey {
    pub fn curve(&self) -> EcdsaCurve {
        match self {
            #[cfg(feature = "secp256k1")]
            Self::K256(_) => EcdsaCurve::K256,

            #[cfg(feature = "secp256r1")]
            Self::P256(_) => EcdsaCurve::P256,

            #[cfg(feature = "secp384r1")]
            Self::P384(_) => EcdsaCurve::P384,

            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }

    pub fn verify_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        VerifyingKey::verify_bytes(self, algorithm, signing_bytes, signature)
    }
}

impl From<EcdsaPublicKey> for PublicKey {
    fn from(value: EcdsaPublicKey) -> Self {
        Self::Ecdsa(value)
    }
}

impl VerifyingKey for EcdsaPublicKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            id: None,
            r#type: Some(KeyType::Ecdsa(self.curve())),
            algorithm: None,
        }
    }

    #[allow(unused_variables)]
    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        match self {
            #[cfg(feature = "secp256r1")]
            Self::P256(key) => key.verify_bytes(algorithm, signing_bytes, signature),

            #[cfg(feature = "secp384r1")]
            Self::P384(key) => key.verify_bytes(algorithm, signing_bytes, signature),

            #[cfg(feature = "secp256k1")]
            Self::K256(key) => key.verify_bytes(algorithm, signing_bytes, signature),

            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl Verifier for EcdsaPublicKey {
    type VerifyingKey = Self;

    async fn get_verifying_key_with(
        &self,
        _key_id: Option<&[u8]>,
        _options: &Options,
    ) -> Result<Option<Self::VerifyingKey>, Error> {
        Ok(Some(self.clone()))
    }

    async fn verify_with(
        &self,
        _key_id: Option<&[u8]>,
        algorithm: Option<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
        _options: &Options,
    ) -> Result<SignatureVerification, Error> {
        let algorithm = infer_algorithm(algorithm, || None, || Some(KeyType::Ecdsa(self.curve())))
            .ok_or(Error::AlgorithmMissing)?;

        VerifyingKey::verify_bytes(self, algorithm, signing_bytes, signature)
    }
}

/// Secret key.
#[derive(ZeroizeOnDrop)]
#[non_exhaustive]
pub enum EcdsaSecretKey {
    #[cfg(feature = "secp256k1")]
    K256(k256::K256SecretKey),

    #[cfg(feature = "secp256r1")]
    P256(p256::P256SecretKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::P384SecretKey),
}

impl EcdsaSecretKey {
    /// Returns the public key to this secret key.
    pub fn to_public(&self) -> EcdsaPublicKey {
        match self {
            #[cfg(feature = "secp256k1")]
            Self::K256(secret) => EcdsaPublicKey::K256(*secret.verifying_key()),

            #[cfg(feature = "secp256r1")]
            Self::P256(secret) => EcdsaPublicKey::P256(*secret.verifying_key()),

            #[cfg(feature = "secp384r1")]
            Self::P384(secret) => EcdsaPublicKey::P384(*secret.verifying_key()),

            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }

    pub fn sign_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        SigningKey::sign_bytes(self, algorithm, signing_bytes)
    }
}

impl SigningKey for EcdsaSecretKey {
    #[allow(unused_variables)]
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            #[cfg(feature = "secp256r1")]
            Self::P256(key) => key.sign_bytes(algorithm, signing_bytes),

            #[cfg(feature = "secp384r1")]
            Self::P384(key) => key.sign_bytes(algorithm, signing_bytes),

            #[cfg(feature = "secp256k1")]
            Self::K256(key) => key.sign_bytes(algorithm, signing_bytes),

            #[allow(unreachable_patterns)]
            _ => unreachable!(),
        }
    }
}

impl Signer for EcdsaSecretKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata::default()
    }

    async fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        SigningKey::sign_bytes(self, algorithm, signing_bytes)
    }
}
