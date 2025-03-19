use rand::{CryptoRng, RngCore};
use zeroize::ZeroizeOnDrop;

use crate::{
    key::{metadata::infer_algorithm, KeyGenerationFailed, KeyMetadata},
    AlgorithmInstance, Error, Options, SignatureVerification, Signer, SigningKey, Verifier,
    VerifyingKey,
};

use super::KeyType;

#[cfg(feature = "ed25519")]
pub mod ed25519;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum EdDsaKeyType {
    Curve25519,
}

impl EdDsaKeyType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Curve25519 => "Ed25519",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Ed25519" => Some(Self::Curve25519),
            _ => None,
        }
    }

    pub fn generate_from(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
    ) -> Result<EdDsaSecretKey, KeyGenerationFailed> {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Curve25519 => Ok(EdDsaSecretKey::generate_ed25519_from(rng)),

            #[allow(unreachable_patterns)]
            _ => Err(KeyGenerationFailed::UnsupportedType),
        }
    }

    pub fn default_algorithm_params(&self) -> AlgorithmInstance {
        match self {
            Self::Curve25519 => AlgorithmInstance::EdDsa,
        }
    }
}

#[derive(Clone)]
#[non_exhaustive]
pub enum EdDsaPublicKey {
    #[cfg(feature = "ed25519")]
    Curve25519(ed25519::Ed25519PublicKey),
}

impl EdDsaPublicKey {
    pub fn r#type(&self) -> EdDsaKeyType {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Curve25519(_) => EdDsaKeyType::Curve25519,
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

impl VerifyingKey for EdDsaPublicKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            id: None,
            r#type: Some(KeyType::EdDsa(self.r#type())),
            algorithm: None,
        }
    }

    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Curve25519(key) => key.verify_bytes(algorithm, signing_bytes, signature),
        }
    }
}

impl Verifier for EdDsaPublicKey {
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
        let algorithm = infer_algorithm(algorithm, || None, || Some(KeyType::EdDsa(self.r#type())))
            .ok_or(Error::AlgorithmMissing)?;

        VerifyingKey::verify_bytes(self, algorithm, signing_bytes, signature)
    }
}

#[derive(ZeroizeOnDrop)]
#[non_exhaustive]
pub enum EdDsaSecretKey {
    #[cfg(feature = "ed25519")]
    Curve25519(ed25519::Ed25519SecretKey),
}

impl EdDsaSecretKey {
    /// Returns the public key to this secret key.
    pub fn to_public(&self) -> EdDsaPublicKey {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Curve25519(key) => EdDsaPublicKey::Curve25519(key.verifying_key()),
        }
    }

    pub fn sign_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        SigningKey::sign_bytes(self, algorithm, signing_bytes)
    }
}

impl SigningKey for EdDsaSecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        match self {
            #[cfg(feature = "ed25519")]
            Self::Curve25519(key) => key.sign_bytes(algorithm, signing_bytes),
        }
    }
}

impl Signer for EdDsaSecretKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata::default()
    }

    async fn sign(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        SigningKey::sign_bytes(self, algorithm, signing_bytes)
    }
}
