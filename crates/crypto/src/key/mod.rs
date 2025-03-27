use metadata::infer_algorithm;
use zeroize::ZeroizeOnDrop;

#[derive(Debug, thiserror::Error)]
#[error("invalid public key")]
pub struct InvalidPublicKey;

mod r#type;
pub use r#type::*;

pub mod metadata;
pub use metadata::KeyMetadata;

use crate::{
    AlgorithmInstance, Error, Options, SignatureVerification, Signer, SigningKey, Verifier,
    VerifyingKey,
};

mod spki;

/// Public key.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum PublicKey {
    /// Symmetric key.
    ///
    /// Such key cannot be made public, that's why there is no payload.
    Symmetric,

    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::Ed25519PublicKey),

    #[cfg(feature = "rsa")]
    Rsa(rsa::RsaPublicKey),

    #[cfg(feature = "secp256k1")]
    K256(k256::K256PublicKey),

    #[cfg(feature = "secp256r1")]
    P256(p256::P256PublicKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::P384PublicKey),
}

impl PublicKey {
    pub fn r#type(&self) -> KeyType {
        match self {
            Self::Symmetric => KeyType::Symmetric,

            #[cfg(feature = "ed25519")]
            Self::Ed25519(_) => KeyType::Ed25519,

            #[cfg(feature = "rsa")]
            Self::Rsa(_) => KeyType::Rsa,

            #[cfg(feature = "secp256k1")]
            Self::K256(_) => KeyType::K256,

            #[cfg(feature = "secp256r1")]
            Self::P256(_) => KeyType::P256,

            #[cfg(feature = "secp384r1")]
            Self::P384(_) => KeyType::P384,
        }
    }
}

impl VerifyingKey for PublicKey {
    fn key_metadata(&self) -> KeyMetadata {
        KeyMetadata {
            id: None,
            r#type: Some(self.r#type()),
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
            Self::Symmetric => Err(Error::AlgorithmUnsupported(algorithm.into().algorithm())),

            #[cfg(feature = "ed25519")]
            Self::Ed25519(key) => key.verify_bytes(algorithm, signing_bytes, signature),

            #[cfg(feature = "rsa")]
            Self::Rsa(key) => key.verify_bytes(algorithm, signing_bytes, signature),

            #[cfg(feature = "secp256r1")]
            Self::P256(key) => key.verify_bytes(algorithm, signing_bytes, signature),

            #[cfg(feature = "secp384r1")]
            Self::P384(key) => key.verify_bytes(algorithm, signing_bytes, signature),

            #[cfg(feature = "secp256k1")]
            Self::K256(key) => key.verify_bytes(algorithm, signing_bytes, signature),
        }
    }
}

impl Verifier for PublicKey {
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
        let algorithm = infer_algorithm(algorithm, || None, || Some(self.r#type()))
            .ok_or(Error::AlgorithmMissing)?;

        VerifyingKey::verify_bytes(self, algorithm, signing_bytes, signature)
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid secret key")]
pub struct InvalidSecretKey;

/// Secret key.
#[derive(ZeroizeOnDrop)]
#[non_exhaustive]
pub enum SecretKey {
    /// Symmetric key.
    Symmetric(symmetric::SymmetricKey),

    #[cfg(feature = "rsa")]
    Rsa(rsa::RsaSecretKey),

    #[cfg(feature = "ed25519")]
    Ed25519(ed25519::Ed25519SecretKey),

    #[cfg(feature = "secp256k1")]
    K256(k256::K256SecretKey),

    #[cfg(feature = "secp256r1")]
    P256(p256::P256SecretKey),

    #[cfg(feature = "secp384r1")]
    P384(p384::P384SecretKey),
}

impl SecretKey {
    #[cfg(feature = "rsa")]
    pub fn as_rsa(&self) -> Option<&rsa::RsaSecretKey> {
        match self {
            Self::Rsa(key) => Some(key),
            _ => None,
        }
    }

    /// Returns the public key to this secret key.
    pub fn to_public(&self) -> PublicKey {
        match self {
            Self::Symmetric(_) => PublicKey::Symmetric,

            #[cfg(feature = "rsa")]
            Self::Rsa(secret) => PublicKey::Rsa(secret.to_public_key()),

            #[cfg(feature = "ed25519")]
            Self::Ed25519(secret) => PublicKey::Ed25519(secret.verifying_key()),

            #[cfg(feature = "secp256k1")]
            Self::K256(secret) => PublicKey::K256(secret.public_key()),

            #[cfg(feature = "secp256r1")]
            Self::P256(secret) => PublicKey::P256(secret.public_key()),

            #[cfg(feature = "secp384r1")]
            Self::P384(secret) => PublicKey::P384(secret.public_key()),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyConversionError {
    #[error("no secret material")]
    NotSecret,

    #[error("unsupported key type")]
    Unsupported,

    #[error("invalid key")]
    Invalid,
}

#[derive(Debug, thiserror::Error)]
#[error("key generation failed")]
pub struct KeyGenerationFailed;

impl SigningKey for SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        match self {
            Self::Symmetric(key) => key.sign_bytes(algorithm, signing_bytes),

            #[cfg(feature = "ed25519")]
            Self::Ed25519(key) => key.sign_bytes(algorithm, signing_bytes),

            #[cfg(feature = "rsa")]
            Self::Rsa(key) => key.sign_bytes(algorithm, signing_bytes),

            #[cfg(feature = "secp256r1")]
            Self::P256(key) => key.sign_bytes(algorithm, signing_bytes),

            #[cfg(feature = "secp384r1")]
            Self::P384(key) => key.sign_bytes(algorithm, signing_bytes),

            #[cfg(feature = "secp256k1")]
            Self::K256(key) => key.sign_bytes(algorithm, signing_bytes),
        }
    }
}

impl Signer for SecretKey {
    fn key_metadata(&self) -> KeyMetadata {
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
