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

#[cfg(feature = "spki")]
mod spki;

/// Public key.
#[derive(Clone)]
#[non_exhaustive]
#[allow(clippy::large_enum_variant)]
pub enum PublicKey {
    /// Symmetric key.
    ///
    /// Such key cannot be made public, that's why there is no payload, only the
    /// size of the key.
    Symmetric(usize),

    /// RSA key.
    ///
    /// Requires the `rsa` feature.
    #[cfg(feature = "rsa")]
    Rsa(RsaPublicKey),

    /// ECDSA key.
    Ecdsa(EcdsaPublicKey),

    /// EdDSA key.
    EdDsa(EdDsaPublicKey),
}

impl PublicKey {
    /// Returns the key type.
    pub fn r#type(&self) -> KeyType {
        match self {
            Self::Symmetric(len) => KeyType::Symmetric(*len),

            #[cfg(feature = "rsa")]
            Self::Rsa(k) => {
                use ::rsa::traits::PublicKeyParts;
                KeyType::Rsa(crate::BitSize(k.n().bits()))
            }

            Self::Ecdsa(k) => KeyType::Ecdsa(k.curve()),

            Self::EdDsa(k) => KeyType::EdDsa(k.curve()),
        }
    }

    pub fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        VerifyingKey::verify_bytes(self, algorithm, signing_bytes, signature)
    }
}

impl VerifyingKey for PublicKey {
    fn metadata(&self) -> KeyMetadata {
        KeyMetadata {
            id: None,
            r#type: Some(self.r#type()),
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
            Self::Symmetric(_) => Err(Error::AlgorithmUnsupported(algorithm.into().algorithm())),

            #[cfg(feature = "rsa")]
            Self::Rsa(key) => key.verify_bytes(algorithm, signing_bytes, signature),

            Self::Ecdsa(key) => key.verify_message(algorithm, signing_bytes, signature),

            Self::EdDsa(key) => key.verify_message(algorithm, signing_bytes, signature),
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
#[allow(clippy::large_enum_variant)]
pub enum SecretKey {
    /// Symmetric key.
    Symmetric(SymmetricKey),

    /// RSA key.
    ///
    /// Requires the `rsa` feature.
    #[cfg(feature = "rsa")]
    Rsa(RsaSecretKey),

    /// ECDSA key.
    Ecdsa(EcdsaSecretKey),

    /// EdDSA key.
    EdDsa(EdDsaSecretKey),
}

impl SecretKey {
    #[cfg(feature = "rsa")]
    pub fn as_rsa(&self) -> Option<&RsaSecretKey> {
        match self {
            Self::Rsa(key) => Some(key),
            _ => None,
        }
    }

    /// Returns the public key to this secret key.
    pub fn to_public(&self) -> PublicKey {
        match self {
            Self::Symmetric(s) => PublicKey::Symmetric(s.len()),

            #[cfg(feature = "rsa")]
            Self::Rsa(secret) => PublicKey::Rsa(secret.to_public_key()),

            Self::Ecdsa(secret) => PublicKey::Ecdsa(secret.to_public()),

            Self::EdDsa(secret) => PublicKey::EdDsa(secret.to_public()),
        }
    }

    pub fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        SigningKey::sign_bytes(self, algorithm, signing_bytes)
    }
}

impl SigningKey for SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Vec<u8>, Error> {
        match self {
            Self::Symmetric(key) => key.sign_bytes(algorithm, signing_bytes),

            #[cfg(feature = "rsa")]
            Self::Rsa(key) => key.sign_bytes(algorithm, signing_bytes),

            Self::Ecdsa(key) => key.sign_message(algorithm, signing_bytes),

            Self::EdDsa(key) => key.sign_message(algorithm, signing_bytes),
        }
    }
}

impl Signer for SecretKey {
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
pub enum KeyGenerationFailed {
    #[error("unsupported key type")]
    UnsupportedType,

    #[error("invalid key parameters")]
    InvalidParameters,
}
