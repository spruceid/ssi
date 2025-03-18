use zeroize::ZeroizeOnDrop;

use crate::{
    key::{metadata::infer_algorithm, KeyMetadata},
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
pub enum EcdsaKeyType {
    K256,
    P256,
    P384,
}

impl EcdsaKeyType {
    pub fn name(&self) -> &'static str {
        match self {
            Self::K256 => "K-256",
            Self::P256 => "P-256",
            Self::P384 => "P-384",
        }
    }

    pub fn default_algorithm_params(&self) -> AlgorithmInstance {
        match self {
            Self::K256 => AlgorithmInstance::ES256K,
            Self::P256 => AlgorithmInstance::ES256,
            Self::P384 => AlgorithmInstance::ES384,
        }
    }
}

impl From<EcdsaKeyType> for KeyType {
    fn from(value: EcdsaKeyType) -> Self {
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
    pub fn r#type(&self) -> EcdsaKeyType {
        match self {
            #[cfg(feature = "secp256k1")]
            Self::K256(_) => EcdsaKeyType::K256,

            #[cfg(feature = "secp256r1")]
            Self::P256(_) => EcdsaKeyType::P256,

            #[cfg(feature = "secp384r1")]
            Self::P384(_) => EcdsaKeyType::P384,
        }
    }

    pub fn verify_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        VerifyingKey::verify_message(self, algorithm, signing_bytes, signature)
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
            r#type: Some(KeyType::Ecdsa(self.r#type())),
            algorithm: None,
        }
    }

    fn verify_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<SignatureVerification, Error> {
        match self {
            #[cfg(feature = "secp256r1")]
            Self::P256(key) => key.verify_message(algorithm, signing_bytes, signature),

            #[cfg(feature = "secp384r1")]
            Self::P384(key) => key.verify_message(algorithm, signing_bytes, signature),

            #[cfg(feature = "secp256k1")]
            Self::K256(key) => key.verify_message(algorithm, signing_bytes, signature),
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
        let algorithm = infer_algorithm(algorithm, || None, || Some(KeyType::Ecdsa(self.r#type())))
            .ok_or(Error::AlgorithmMissing)?;

        VerifyingKey::verify_message(self, algorithm, signing_bytes, signature)
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
            Self::K256(secret) => EcdsaPublicKey::K256(secret.public_key()),

            #[cfg(feature = "secp256r1")]
            Self::P256(secret) => EcdsaPublicKey::P256(secret.public_key()),

            #[cfg(feature = "secp384r1")]
            Self::P384(secret) => EcdsaPublicKey::P384(secret.public_key()),
        }
    }

    pub fn sign_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        SigningKey::sign_message(self, algorithm, signing_bytes)
    }
}

impl SigningKey for EcdsaSecretKey {
    fn sign_message(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, Error> {
        match self {
            #[cfg(feature = "secp256r1")]
            Self::P256(key) => key.sign_message(algorithm, signing_bytes),

            #[cfg(feature = "secp384r1")]
            Self::P384(key) => key.sign_message(algorithm, signing_bytes),

            #[cfg(feature = "secp256k1")]
            Self::K256(key) => key.sign_message(algorithm, signing_bytes),
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
    ) -> Result<Box<[u8]>, Error> {
        SigningKey::sign_message(self, algorithm, signing_bytes)
    }
}
