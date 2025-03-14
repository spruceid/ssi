use crate::{
    key::{KeyConversionError, KeyMetadata},
    Algorithm, AlgorithmInstance, SecretKey,
};

/// Signer.
pub trait Signer {
    fn key_metadata(&self) -> KeyMetadata;

    #[allow(async_fn_in_trait)]
    async fn sign_bytes(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, SignatureError>;
}

impl<'a, T: Signer> Signer for &'a T {
    fn key_metadata(&self) -> KeyMetadata {
        T::key_metadata(*self)
    }

    async fn sign_bytes(
        &self,
        algorithm: AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, SignatureError> {
        T::sign_bytes(*&self, algorithm, signing_bytes).await
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("key conversion failed: {0}")]
    KeyConversion(#[from] KeyConversionError),

    #[error("missing algorithm")]
    MissingAlgorithm,

    #[error("unsupported algorithm `{0}`")]
    UnsupportedAlgorithm(Algorithm),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

impl SignatureError {
    pub fn other(e: impl 'static + Send + Sync + std::error::Error) -> Self {
        Self::Other(e.into())
    }
}

pub trait SigningKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, SignatureError>;
}

impl SigningKey for SecretKey {
    fn sign_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, SignatureError> {
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
