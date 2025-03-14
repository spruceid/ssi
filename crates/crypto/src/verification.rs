use crate::{key::KeyConversionError, Algorithm, AlgorithmInstance, PublicKey};

pub trait Verifier {
    #[allow(async_fn_in_trait)]
    async fn verify_bytes(
        &self,
        key_id: Option<&[u8]>,
        algorithm: Option<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Verification, VerificationError>;
}

impl<'a, T: Verifier> Verifier for &'a T {
    async fn verify_bytes(
        &self,
        key_id: Option<&[u8]>,
        algorithm: Option<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Verification, VerificationError> {
        T::verify_bytes(*self, key_id, algorithm, signing_bytes, signature).await
    }
}

pub type Verification = Result<(), RejectedSignature>;

#[derive(Debug, thiserror::Error)]
#[error("rejected signature")]
pub struct RejectedSignature;

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error("key conversion failed: {0}")]
    KeyConversion(#[from] KeyConversionError),

    #[error("verifying key not found")]
    KeyNotFound,

    #[error("missing algorithm")]
    MissingAlgorithm,

    #[error("unsupported algorithm `{0}`")]
    UnsupportedAlgorithm(Algorithm),

    #[error("malformed signature")]
    MalformedSignature,
}

pub trait VerifyingKey {
    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Verification, VerificationError>;
}

impl VerifyingKey for PublicKey {
    fn verify_bytes(
        &self,
        algorithm: impl Into<AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<Verification, VerificationError> {
        match self {
            Self::Symmetric => Err(VerificationError::UnsupportedAlgorithm(
                algorithm.into().algorithm(),
            )),

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
