use crate::{InvalidVerificationMethod, VerificationError, VerificationMethodResolutionError};

mod signer;

pub use signer::*;

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("verification method resolution failed: {0}")]
    Resolution(#[from] VerificationMethodResolutionError),

    #[error("missing verification method")]
    MissingVerificationMethod,

    #[error("unknown verification method")]
    UnknownVerificationMethod,

    #[error("no signer for requested verification method")]
    MissingSigner,

    #[error("invalid hash")]
    InvalidHash,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error(transparent)]
    InvalidVerificationMethod(#[from] InvalidVerificationMethod),

    #[error("missing public key")]
    MissingPublicKey,

    #[error(transparent)]
    Signer(#[from] ssi_crypto::MessageSignatureError),

    #[error("invalid received signature")]
    InvalidSignature,

    #[error("invalid signature algorithm")]
    InvalidAlgorithm,

    #[error("missing signature algorithm")]
    MissingAlgorithm,
}

impl From<std::convert::Infallible> for SignatureError {
    fn from(_value: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

pub enum InvalidSignature {
    MissingValue,

    InvalidValue,

    MissingPublicKey,

    AmbiguousPublicKey,
}

impl From<InvalidSignature> for VerificationError {
    fn from(value: InvalidSignature) -> Self {
        match value {
            InvalidSignature::MissingValue => Self::MissingSignature,
            InvalidSignature::InvalidValue => Self::InvalidSignature,
            InvalidSignature::MissingPublicKey => Self::MissingPublicKey,
            InvalidSignature::AmbiguousPublicKey => Self::AmbiguousPublicKey,
        }
    }
}
