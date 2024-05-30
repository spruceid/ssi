use std::convert::Infallible;

use ssi_claims_core::{ProofPreparationError, ProofValidationError, SignatureError};
use ssi_verification_methods_core::InvalidVerificationMethod;

use crate::ProofConfigurationCastError;

#[derive(Debug, thiserror::Error)]
pub enum ProofConfigurationError {}

impl From<ProofConfigurationError> for SignatureError {
    fn from(value: ProofConfigurationError) -> Self {
        match value {}
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TransformError {
    #[error("Expansion failed: {0}")]
    ExpansionFailed(String),

    #[error("RDF deserialization failed: {0}")]
    LinkedData(#[from] linked_data::IntoQuadsError),

    #[error("JSON serialization failed: {0}")]
    JsonSerialization(json_syntax::SerializeError),

    #[error("expected JSON object")] // TODO merge it with `InvalidData`.
    ExpectedJsonObject,

    #[error("invalid data")]
    InvalidData,

    #[error("unsupported input format")]
    UnsupportedInputFormat,

    #[error("invalid proof options: {0}")]
    InvalidProofOptions(InvalidOptions),

    #[error("invalid verification method: {0}")]
    InvalidVerificationMethod(InvalidVerificationMethod),

    #[error("internal error: `{0}`")]
    Internal(String),
}

impl TransformError {
    pub fn internal(e: impl ToString) -> Self {
        Self::Internal(e.to_string())
    }
}

impl From<ProofConfigurationCastError<InvalidVerificationMethod, InvalidOptions>>
    for TransformError
{
    fn from(value: ProofConfigurationCastError<InvalidVerificationMethod, InvalidOptions>) -> Self {
        match value {
            ProofConfigurationCastError::VerificationMethod(e) => {
                Self::InvalidVerificationMethod(e)
            }
            ProofConfigurationCastError::Options(e) => Self::InvalidProofOptions(e),
        }
    }
}

impl From<ProofConfigurationCastError<InvalidVerificationMethod, Infallible>> for TransformError {
    fn from(value: ProofConfigurationCastError<InvalidVerificationMethod, Infallible>) -> Self {
        match value {
            ProofConfigurationCastError::VerificationMethod(e) => {
                Self::InvalidVerificationMethod(e)
            }
            ProofConfigurationCastError::Options(_) => unreachable!(),
        }
    }
}

impl From<TransformError> for ProofPreparationError {
    fn from(value: TransformError) -> Self {
        ProofPreparationError::Claims(value.to_string())
    }
}

impl From<TransformError> for SignatureError {
    fn from(value: TransformError) -> Self {
        SignatureError::Claims(value.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum HashError {
    #[error("invalid verification method")]
    InvalidVerificationMethod,

    #[error("message is too long")]
    TooLong,

    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("invalid transformed input")]
    InvalidTransformedInput,
}

impl From<HashError> for ProofPreparationError {
    fn from(value: HashError) -> Self {
        Self::Claims(value.to_string())
    }
}

impl From<HashError> for SignatureError {
    fn from(value: HashError) -> Self {
        Self::Claims(value.to_string())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidOptions {
    #[error("missing public key")]
    MissingPublicKey,
}

impl From<InvalidOptions> for ProofValidationError {
    fn from(value: InvalidOptions) -> Self {
        match value {
            InvalidOptions::MissingPublicKey => ProofValidationError::MissingPublicKey,
        }
    }
}

impl From<InvalidOptions> for SignatureError {
    fn from(value: InvalidOptions) -> Self {
        match value {
            InvalidOptions::MissingPublicKey => SignatureError::MissingPublicKey,
        }
    }
}