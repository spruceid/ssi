use crate::{key::KeyConversionError, Algorithm, HashFunction};

/// Signature or verification error.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid input")]
    InputMalformed(anyhow::Error),

    #[error("verifying key not found")]
    KeyNotFound(Option<Vec<u8>>),

    #[error("key conversion failed: {0}")]
    KeyConversion(#[from] KeyConversionError),

    #[error("invalid key")]
    KeyInvalid,

    #[error("unsupported key")]
    KeyUnsupported,

    #[error("invalid key use")]
    KeyInvalidUse,

    #[error("key controller not found")]
    KeyControllerNotFound,

    #[error("invalid key controller")]
    KeyControllerInvalid,

    #[error("unsupported key controller")]
    KeyControllerUnsupported,

    #[error("missing algorithm")]
    AlgorithmMissing,

    #[error("unsupported algorithm `{0}`")]
    AlgorithmUnsupported(Algorithm),

    #[error("unsupported hash function `{0}`")]
    HashFunctionUnsupported(HashFunction),

    #[error("missing signature")]
    SignatureMissing,

    #[error("malformed signature")]
    SignatureMalformed,

    #[error("too many signature")]
    SignatureTooMany,

    #[error(transparent)]
    Internal(#[from] anyhow::Error),
}

impl Error {
    pub fn internal(e: impl Into<anyhow::Error>) -> Self {
        Self::Internal(e.into())
    }

    pub fn malformed_input(e: impl Into<anyhow::Error>) -> Self {
        Self::InputMalformed(e.into())
    }
}
