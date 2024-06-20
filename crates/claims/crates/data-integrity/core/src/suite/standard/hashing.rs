use ssi_claims_core::SignatureError;

use crate::ProofConfigurationRef;

use super::{StandardCryptographicSuite, TransformedData};

pub type HashedData<S> =
    <<S as StandardCryptographicSuite>::Hashing as HashingAlgorithm<S>>::Output;

#[derive(Debug, thiserror::Error)]
pub enum HashingError {
    #[error("invalid message: {0}")]
    InvalidMessage(String),

    #[error("message is too long")]
    TooLong,
}

impl From<HashingError> for SignatureError {
    fn from(value: HashingError) -> Self {
        Self::other(value)
    }
}

/// Hashing algorithm.
pub trait HashingAlgorithm<S: StandardCryptographicSuite> {
    type Output;

    fn hash(
        input: TransformedData<S>,
        proof_configuration: ProofConfigurationRef<S>,
    ) -> Result<Self::Output, HashingError>;
}
