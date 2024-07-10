use ssi_claims_core::{ProofValidationError, SignatureError};
use ssi_crypto::{
    algorithm::{self, Algorithm, SignatureAlgorithmType},
    AlgorithmInstance,
};

mod jws;
pub use jws::*;

mod multibase;
pub use multibase::*;

pub enum AlgorithmSelectionError {
    MissingAlgorithm,
    InvalidKey,
}

impl From<AlgorithmSelectionError> for SignatureError {
    fn from(value: AlgorithmSelectionError) -> Self {
        match value {
            AlgorithmSelectionError::MissingAlgorithm => Self::MissingAlgorithm,
            AlgorithmSelectionError::InvalidKey => Self::InvalidPublicKey,
        }
    }
}

impl From<AlgorithmSelectionError> for ProofValidationError {
    fn from(value: AlgorithmSelectionError) -> Self {
        match value {
            AlgorithmSelectionError::MissingAlgorithm => Self::MissingAlgorithm,
            AlgorithmSelectionError::InvalidKey => Self::InvalidKey,
        }
    }
}

pub trait AlgorithmSelection<M, O>: SignatureAlgorithmType {
    fn select_algorithm(
        verification_method: &M,
        options: &O,
    ) -> Result<Self::Instance, AlgorithmSelectionError>;
}

impl<M: ssi_verification_methods_core::JwkVerificationMethod, O> AlgorithmSelection<M, O>
    for Algorithm
{
    fn select_algorithm(
        verification_method: &M,
        _options: &O,
    ) -> Result<AlgorithmInstance, AlgorithmSelectionError> {
        verification_method
            .to_jwk()
            .get_algorithm()
            .ok_or(AlgorithmSelectionError::MissingAlgorithm)
            .map(Into::into)
    }
}

impl<M: ssi_verification_methods_core::JwkVerificationMethod, O> AlgorithmSelection<M, O>
    for ssi_jwk::Algorithm
{
    fn select_algorithm(
        verification_method: &M,
        _options: &O,
    ) -> Result<Self, AlgorithmSelectionError> {
        verification_method
            .to_jwk()
            .get_algorithm()
            .ok_or(AlgorithmSelectionError::MissingAlgorithm)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::ES256KR {
    fn select_algorithm(
        _verification_method: &M,
        _options: &O,
    ) -> Result<Self, AlgorithmSelectionError> {
        Ok(Self)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::ES256K {
    fn select_algorithm(
        _verification_method: &M,
        _options: &O,
    ) -> Result<Self, AlgorithmSelectionError> {
        Ok(Self)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::ES256 {
    fn select_algorithm(
        _verification_method: &M,
        _options: &O,
    ) -> Result<Self, AlgorithmSelectionError> {
        Ok(Self)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::EdDSA {
    fn select_algorithm(
        _verification_method: &M,
        _options: &O,
    ) -> Result<Self, AlgorithmSelectionError> {
        Ok(Self)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::EdBlake2b {
    fn select_algorithm(
        _verification_method: &M,
        _options: &O,
    ) -> Result<Self, AlgorithmSelectionError> {
        Ok(Self)
    }
}

impl<M, O> AlgorithmSelection<M, O> for algorithm::ESBlake2b {
    fn select_algorithm(
        _verification_method: &M,
        _options: &O,
    ) -> Result<Self, AlgorithmSelectionError> {
        Ok(Self)
    }
}

pub trait AlterSignature {
    fn alter(&mut self);
}
