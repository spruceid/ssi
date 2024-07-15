use linked_data::IntoQuadsError;
use serde::Serialize;
use ssi_claims_core::{ProofValidationError, SignatureError};

use crate::{
    suite::TransformationOptions, ConfigurationExpansionError, CryptographicSuite,
    ProofConfigurationRef,
};

use super::StandardCryptographicSuite;

pub type TransformedData<S> =
    <<S as StandardCryptographicSuite>::Transformation as TransformationAlgorithm<S>>::Output;

#[derive(Debug, thiserror::Error)]
pub enum TransformationError {
    #[error("JSON-LD expansion failed: {0}")]
    JsonLdExpansion(String),

    #[error("JSON-LD deserialization failed: {0}")]
    JsonLdDeserialization(#[from] IntoQuadsError),

    #[error("proof configuration expansion failed: {0}")]
    ProofConfigurationExpansion(#[from] ConfigurationExpansionError),

    #[error("JSON serialization failed: {0}")]
    JsonSerialization(#[from] json_syntax::SerializeError),

    #[error("expected JSON object")]
    ExpectedJsonObject,

    #[error("invalid input")]
    InvalidInput,

    #[error("invalid options")]
    InvalidOptions,

    #[error("invalid key")]
    InvalidKey,

    #[error("{0}")]
    Internal(String),
}

impl TransformationError {
    pub fn internal(e: impl ToString) -> Self {
        Self::Internal(e.to_string())
    }

    pub fn json_ld_expansion(e: impl ToString) -> Self {
        Self::JsonLdExpansion(e.to_string())
    }
}

impl From<TransformationError> for SignatureError {
    fn from(value: TransformationError) -> Self {
        Self::other(value)
    }
}

impl From<TransformationError> for ProofValidationError {
    fn from(value: TransformationError) -> Self {
        Self::other(value)
    }
}

/// Transformation algorithm definition.
pub trait TransformationAlgorithm<S: CryptographicSuite> {
    /// Transformed data.
    type Output;
}

pub trait TypedTransformationAlgorithm<S: CryptographicSuite, T, C>:
    TransformationAlgorithm<S>
{
    #[allow(async_fn_in_trait)]
    async fn transform(
        context: &C,
        data: &T,
        proof_configuration: ProofConfigurationRef<S>,
        verification_method: &S::VerificationMethod,
        transformation_options: TransformationOptions<S>,
    ) -> Result<Self::Output, TransformationError>;
}

pub struct JsonObjectTransformation;

impl<S: CryptographicSuite> TransformationAlgorithm<S> for JsonObjectTransformation {
    type Output = json_syntax::Object;
}

impl<S: StandardCryptographicSuite, T: Serialize, C> TypedTransformationAlgorithm<S, T, C>
    for JsonObjectTransformation
{
    async fn transform(
        _context: &C,
        data: &T,
        _options: ProofConfigurationRef<'_, S>,
        _verification_method: &S::VerificationMethod,
        _transformation_options: TransformationOptions<S>,
    ) -> Result<Self::Output, TransformationError> {
        json_syntax::to_value(data)
            .map_err(TransformationError::JsonSerialization)?
            .into_object()
            .ok_or(TransformationError::ExpectedJsonObject)
    }
}
