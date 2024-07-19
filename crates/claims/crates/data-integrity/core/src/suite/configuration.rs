use std::marker::PhantomData;

use ssi_claims_core::{ProofValidationError, SignatureError};
use ssi_json_ld::syntax::Context;

use crate::{CryptographicSuite, ProofConfiguration, ProofOptions};

pub type InputVerificationMethod<S> = <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::InputVerificationMethod;

pub type InputSuiteOptions<S> =
    <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::InputSuiteOptions;

pub type InputProofOptions<S> = ProofOptions<InputVerificationMethod<S>, InputSuiteOptions<S>>;

pub type InputSignatureOptions<S> =
    <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::InputSignatureOptions;

pub type InputVerificationOptions<S> =
    <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::InputVerificationOptions;

pub type TransformationOptions<S> =
    <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::TransformationOptions;

#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    #[error("missing verification method")]
    MissingVerificationMethod,

    #[error("missing option `{0}`")]
    MissingOption(String),

    #[error("invalid option `{0}`")]
    InvalidOption(String),

    #[error("{0}")]
    Other(String),
}

impl From<std::convert::Infallible> for ConfigurationError {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl ConfigurationError {
    pub fn invalid_option(e: impl ToString) -> Self {
        Self::InvalidOption(e.to_string())
    }

    pub fn other(e: impl ToString) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<ConfigurationError> for SignatureError {
    fn from(value: ConfigurationError) -> Self {
        Self::other(value)
    }
}

impl From<ConfigurationError> for ProofValidationError {
    fn from(value: ConfigurationError) -> Self {
        Self::other(value)
    }
}

pub trait ConfigurationAlgorithm<S: CryptographicSuite> {
    /// Input type for the verification method.
    type InputVerificationMethod;

    /// Input suite-specific proof options.
    ///
    /// These options are stored in the `proof` object.
    type InputSuiteOptions;

    /// Input suite-specific signature options.
    ///
    /// These options do not appear in the `proof` object.
    type InputSignatureOptions;

    /// Input suite-specific verification options.
    ///
    /// These options do not appear in the `proof` object.
    type InputVerificationOptions;

    /// Document transformation options.
    type TransformationOptions;

    fn configure_signature(
        suite: &S,
        proof_options: ProofOptions<Self::InputVerificationMethod, Self::InputSuiteOptions>,
        signature_options: InputSignatureOptions<S>,
    ) -> Result<(ProofConfiguration<S>, Self::TransformationOptions), ConfigurationError>;

    fn configure_verification(
        suite: &S,
        verification_options: &InputVerificationOptions<S>,
    ) -> Result<Self::TransformationOptions, ConfigurationError>;
}

pub struct NoConfiguration;

impl<S: CryptographicSuite> ConfigurationAlgorithm<S> for NoConfiguration {
    type InputVerificationMethod = S::VerificationMethod;
    type InputSuiteOptions = S::ProofOptions;

    type InputSignatureOptions = ();

    type InputVerificationOptions = ();

    type TransformationOptions = ();

    fn configure_signature(
        suite: &S,
        proof_options: ProofOptions<S::VerificationMethod, S::ProofOptions>,
        _: InputSignatureOptions<S>,
    ) -> Result<(ProofConfiguration<S>, Self::TransformationOptions), ConfigurationError> {
        Ok((proof_options.into_configuration(suite.clone())?, ()))
    }

    fn configure_verification(
        _suite: &S,
        _verification_options: &InputVerificationOptions<S>,
    ) -> Result<Self::TransformationOptions, ConfigurationError> {
        Ok(())
    }
}

pub struct AddProofContext<C>(PhantomData<C>);

impl<C, S: CryptographicSuite + Default> ConfigurationAlgorithm<S> for AddProofContext<C>
where
    C: Default + Into<ssi_json_ld::syntax::Context>,
{
    type InputVerificationMethod = S::VerificationMethod;
    type InputSuiteOptions = S::ProofOptions;
    type InputSignatureOptions = ();
    type InputVerificationOptions = ();
    type TransformationOptions = ();

    fn configure_signature(
        suite: &S,
        options: ProofOptions<S::VerificationMethod, S::ProofOptions>,
        _: InputSignatureOptions<S>,
    ) -> Result<(ProofConfiguration<S>, Self::TransformationOptions), ConfigurationError> {
        let mut result = options.into_configuration(suite.clone())?;
        result.context = match result.context {
            None => Some(C::default().into()),
            Some(c) => Some(Context::Many(
                c.into_iter().chain(C::default().into()).collect(),
            )),
        };
        Ok((result, ()))
    }

    fn configure_verification(
        _suite: &S,
        _verification_options: &InputVerificationOptions<S>,
    ) -> Result<Self::TransformationOptions, ConfigurationError> {
        Ok(())
    }
}
