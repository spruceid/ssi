use std::marker::PhantomData;

use ssi_claims_core::SignatureError;
use ssi_json_ld::syntax::Context;

use crate::{CryptographicSuite, ProofConfiguration, ProofOptions};

pub type InputVerificationMethod<S> = <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::InputVerificationMethod;

pub type InputSuiteOptions<S> =
    <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::InputProofOptions;

pub type InputProofOptions<S> = ProofOptions<InputVerificationMethod<S>, InputSuiteOptions<S>>;

pub type InputSignatureOptions<S> =
    <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::InputSignatureOptions;

pub type TransformationOptions<S> =
    <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::TransformationOptions;

#[derive(Debug, thiserror::Error)]
pub enum ConfigurationError {
    #[error("missing verification method")]
    MissingVerificationMethod,

    #[error("missing option `{0}`")]
    MissingOption(String),

    #[error("{0}")]
    Other(String),
}

impl From<std::convert::Infallible> for ConfigurationError {
    fn from(_: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl ConfigurationError {
    pub fn other(e: impl ToString) -> Self {
        Self::Other(e.to_string())
    }
}

impl From<ConfigurationError> for SignatureError {
    fn from(value: ConfigurationError) -> Self {
        Self::other(value)
    }
}

pub trait ConfigurationAlgorithm<S: CryptographicSuite> {
    /// Input type for the verification method.
    type InputVerificationMethod;

    /// Input suite-specific proof options.
    type InputProofOptions;

    /// Input signature options.
    type InputSignatureOptions;

    /// Document transformation options.
    type TransformationOptions;

    fn configure(
        suite: &S,
        proof_options: ProofOptions<Self::InputVerificationMethod, Self::InputProofOptions>,
        signature_options: Self::InputSignatureOptions,
    ) -> Result<(ProofConfiguration<S>, Self::TransformationOptions), ConfigurationError>;
}

pub struct NoConfiguration;

impl<S: CryptographicSuite> ConfigurationAlgorithm<S> for NoConfiguration {
    type InputVerificationMethod = S::VerificationMethod;
    type InputProofOptions = S::ProofOptions;
    type InputSignatureOptions = ();
    type TransformationOptions = ();

    fn configure(
        suite: &S,
        proof_options: ProofOptions<S::VerificationMethod, S::ProofOptions>,
        _: (),
    ) -> Result<(ProofConfiguration<S>, ()), ConfigurationError> {
        Ok((proof_options.into_configuration(suite.clone())?, ()))
    }
}

pub struct AddProofContext<C>(PhantomData<C>);

impl<C, S: CryptographicSuite + Default> ConfigurationAlgorithm<S> for AddProofContext<C>
where
    C: Default + Into<ssi_json_ld::syntax::Context>,
{
    type InputVerificationMethod = S::VerificationMethod;
    type InputProofOptions = S::ProofOptions;
    type InputSignatureOptions = ();
    type TransformationOptions = ();

    fn configure(
        suite: &S,
        options: ProofOptions<S::VerificationMethod, S::ProofOptions>,
        _: (),
    ) -> Result<(ProofConfiguration<S>, ()), ConfigurationError> {
        let mut result = options.into_configuration(suite.clone())?;
        result.context = match result.context {
            None => Some(C::default().into()),
            Some(c) => Some(Context::Many(
                c.into_iter().chain(C::default().into()).collect(),
            )),
        };
        Ok((result, ()))
    }
}
