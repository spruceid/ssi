use std::marker::PhantomData;

use ssi_claims_core::SignatureError;

use crate::{CryptographicSuite, ProofConfiguration, ProofOptions};

pub type InputVerificationMethod<S> = <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::InputVerificationMethod;

pub type InputSuiteOptions<S> =
    <<S as CryptographicSuite>::Configuration as ConfigurationAlgorithm<S>>::InputSuiteOptions;

pub type InputOptions<S> = ProofOptions<InputVerificationMethod<S>, InputSuiteOptions<S>>;

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
    type InputVerificationMethod;
    type InputSuiteOptions;

    fn configure(
        suite: &S,
        options: ProofOptions<Self::InputVerificationMethod, Self::InputSuiteOptions>,
    ) -> Result<ProofConfiguration<S>, ConfigurationError>;
}

pub struct NoConfiguration;

impl<S: CryptographicSuite> ConfigurationAlgorithm<S> for NoConfiguration {
    type InputVerificationMethod = S::VerificationMethod;
    type InputSuiteOptions = S::ProofOptions;

    fn configure(
        suite: &S,
        options: ProofOptions<S::VerificationMethod, S::ProofOptions>,
    ) -> Result<ProofConfiguration<S>, ConfigurationError> {
        options.into_configuration(suite.clone())
    }
}

pub struct AddProofContext<C>(PhantomData<C>);

impl<C, S: CryptographicSuite + Default> ConfigurationAlgorithm<S> for AddProofContext<C>
where
    C: Default + Into<json_ld::syntax::Context>,
{
    type InputVerificationMethod = S::VerificationMethod;
    type InputSuiteOptions = S::ProofOptions;

    fn configure(
        suite: &S,
        options: ProofOptions<S::VerificationMethod, S::ProofOptions>,
    ) -> Result<ProofConfiguration<S>, ConfigurationError> {
        let mut result = options.into_configuration(suite.clone())?;
        result.context = Some(C::default().into());
        Ok(result)
    }
}
