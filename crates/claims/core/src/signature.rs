use core::fmt;

use ssi_crypto::algorithm::{AlgorithmError, UnsupportedAlgorithm};
use ssi_eip712::Eip712TypesLoaderProvider;
use ssi_json_ld::JsonLdLoaderProvider;

#[derive(Debug, thiserror::Error)]
pub enum SignatureError {
    #[error("missing signature algorithm")]
    MissingAlgorithm,

    #[error("algorithm mismatch")]
    AlgorithmMismatch,

    #[error("unsupported algorithm `{0}`")]
    UnsupportedAlgorithm(String),

    #[error("missing required public key")]
    MissingPublicKey,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("proof configuration: {0}")]
    ProofConfiguration(String),

    #[error("claims: {0}")]
    Claims(String),

    #[error("missing required option `{0}`")]
    MissingRequiredOption(String),

    #[error("missing signer")]
    MissingSigner,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("{0}")]
    Other(String),
}

impl SignatureError {
    pub fn other(e: impl fmt::Display) -> Self {
        Self::Other(e.to_string())
    }

    pub fn missing_required_option(name: &str) -> Self {
        Self::MissingRequiredOption(name.to_string())
    }
}

impl From<std::convert::Infallible> for SignatureError {
    fn from(_value: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

impl From<ssi_crypto::SignatureError> for SignatureError {
    fn from(value: ssi_crypto::SignatureError) -> Self {
        match value {
            ssi_crypto::SignatureError::UnsupportedAlgorithm(a) => {
                Self::UnsupportedAlgorithm(a.to_string())
            }
            e => Self::other(e),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum MessageSignatureError {
    #[error("0")]
    SignatureFailed(String),

    #[error("invalid signature client query")]
    InvalidQuery,

    #[error("invalid signer response")]
    InvalidResponse,

    #[error("invalid public key")]
    InvalidPublicKey,

    #[error("invalid secret key")]
    InvalidSecretKey,

    #[error("missing signature algorithm")]
    MissingAlgorithm,

    #[error("unsupported signature algorithm `{0}`")]
    UnsupportedAlgorithm(String),

    #[error("unsupported verification method `{0}`")]
    UnsupportedVerificationMethod(String),

    /// Signature algorithm does not support multi-message signing.
    #[error("too many messages")]
    TooManyMessages,

    /// Signature algorithm requires at least one message.
    #[error("missing message")]
    MissingMessage,
}

impl MessageSignatureError {
    pub fn signature_failed(e: impl ToString) -> Self {
        Self::SignatureFailed(e.to_string())
    }
}

impl From<MessageSignatureError> for SignatureError {
    fn from(value: MessageSignatureError) -> Self {
        match value {
            MessageSignatureError::MissingAlgorithm => Self::MissingAlgorithm,
            MessageSignatureError::UnsupportedAlgorithm(name) => Self::UnsupportedAlgorithm(name),
            MessageSignatureError::InvalidSecretKey => Self::InvalidSecretKey,
            other => Self::other(other),
        }
    }
}

impl From<AlgorithmError> for MessageSignatureError {
    fn from(value: AlgorithmError) -> Self {
        match value {
            AlgorithmError::Missing => Self::MissingAlgorithm,
            AlgorithmError::Unsupported(a) => Self::UnsupportedAlgorithm(a.to_string()),
        }
    }
}

impl From<UnsupportedAlgorithm> for MessageSignatureError {
    fn from(value: UnsupportedAlgorithm) -> Self {
        Self::UnsupportedAlgorithm(value.0.to_string())
    }
}

/// Signature environment.
///
/// This is a common environment implementation expected to work with most
/// claims.
///
/// It is possible to define a custom environment type, as long it implements
/// the accessor traits required for signature.
pub struct SignatureEnvironment<JsonLdLoader = ssi_json_ld::ContextLoader, Eip712Loader = ()> {
    pub json_ld_loader: JsonLdLoader,

    pub eip712_loader: Eip712Loader,
}

impl Default for SignatureEnvironment {
    fn default() -> Self {
        Self {
            json_ld_loader: ssi_json_ld::ContextLoader::default(),
            eip712_loader: (),
        }
    }
}

impl<JsonLdLoader, Eip712Loader> JsonLdLoaderProvider
    for SignatureEnvironment<JsonLdLoader, Eip712Loader>
where
    JsonLdLoader: ssi_json_ld::Loader,
{
    type Loader = JsonLdLoader;

    fn loader(&self) -> &Self::Loader {
        &self.json_ld_loader
    }
}

impl<JsonLdLoader, Eip712Loader> Eip712TypesLoaderProvider
    for SignatureEnvironment<JsonLdLoader, Eip712Loader>
where
    Eip712Loader: ssi_eip712::TypesLoader,
{
    type Loader = Eip712Loader;

    fn eip712_types(&self) -> &Self::Loader {
        &self.eip712_loader
    }
}
