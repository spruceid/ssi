use core::fmt;

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
}

impl From<std::convert::Infallible> for SignatureError {
    fn from(_value: std::convert::Infallible) -> Self {
        unreachable!()
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
