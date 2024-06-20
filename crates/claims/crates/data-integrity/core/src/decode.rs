use serde::de::DeserializeOwned;
use ssi_claims_core::{ProofPreparationError, Verifiable, VerifiableClaims};
use ssi_json_ld::JsonLdNodeObject;

use crate::{
    suite::{CryptographicSuiteInstance, DeserializeCryptographicSuiteOwned},
    DataIntegrity, Proofs,
};

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("syntax error: {0}")]
    Syntax(#[from] serde_json::Error),

    #[error("proof preparation failed: {0}")]
    ProofPreparation(#[from] ProofPreparationError),
}

/// Decodes a Data-Integrity credential or presentation from its JSON binary
/// representation.
pub async fn from_json_slice<T, S, E>(
    json: &[u8],
    environment: E,
) -> Result<Verifiable<T, Proofs<S>>, DecodeError>
where
    T: DeserializeOwned + JsonLdNodeObject,
    S: DeserializeCryptographicSuiteOwned + CryptographicSuiteInstance<T, E>,
{
    serde_json::from_slice::<DataIntegrity<T, S>>(json)?
        .into_verifiable_with(environment)
        .await
        .map_err(Into::into)
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn from_json_str<T, S, E>(
    json: &str,
    environment: E,
) -> Result<Verifiable<T, Proofs<S>>, DecodeError>
where
    T: DeserializeOwned + JsonLdNodeObject,
    S: DeserializeCryptographicSuiteOwned + CryptographicSuiteInstance<T, E>,
{
    from_json_slice(json.as_bytes(), environment).await
}
