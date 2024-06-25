use serde::de::DeserializeOwned;
use ssi_claims_core::ProofPreparationError;
use ssi_json_ld::JsonLdNodeObject;

use crate::{suite::DeserializeCryptographicSuiteOwned, DataIntegrity};

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("syntax error: {0}")]
    Syntax(#[from] serde_json::Error),

    #[error("proof preparation failed: {0}")]
    ProofPreparation(#[from] ProofPreparationError),
}

/// Decodes a Data-Integrity credential or presentation from its JSON binary
/// representation.
pub fn from_json_slice<T, S>(json: &[u8]) -> Result<DataIntegrity<T, S>, DecodeError>
where
    T: DeserializeOwned + JsonLdNodeObject,
    S: DeserializeCryptographicSuiteOwned,
{
    serde_json::from_slice::<DataIntegrity<T, S>>(json).map_err(Into::into)
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub fn from_json_str<T, S>(json: &str) -> Result<DataIntegrity<T, S>, DecodeError>
where
    T: DeserializeOwned + JsonLdNodeObject,
    S: DeserializeCryptographicSuiteOwned,
{
    from_json_slice(json.as_bytes())
}
