use json_syntax::Parse;
use serde::de::DeserializeOwned;
use ssi_claims_core::{ProofPreparationError, Verifiable};
use ssi_json_ld::JsonLdNodeObject;

use crate::{proof, CryptographicSuiteInput, Proof, ProofConfigurationRefExpansion, Proofs};

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid JSON claims (expected JSON object)")]
    ExpectedJsonObject,

    #[error("missing `proof` property")]
    MissingProof,

    #[error(transparent)]
    DuplicateEntry(#[from] json_syntax::object::DuplicateEntry),

    #[error("parse error: {0}")]
    Parse(json_syntax::parse::Error),

    #[error("deserialization failed: {0}")]
    Deserialization(json_syntax::DeserializeError),

    #[error("proof preparation failed: {0}")]
    ProofPreparation(ProofPreparationError),
}

/// Decodes a Data-Integrity credential or presentation from its JSON binary
/// representation.
pub async fn from_json_slice<T, S, E>(
    json: &[u8],
    environment: E,
) -> Result<Verifiable<T, Proofs<S>>, DecodeError>
where
    T: DeserializeOwned + JsonLdNodeObject,
    S: CryptographicSuiteInput<T, E> + TryFrom<proof::Type>,
    S::VerificationMethod: DeserializeOwned,
    S::Options: DeserializeOwned,
    S::Signature: DeserializeOwned,
    E: for<'a> ProofConfigurationRefExpansion<'a, S>,
{
    from_json(
        json_syntax::Value::parse_slice(json)
            .map_err(DecodeError::Parse)?
            .0,
        environment,
    )
    .await
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn from_json_str<T, S, E>(
    json: &str,
    environment: E,
) -> Result<Verifiable<T, Proofs<S>>, DecodeError>
where
    T: DeserializeOwned + JsonLdNodeObject,
    S: CryptographicSuiteInput<T, E> + TryFrom<proof::Type>,
    S::VerificationMethod: DeserializeOwned,
    S::Options: DeserializeOwned,
    S::Signature: DeserializeOwned,
    E: for<'a> ProofConfigurationRefExpansion<'a, S>,
{
    from_json(json.parse().map_err(DecodeError::Parse)?, environment).await
}

/// Decodes a Data-Integrity credential or presentation from its JSON
/// representation.
pub async fn from_json<T, S, E>(
    json: json_syntax::Value,
    mut environment: E,
) -> Result<Verifiable<T, Proofs<S>>, DecodeError>
where
    T: DeserializeOwned + JsonLdNodeObject,
    S: CryptographicSuiteInput<T, E> + TryFrom<proof::Type>,
    S::VerificationMethod: DeserializeOwned,
    S::Options: DeserializeOwned,
    S::Signature: DeserializeOwned,
    E: for<'a> ProofConfigurationRefExpansion<'a, S>,
{
    use ssi_claims_core::PrepareWith;
    match json {
        json_syntax::Value::Object(mut obj) => match obj.remove_unique("proof")? {
            Some(proof_entry) => {
                let t: T = json_syntax::from_value(json_syntax::Value::Object(obj))
                    .map_err(DecodeError::Deserialization)?;

                let json_proofs = match proof_entry.value {
                    json_syntax::Value::Array(proofs) => proofs,
                    proof => vec![proof],
                };

                let mut proofs = Vec::with_capacity(json_proofs.len());
                for json_proof in json_proofs {
                    let unprepared_proof: Proof<S> = json_syntax::from_value(json_proof)
                        .map_err(DecodeError::Deserialization)?;
                    let proof = unprepared_proof
                        .prepare_with(&t, &mut environment)
                        .await
                        .map_err(DecodeError::ProofPreparation)?;
                    proofs.push(proof);
                }

                Ok(Verifiable::from_parts(t, proofs))
            }
            None => Err(DecodeError::MissingProof),
        },
        _ => Err(DecodeError::ExpectedJsonObject),
    }
}
