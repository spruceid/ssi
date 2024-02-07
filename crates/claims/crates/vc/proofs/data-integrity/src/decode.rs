use serde::Deserialize;
use ssi_claims_core::Verifiable;
use ssi_rdf::{Expandable, Expanded};
use ssi_vc_core::verification::Claims;

use crate::{proof, CryptographicSuite, CryptographicSuiteInput, Proof, ProofPreparationError};

#[derive(Debug, thiserror::Error)]
pub enum DecodeError<E = std::convert::Infallible> {
    #[error("invalid JSON claims (expected JSON object)")]
    ExpectedJsonObject,

    #[error("missing `proof` property")]
    MissingProof,

    #[error("deserialization failed: {0}")]
    Deserialization(serde_json::Error),

    #[error("expansion error: {0}")]
    Expansion(E),

    #[error("proof preparation failed: {0}")]
    ProofPreparation(ProofPreparationError),
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn from_json_str<T, S: CryptographicSuite, E>(
    json: &str,
    environment: E,
) -> Result<Verifiable<Claims<T, Proof<S>>>, DecodeError>
where
    T: for<'a> Deserialize<'a>,
    S: CryptographicSuiteInput<T, E>,
    S: From<proof::Type>,
    S::VerificationMethod: for<'a> Deserialize<'a>,
    S::Options: for<'a> Deserialize<'a>,
    S::Signature: for<'a> Deserialize<'a>,
{
    from_json(
        json.parse().map_err(DecodeError::Deserialization)?,
        environment,
    )
    .await
}

/// Decodes a Data-Integrity credential or presentation from its JSON
/// representation.
pub async fn from_json<T, S: CryptographicSuite, E>(
    json: serde_json::Value,
    mut environment: E,
) -> Result<Verifiable<Claims<T, Proof<S>>>, DecodeError>
where
    T: for<'a> Deserialize<'a>,
    S: CryptographicSuiteInput<T, E>,
    S: From<proof::Type>,
    S::VerificationMethod: for<'a> Deserialize<'a>,
    S::Options: for<'a> Deserialize<'a>,
    S::Signature: for<'a> Deserialize<'a>,
{
    use ssi_vc_core::verification::PrepareWith;
    match json {
        serde_json::Value::Object(mut obj) => match obj.remove("proof") {
            Some(proof_value) => {
                let t: T = serde_json::from_value(serde_json::Value::Object(obj))
                    .map_err(DecodeError::Deserialization)?;

                let json_proofs = match proof_value {
                    serde_json::Value::Array(proofs) => proofs,
                    proof => vec![proof],
                };

                let mut proofs = Vec::with_capacity(json_proofs.len());
                for json_proof in json_proofs {
                    let unprepared_proof: Proof<S> =
                        serde_json::from_value(json_proof).map_err(DecodeError::Deserialization)?;
                    let proof = unprepared_proof
                        .prepare_with(&t, &mut environment)
                        .await
                        .map_err(DecodeError::ProofPreparation)?;
                    proofs.push(proof);
                }

                Ok(Verifiable::new(Claims::from_proofless(t), proofs))
            }
            None => Err(DecodeError::MissingProof),
        },
        _ => Err(DecodeError::ExpectedJsonObject),
    }
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn expand_from_json_str<T, S: CryptographicSuite, E>(
    json: &str,
    environment: E,
) -> Result<Verifiable<Claims<Expanded<T, T::Resource>, Proof<S>>>, DecodeError<T::Error>>
where
    T: for<'a> Deserialize<'a> + Expandable<E>,
    S: CryptographicSuiteInput<Expanded<T, T::Resource>, E>,
    S: TryFrom<proof::Type>,
    S::VerificationMethod: for<'a> Deserialize<'a>,
    S::Options: for<'a> Deserialize<'a>,
    S::Signature: for<'a> Deserialize<'a>,
{
    expand_from_json(
        json.parse().map_err(DecodeError::Deserialization)?,
        environment,
    )
    .await
}

/// Decodes a Data-Integrity credential or presentation from its JSON
/// representation and expand it to have access to the Linked-Data dataset it
/// represents.
pub async fn expand_from_json<T, S: CryptographicSuite, E>(
    json: serde_json::Value,
    mut environment: E,
) -> Result<Verifiable<Claims<Expanded<T, T::Resource>, Proof<S>>>, DecodeError<T::Error>>
where
    T: for<'a> Deserialize<'a> + Expandable<E>,
    S: CryptographicSuiteInput<Expanded<T, T::Resource>, E>,
    S: TryFrom<proof::Type>,
    S::VerificationMethod: for<'a> Deserialize<'a>,
    S::Options: for<'a> Deserialize<'a>,
    S::Signature: for<'a> Deserialize<'a>,
{
    use ssi_vc_core::verification::PrepareWith;
    match json {
        serde_json::Value::Object(mut obj) => match obj.remove("proof") {
            Some(proof_value) => {
                let t: T = serde_json::from_value(serde_json::Value::Object(obj))
                    .map_err(DecodeError::Deserialization)?;
                let expanded = t
                    .expand(&mut environment)
                    .await
                    .map_err(DecodeError::Expansion)?;

                let json_proofs = match proof_value {
                    serde_json::Value::Array(proofs) => proofs,
                    proof => vec![proof],
                };

                let mut proofs = Vec::with_capacity(json_proofs.len());
                for json_proof in json_proofs {
                    let unprepared_proof: Proof<S> =
                        serde_json::from_value(json_proof).map_err(DecodeError::Deserialization)?;
                    let proof = unprepared_proof
                        .prepare_with(&expanded, &mut environment)
                        .await
                        .map_err(DecodeError::ProofPreparation)?;
                    proofs.push(proof);
                }

                Ok(Verifiable::new(Claims::from_proofless(expanded), proofs))
            }
            None => Err(DecodeError::MissingProof),
        },
        _ => Err(DecodeError::ExpectedJsonObject),
    }
}
