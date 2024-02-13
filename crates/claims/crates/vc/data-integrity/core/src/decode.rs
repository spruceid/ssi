use std::hash::Hash;

use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::{
    ExportedFromVocabulary, InterpretationMut, IriVocabulary, Literal,
    ReverseBlankIdInterpretation, ReverseIriInterpretation, ReverseLiteralInterpretation,
    VocabularyMut,
};
use serde::{de::DeserializeOwned, Deserialize};
use ssi_claims_core::Verifiable;
use ssi_core::Referencable;
use ssi_json_ld::{AnyJsonLdEnvironment, WithJsonLdContext};
use ssi_vc_core::verification::Claims;

use crate::{
    proof, CryptographicSuite, CryptographicSuiteInput, Proof, ProofConfigurationRefExpansion,
    ProofPreparationError,
};

#[derive(Debug, thiserror::Error)]
pub enum DecodeError<E = ssi_json_ld::UnknownContext> {
    #[error("invalid JSON claims (expected JSON object)")]
    ExpectedJsonObject,

    #[error("missing `proof` property")]
    MissingProof,

    #[error("deserialization failed: {0}")]
    Deserialization(serde_json::Error),

    #[error("proof preparation failed: {0}")]
    ProofPreparation(ProofPreparationError<E>),
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn from_json_str<T, S: CryptographicSuite, E>(
    json: &str,
    environment: E,
) -> Result<Verifiable<Claims<T, Proof<S>>>, DecodeError<E::LoadError>>
where
    T: DeserializeOwned + WithJsonLdContext,
    S: CryptographicSuiteInput<T, E> + TryFrom<proof::Type>,
    S::VerificationMethod: DeserializeOwned,
    S::Options: DeserializeOwned,
    S::Signature: DeserializeOwned,
    E: for<'a> ProofConfigurationRefExpansion<'a, S>,
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
) -> Result<Verifiable<Claims<T, Proof<S>>>, DecodeError<E::LoadError>>
where
    T: DeserializeOwned + WithJsonLdContext,
    S: CryptographicSuiteInput<T, E> + TryFrom<proof::Type>,
    S::VerificationMethod: DeserializeOwned,
    S::Options: DeserializeOwned,
    S::Signature: DeserializeOwned,
    E: for<'a> ProofConfigurationRefExpansion<'a, S>,
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
