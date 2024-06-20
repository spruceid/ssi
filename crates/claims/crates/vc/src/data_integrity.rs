use std::hash::Hash;

use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::{
    interpretation::{
        ReverseBlankIdInterpretation, ReverseIriInterpretation, ReverseLiteralInterpretation,
    },
    InterpretationMut, VocabularyMut,
};
use ssi_claims_core::Verifiable;
use ssi_data_integrity::{AnyInputContext, AnySuite, DecodeError, Proofs};
use ssi_json_ld::AnyJsonLdEnvironment;

use crate::{JsonCredential, SpecializedJsonCredential};

/// Decodes a Data-Integrity credential or presentation from its JSON binary
/// representation.
pub async fn any_credential_from_json_slice(
    json: &[u8],
) -> Result<Verifiable<SpecializedJsonCredential, Proofs<AnySuite>>, DecodeError> {
    any_credential_from_json_slice_with(json, AnyInputContext::default()).await
}

/// Decodes a Data-Integrity credential or presentation from its JSON binary
/// representation.
pub async fn any_credential_from_json_slice_with<
    V,
    I,
    L,
    E,
    Y: ssi_data_integrity::suites::eip712::TypesProvider,
>(
    json: &[u8],
    environment: AnyInputContext<E, Y>,
) -> Result<Verifiable<SpecializedJsonCredential, Proofs<AnySuite>>, DecodeError>
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Interpretation = I, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    I: InterpretationMut<V>
        + ReverseIriInterpretation<Iri = V::Iri>
        + ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + ReverseLiteralInterpretation<Literal = V::Literal>,
    I::Resource: Clone,
    L: json_ld::Loader<V::Iri>,
    L::Error: std::fmt::Display,
{
    ssi_data_integrity::from_json_slice(json, environment).await
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn any_credential_from_json_str(
    json: &str,
) -> Result<Verifiable<JsonCredential, Proofs<AnySuite>>, DecodeError> {
    any_credential_from_json_str_with(json, AnyInputContext::default()).await
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn any_credential_from_json_str_with<
    V,
    I,
    L,
    E,
    Y: ssi_data_integrity::suites::eip712::TypesProvider,
>(
    json: &str,
    environment: AnyInputContext<E, Y>,
) -> Result<Verifiable<JsonCredential, Proofs<AnySuite>>, DecodeError>
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Interpretation = I, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    I: InterpretationMut<V>
        + ReverseIriInterpretation<Iri = V::Iri>
        + ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + ReverseLiteralInterpretation<Literal = V::Literal>,
    I::Resource: Clone,
    L: json_ld::Loader<V::Iri>,
    L::Error: std::fmt::Display,
{
    ssi_data_integrity::from_json_str(json, environment).await
}
