mod any;
use std::hash::Hash;

pub use any::*;
use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::{
    InterpretationMut, ReverseBlankIdInterpretation, ReverseIriInterpretation,
    ReverseLiteralInterpretation, VocabularyMut,
};
use ssi_claims_core::Verifiable;
use ssi_json_ld::AnyJsonLdEnvironment;
use ssi_vc_core::{verification::Claims, JsonCredential};

pub use ssi_vc_data_integrity::*;

/// Any Data-Integrity proof known by this library.
pub type AnyProof = Proof<AnySuite>;

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn any_credential_from_json_str(
    json: &str,
) -> Result<Verifiable<Claims<JsonCredential, Proof<AnySuite>>>, DecodeError> {
    any_credential_from_json_str_with(json, AnyInputContext::default()).await
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn any_credential_from_json_str_with<V, I, L, E, Y>(
    json: &str,
    environment: AnyInputContext<E, Y>,
) -> Result<Verifiable<Claims<JsonCredential, Proof<AnySuite>>>, DecodeError>
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Interpretation = I, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    I: InterpretationMut<V>
        + ReverseIriInterpretation<Iri = V::Iri>
        + ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + ReverseLiteralInterpretation<Literal = V::Literal>,
    L: json_ld::Loader<V::Iri>,
    Y: ssi_vc_data_integrity::eip712::TypesProvider,
    //
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send,
{
    ssi_vc_data_integrity::from_json_str(json, environment).await
}
