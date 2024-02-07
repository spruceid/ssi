mod any;
use std::hash::Hash;

pub use any::*;
use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::{BlankIdInterpretationMut, InterpretationMut, IriInterpretationMut, LiteralInterpretationMut, ReverseBlankIdInterpretation, ReverseIriInterpretation, ReverseLiteralInterpretation, VocabularyMut};
use ssi_claims_core::Verifiable;
use ssi_rdf::Expanded;
use ssi_json_ld::{AnyJsonLdEnvironment, JsonLdError, UnknownContext};
use ssi_vc_core::{syntax::JsonCredential, verification::Claims};
use ssi_vc_data_integrity::{DecodeError, Proof};

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn any_credential_from_json_str_default(
    json: &str
) -> Result<Verifiable<Claims<Expanded<JsonCredential>, Proof<AnySuite>>>, DecodeError<JsonLdError<UnknownContext>>> {
    any_credential_from_json_str(json, AnyInputContext::default()).await
}

/// Decodes a Data-Integrity credential or presentation from its JSON textual
/// representation.
pub async fn any_credential_from_json_str<V, I, L, E, Y>(
    json: &str,
    environment: AnyInputContext<E, Y>
) -> Result<Verifiable<Claims<Expanded<JsonCredential, I::Resource>, Proof<AnySuite>>>, DecodeError<JsonLdError<L::Error>>>
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Interpretation = I, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::LanguageTag: Clone,
    V::Value: From<String> + From<xsd_types::Value> + From<json_syntax::Value>,
    V::Type: From<rdf_types::literal::Type<V::Iri, V::LanguageTag>>,
    V::Literal: rdf_types::ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    I: InterpretationMut<V>
        + IriInterpretationMut<V::Iri> + ReverseIriInterpretation<Iri = V::Iri>
        + BlankIdInterpretationMut<V::BlankId> + ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + LiteralInterpretationMut<V::Literal> + ReverseLiteralInterpretation<Literal = V::Literal>,
    I::Resource: Clone + Ord + Hash + LinkedDataResource<I, V>,
    L: json_ld::Loader<V::Iri>,
    Y: ssi_vc_data_integrity::eip712::TypesProvider,
    //
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send
{
    ssi_vc_data_integrity::expand_from_json_str(
        json,
        environment
    ).await
}