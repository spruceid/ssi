use linked_data::{
    LinkedData, LinkedDataDeserializeSubject, LinkedDataResource, LinkedDataSubject,
    RdfLiteralType, RdfLiteralValue,
};
use rdf_types::{
    interpretation::{self, ReverseBlankIdInterpretation, ReverseIriInterpretation},
    BlankIdInterpretationMut, ExportedFromVocabulary, Generator, InterpretationMut,
    IriInterpretationMut, IriVocabularyMut, LiteralInterpretationMut, LiteralVocabularyMut,
    ReverseLiteralInterpretation, Vocabulary, VocabularyMut,
};
use ssi_claims_core::Verifiable;
pub use ssi_vc_data_integrity::*;
use std::hash::Hash;

mod any;
pub use any::*;

// pub async fn from_linked_data<G: Generator, U>(
//     generator: G,
//     eip712_types: impl eip712::TypesProvider,
//     input: U,
// ) -> Result<Verifiable<DataIntegrity<U::Data, AnySuite>>, DecodeError<U::Error>>
// where
//     U: DataIntegrityInput<interpretation::WithGenerator<G>>,
//     U::Data: serde::Serialize + LinkedData<interpretation::WithGenerator<G>>,
// {
//     from_linked_data_with(
//         LinkedDataInput {
//             vocabulary: (),
//             interpretation: interpretation::WithGenerator::new((), generator),
//         },
//         eip712_types,
//         input,
//     )
//     .await
// }

// pub async fn from_linked_data_with<'a, I, V, U>(
//     ld_context: LinkedDataInput<I, V>,
//     eip712_types: impl 'a + eip712::TypesProvider,
//     input: U,
// ) -> Result<Verifiable<DataIntegrity<U::Data, AnySuite>>, DecodeError<U::Error>>
// where
//     I: InterpretationMut<V>
//         + IriInterpretationMut<V::Iri>
//         + BlankIdInterpretationMut<V::BlankId>
//         + LiteralInterpretationMut<V::Literal>
//         + ReverseIriInterpretation<Iri = V::Iri>
//         + ReverseBlankIdInterpretation<BlankId = V::BlankId>
//         + ReverseLiteralInterpretation<Literal = V::Literal>,
//     I::Resource: Clone + Eq + Hash,
//     V: Vocabulary + IriVocabularyMut + LiteralVocabularyMut,
//     V::Iri: Clone,
//     V::BlankId: Clone,
//     V::Literal: ExportedFromVocabulary<V, Output = rdf_types::Literal>,
//     V::Value: RdfLiteralValue,
//     V::Type: RdfLiteralType<V>,
//     V::LanguageTag: Clone,
//     Proof<AnySuite>: LinkedDataDeserializeSubject<I, V>,
//     U: DataIntegrityInput<I, V>,
//     U::Data: serde::Serialize + LinkedData<I, V>,
// {
//     DataIntegrity::from_linked_data_with(ld_context, input, |ld| AnyInputContext {
//         ld,
//         loader: eip712_types,
//     })
//     .await
// }

// #[derive(Debug, thiserror::Error)]
// pub enum JsonLdError<E = ssi_json_ld::UnknownContext> {
//     #[error(transparent)]
//     Syntax(json_ld::syntax::parse::Error),

//     #[error(transparent)]
//     Expansion(json_ld::ExpandError<E>),
// }

// pub type AnyVerifiableJsonLd = Verifiable<DataIntegrity<json_ld::Document, AnySuite>>;

// /// Imports a Data Integrity credential from a JSON-LD document.
// ///
// /// This will expand the input document, put it in canonical form, give a
// /// name to all anonymous nodes using `generator` and finally call the
// /// `from_linked_data` function.
// ///
// /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
// /// expansion policy. If it fails to expand a key in the input document,
// /// it will not be ignored and the whole process will fail.
// pub async fn from_json_ld_str_with_defaults(
//     content: &str,
// ) -> Result<AnyVerifiableJsonLd, DecodeError<JsonLdError>> {
//     let mut loader = ssi_json_ld::ContextLoader::default();

//     from_json_ld_str(
//         rdf_types::generator::Blank::default(),
//         (),
//         &mut loader,
//         content,
//     )
//     .await
// }

// /// Imports a Data Integrity credential from a JSON-LD document.
// ///
// /// This will expand the input document, put it in canonical form, give a
// /// name to all anonymous nodes using `generator` and finally call the
// /// `from_linked_data` function.
// ///
// /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
// /// expansion policy. If it fails to expand a key in the input document,
// /// it will not be ignored and the whole process will fail.
// pub async fn from_json_ld_str<'a, G: Generator, L>(
//     generator: G,
//     eip712_types: impl 'a + eip712::TypesProvider,
//     loader: &mut L,
//     content: &str,
// ) -> Result<AnyVerifiableJsonLd, DecodeError<JsonLdError<L::Error>>>
// where
//     L: json_ld::Loader,
//     // TODO those bounds are required because of `json-ld`, and can't be
//     //      avoided until `async fn` in traits are stabilized.
//     L: Send + Sync,
//     L::Error: Send,
// {
//     use json_ld::syntax::Parse;
//     let document = json_ld::RemoteDocumentReference::Loaded(json_ld::RemoteDocument::new(
//         None,
//         None,
//         json_ld::syntax::Value::parse_str(content)
//             .map_err(|e| DecodeError::Input(JsonLdError::Syntax(e)))?
//             .0,
//     ));

//     from_json_ld_with(
//         LinkedDataInput::from_generator(generator),
//         eip712_types,
//         loader,
//         document,
//     )
//     .await
//     .map_err(|e| e.map_input(JsonLdError::Expansion))
// }

// /// Imports a Data Integrity credential from a JSON-LD document.
// ///
// /// This will expand the input document, put it in canonical form, give a
// /// name to all anonymous nodes using `generator` and finally call the
// /// `from_linked_data` function.
// ///
// /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
// /// expansion policy. If it fails to expand a key in the input document,
// /// it will not be ignored and the whole process will fail.
// pub async fn from_json_ld<'a, G: Generator, L>(
//     generator: G,
//     eip712_types: impl 'a + eip712::TypesProvider,
//     loader: &mut L,
//     document: json_ld::RemoteDocumentReference,
// ) -> Result<AnyVerifiableJsonLd, DecodeError<json_ld::ExpandError<L::Error>>>
// where
//     L: json_ld::Loader,
//     // TODO those bounds are required because of `json-ld`, and can't be
//     //      avoided until `async fn` in traits are stabilized.
//     L: Send + Sync,
//     L::Error: Send,
// {
//     from_json_ld_with(
//         LinkedDataInput::from_generator(generator),
//         eip712_types,
//         loader,
//         document,
//     )
//     .await
// }

// /// Imports a Data Integrity credential from a JSON-LD document.
// ///
// /// This will expand the input document, put it in canonical form, give a
// /// name to all anonymous nodes using `generator` and finally call the
// /// `from_linked_data` function.
// ///
// /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
// /// expansion policy. If it fails to expand a key in the input document,
// /// it will not be ignored and the whole process will fail.
// pub async fn from_json_ld_with<'a, I, V, L>(
//     ld_context: LinkedDataInput<I, V>,
//     eip712_types: impl 'a + eip712::TypesProvider,
//     loader: &mut L,
//     document: json_ld::RemoteDocumentReference<V::Iri>,
// ) -> Result<
//     Verifiable<DataIntegrity<json_ld::Document<V::Iri, V::BlankId>, AnySuite>>,
//     DecodeError<json_ld::ExpandError<L::Error>>,
// >
// where
//     I: InterpretationMut<V>
//         + IriInterpretationMut<V::Iri>
//         + BlankIdInterpretationMut<V::BlankId>
//         + LiteralInterpretationMut<V::Literal>
//         + ReverseIriInterpretation<Iri = V::Iri>
//         + ReverseBlankIdInterpretation<BlankId = V::BlankId>
//         + ReverseLiteralInterpretation<Literal = V::Literal>,
//     I::Resource: Clone + Eq + Hash,
//     V: VocabularyMut,
//     V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
//     V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
//     V::Literal: ExportedFromVocabulary<V, Output = rdf_types::Literal>,
//     V::Value: RdfLiteralValue,
//     V::Type: RdfLiteralType<V>,
//     V::LanguageTag: Clone,
//     Proof<AnySuite>: LinkedDataDeserializeSubject<I, V>,
//     L: json_ld::Loader<V::Iri>,
//     // TODO those bounds are required because of `json-ld`, and can't be
//     //      avoided until `async fn` in traits are stabilized.
//     V: Send + Sync,
//     V::Iri: Send + Sync,
//     V::BlankId: Send + Sync,
//     L: Send + Sync,
//     L::Error: Send,
// {
//     DataIntegrity::from_json_ld_with(ld_context, loader, document, |ld| AnyInputContext {
//         ld,
//         loader: eip712_types,
//     })
//     .await
// }

// /// Imports a Data Integrity credential from a JSON-LD document.
// ///
// /// This will expand the input document, put it in canonical form, give a
// /// name to all anonymous nodes using `generator` and finally call the
// /// `from_linked_data` function.
// ///
// /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
// /// expansion policy. If it fails to expand a key in the input document,
// /// it will not be ignored and the whole process will fail.
// pub async fn deserialize_from_json_ld<'a, T, G: Generator, L>(
//     generator: G,
//     eip712_types: impl 'a + eip712::TypesProvider,
//     loader: &mut L,
//     document: json_ld::RemoteDocumentReference,
// ) -> Result<Verifiable<DataIntegrity<T, AnySuite>>, DecodeError<json_ld::ExpandError<L::Error>>>
// where
//     Proof<AnySuite>: LinkedDataDeserializeSubject<interpretation::WithGenerator<G>>,
//     L: json_ld::Loader,
//     T: serde::Serialize
//         + LinkedData<interpretation::WithGenerator<G>>
//         + LinkedDataDeserializeSubject<interpretation::WithGenerator<G>>,
//     // TODO those bounds are required because of `json-ld`, and can't be
//     //      avoided until `async fn` in traits are stabilized.
//     L: Send + Sync,
//     L::Error: Send,
// {
//     DataIntegrity::deserialize_from_json_ld_with(
//         LinkedDataInput::from_generator(generator),
//         loader,
//         document,
//         |ld| AnyInputContext {
//             ld,
//             loader: eip712_types,
//         },
//     )
//     .await
// }

// /// Imports a Data Integrity credential from a JSON-LD document.
// ///
// /// This will expand the input document, put it in canonical form, give a
// /// name to all anonymous nodes using `generator` and finally call the
// /// `from_linked_data` function.
// ///
// /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
// /// expansion policy. If it fails to expand a key in the input document,
// /// it will not be ignored and the whole process will fail.
// pub async fn deserialize_from_json_ld_with<'a, T, I, V, L>(
//     ld_context: LinkedDataInput<I, V>,
//     eip712_types: impl 'a + eip712::TypesProvider,
//     loader: &mut L,
//     document: json_ld::RemoteDocumentReference<V::Iri>,
// ) -> Result<Verifiable<DataIntegrity<T, AnySuite>>, DecodeError<json_ld::ExpandError<L::Error>>>
// where
//     I: InterpretationMut<V>
//         + IriInterpretationMut<V::Iri>
//         + BlankIdInterpretationMut<V::BlankId>
//         + LiteralInterpretationMut<V::Literal>
//         + ReverseIriInterpretation<Iri = V::Iri>
//         + ReverseBlankIdInterpretation<BlankId = V::BlankId>
//         + ReverseLiteralInterpretation<Literal = V::Literal>,
//     I::Resource: Clone + Eq + Hash,
//     V: VocabularyMut,
//     V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
//     V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
//     V::Literal: ExportedFromVocabulary<V, Output = rdf_types::Literal>,
//     V::Value: RdfLiteralValue,
//     V::Type: RdfLiteralType<V>,
//     V::LanguageTag: Clone,
//     Proof<AnySuite>: LinkedDataDeserializeSubject<I, V>,
//     L: json_ld::Loader<V::Iri>,
//     T: serde::Serialize + LinkedData<I, V> + LinkedDataDeserializeSubject<I, V>,
//     // TODO those bounds are required because of `json-ld`, and can't be
//     //      avoided until `async fn` in traits are stabilized.
//     V: Send + Sync,
//     V::Iri: Send + Sync,
//     V::BlankId: Send + Sync,
//     L: Send + Sync,
//     L::Error: Send,
// {
//     DataIntegrity::deserialize_from_json_ld_with(ld_context, loader, document, |ld| {
//         AnyInputContext {
//             ld,
//             loader: eip712_types,
//         }
//     })
//     .await
// }
