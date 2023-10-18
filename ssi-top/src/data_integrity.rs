mod input;
mod options;
mod protocol;
mod suite;

use std::hash::Hash;

pub use input::*;
use linked_data::{LinkedData, LinkedDataDeserializeSubject, RdfLiteralType, RdfLiteralValue};
pub use options::*;
pub use protocol::*;
use rdf_types::{
    interpretation::{self, ReverseBlankIdInterpretation, ReverseIriInterpretation},
    BlankIdInterpretationMut, ExportedFromVocabulary, Generator, InterpretationMut,
    IriInterpretationMut, IriVocabularyMut, LiteralInterpretationMut, LiteralVocabularyMut,
    ReverseLiteralInterpretation, Vocabulary,
};
use ssi_vc::Verifiable;
use ssi_vc_ldp::{eip712, DataIntegrity, DataIntegrityInput, DecodeError, LinkedDataInput, Proof};
pub use suite::*;

pub async fn any_from_linked_data<G: Generator, U>(
    generator: G,
    eip712_types: impl eip712::TypesProvider,
    input: U,
) -> Result<Verifiable<DataIntegrity<U::Data, AnySuite>>, DecodeError<U::Error>>
where
    U: DataIntegrityInput<interpretation::WithGenerator<G>>,
    U::Data: serde::Serialize + LinkedData<interpretation::WithGenerator<G>>,
{
    any_from_linked_data_with(
        LinkedDataInput {
            vocabulary: (),
            interpretation: interpretation::WithGenerator::new((), generator),
        },
        eip712_types,
        input,
    )
    .await
}

pub async fn any_from_linked_data_with<'a, I, V, U>(
    ld_context: LinkedDataInput<I, V>,
    eip712_types: impl 'a + eip712::TypesProvider,
    input: U,
) -> Result<Verifiable<DataIntegrity<U::Data, AnySuite>>, DecodeError<U::Error>>
where
    I: InterpretationMut<V>
        + IriInterpretationMut<V::Iri>
        + BlankIdInterpretationMut<V::BlankId>
        + LiteralInterpretationMut<V::Literal>
        + ReverseIriInterpretation<Iri = V::Iri>
        + ReverseBlankIdInterpretation<BlankId = V::BlankId>
        + ReverseLiteralInterpretation<Literal = V::Literal>,
    I::Resource: Clone + Eq + Hash,
    V: Vocabulary + IriVocabularyMut + LiteralVocabularyMut,
    V::Iri: Clone,
    V::BlankId: Clone,
    V::Literal: ExportedFromVocabulary<V, Output = rdf_types::Literal>,
    V::Value: RdfLiteralValue,
    V::Type: RdfLiteralType<V>,
    V::LanguageTag: Clone,
    Proof<AnySuite>: LinkedDataDeserializeSubject<I, V>,
    U: DataIntegrityInput<I, V>,
    U::Data: serde::Serialize + LinkedData<I, V>,
{
    DataIntegrity::from_linked_data(ld_context, input, |ld| AnyInputContext {
        ld,
        loader: eip712_types,
    })
    .await
}

// /// Imports a Data Integrity credential from a JSON-LD document.
// ///
// /// This will expand the input document, put it in canonical form, give a
// /// name to all anonymous nodes using `generator` and finally call the
// /// `from_linked_data` function.
// ///
// /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
// /// expansion policy. If it fails to expand a key in the input document,
// /// it will not be ignored and the whole process will fail.
// pub async fn any_from_json_ld<'a, I, V, L, X>(
//     vocabulary: &mut V,
//     interpretation: &mut I,
//     loader: &mut L,
//     input: json_ld::RemoteDocumentReference<V::Iri>,
//     make_context: impl FnOnce(&mut V, &mut I) -> X,
// ) -> Result<Verifiable<Self>, FromJsonLdError<L::Error, L::ContextError>>
// where
//     I: InterpretationMut
//         + IriInterpretationMut<V::Iri>
//         + BlankIdInterpretationMut<V::BlankId>
//         + LiteralInterpretationMut<V::Literal>,
//     I::Resource: Clone + Eq + Hash,
//     V: VocabularyMut,
//     V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
//     V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
//     V::Value: RdfLiteralValue,
//     V::Type: RdfLiteralType<V>,
//     V::LanguageTag: Clone,
//     Proof<S>: LinkedDataDeserializeSubject<I, V>,
//     C: LinkedDataDeserializeSubject<I, V>,
//     S: CryptographicSuiteInput<C, X>,
//     L: json_ld::Loader<V::Iri> + json_ld::ContextLoader<V::Iri>,
//     L::Output: Into<json_ld::syntax::Value>,
//     // TODO find a way to hide that bound, if possible.
//     for<'m> <S::VerificationMethod as Referencable>::Reference<'m>: VerificationMethodRef<'m>,
//     // TODO those bounds are required because of `json-ld`, and can't be
//     //      avoided until `async fn` in traits are stabilized.
//     V: Send + Sync,
//     V::Iri: Send + Sync,
//     V::BlankId: Send + Sync,
//     L: Send + Sync,
//     L::Error: Send,
//     L::ContextError: Send;
