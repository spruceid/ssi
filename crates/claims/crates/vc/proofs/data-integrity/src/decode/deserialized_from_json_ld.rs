use std::{hash::Hash, marker::PhantomData};

use json_ld::{Loader, RemoteDocumentReference};
use linked_data::{
    LinkedDataDeserializeSubject, LinkedDataResource, LinkedDataSubject, RdfLiteralType,
    RdfLiteralValue,
};
use rdf_types::{
    BlankIdInterpretationMut, Interpretation, InterpretationMut, IriInterpretationMut,
    LiteralInterpretationMut, Vocabulary, VocabularyMut,
};

use crate::from_json_ld::extract_json_ld_proof;

use super::{DataIntegrityInput, DecodeError};

/// Deserialized JSON-LD Data-Integrity input.
///
/// This is a simple wrapper around [`RemoteDocumentReference<I>`] that adds
/// the ability to expand and extract a Data-Integrity proof from the wrapped
/// (remote) JSON-LD document. The resulting proof-less expanded document is
/// then deserialized (using `LinkedDataDeserializeSubject`) into `T`.
pub struct DeserializedJsonLdInput<'l, I, L, T> {
    /// Remote JSON-LD document.
    document: RemoteDocumentReference<I>,

    /// Document loader (to fetch the remote document).
    loader: &'l mut L,

    /// Target type, not yet realized.
    t: PhantomData<T>,
}

impl<'l, I, L, T> DeserializedJsonLdInput<'l, I, L, T> {
    pub fn new(loader: &'l mut L, document: RemoteDocumentReference<I>) -> Self {
        Self {
            document,
            loader,
            t: PhantomData,
        }
    }
}

impl<'l, T, I: Interpretation, V: Vocabulary, L> DataIntegrityInput<I, V>
    for DeserializedJsonLdInput<'l, V::Iri, L, T>
where
    I: InterpretationMut<V>
        + IriInterpretationMut<V::Iri>
        + BlankIdInterpretationMut<V::BlankId>
        + LiteralInterpretationMut<V::Literal>,
    I::Resource: Clone + Eq + Hash,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::Value: RdfLiteralValue,
    V::Type: RdfLiteralType<V>,
    V::LanguageTag: Clone,
    L: Loader<V::Iri>,
    T: LinkedDataDeserializeSubject<I, V>,
    // Required by `json-ld` for now
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send,
{
    type Error = json_ld::ExpandError<L::Error>;

    type Data = T;

    type Proof = json_ld::Node<V::Iri, V::BlankId>;

    async fn extract_proof<'a>(
        self,
        vocabulary: &'a mut V,
        interpretation: &'a mut I,
    ) -> Result<(Self::Data, Self::Proof), DecodeError<Self::Error>>
    where
        Self: 'a,
    {
        let options = json_ld::Options {
            expansion_policy: json_ld::expansion::Policy::Strictest,
            ..Default::default()
        };

        let (json_ld, proof) =
            extract_json_ld_proof(vocabulary, self.loader, self.document, options).await?;

        match json_ld.into_expanded().into_main_node() {
            Some(node) => {
                let (subject, quads) = linked_data::to_interpreted_subject_quads(
                    vocabulary,
                    interpretation,
                    None,
                    &node,
                )
                .unwrap();

                let dataset: grdf::HashDataset<I::Resource> = quads.into_iter().collect();

                let data = T::deserialize_subject(
                    vocabulary,
                    interpretation,
                    &dataset,
                    dataset.default_graph(),
                    &subject,
                )
                .unwrap();

                Ok((data, proof))
            }
            None => Err(DecodeError::MissingSubject),
        }
    }
}
