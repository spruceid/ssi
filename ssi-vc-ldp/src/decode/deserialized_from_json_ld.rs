use std::{hash::Hash, marker::PhantomData};
use std::pin::Pin;
use std::future::Future;
use std::task;

use json_ld::{RemoteDocumentReference, Loader, ContextLoader};
use linked_data::{LinkedDataResource, LinkedDataSubject, LinkedDataDeserializeSubject, RdfLiteralValue, RdfLiteralType};
use locspan::Meta;
use rdf_types::{Interpretation, Vocabulary, VocabularyMut, InterpretationMut, IriInterpretationMut, BlankIdInterpretationMut, LiteralInterpretationMut, IriVocabularyMut, LiteralVocabularyMut, LanguageTagVocabularyMut};
use ssi_core::futures::LendingMutFuture;

use super::{DataIntegrityInput, DecodeError};

/// Deserialized JSON-LD Data-Integrity input.
/// 
/// This is a simple wrapper around [`RemoteDocumentReference<I>`] that adds
/// the ability to expand and extract a Data-Integrity proof from the wrapped
/// (remote) JSON-LD document. The resulting proof-less expanded document is
/// then deserialized (using `LinkedDataDeserializeSubject`) into `T`.
pub struct DeserializedJsonLdInput<'l, I, L, T> {
    document: RemoteDocumentReference<I>,
    loader: &'l mut L,
	t: PhantomData<T>
}

impl<'l, I, L, T> DeserializedJsonLdInput<'l, I, L, T> {
    pub fn new(
        loader: &'l mut L,
        document: RemoteDocumentReference<I>
    ) -> Self {
        Self {
            document,
            loader,
            t: PhantomData
        }
    }
}

impl<'l, T, I: Interpretation, V: Vocabulary, L> DataIntegrityInput<I, V> for DeserializedJsonLdInput<'l, V::Iri, L, T>
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
    L: Loader<V::Iri> + ContextLoader<V::Iri>,
    L::Output: Into<json_ld::syntax::Value>,
    T: LinkedDataDeserializeSubject<I, V>,
    // Required by `json-ld` for now
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send,
    L::ContextError: Send
{
    type Error = json_ld::ExpandError<(), L::Error, L::ContextError>;

    type Data = T;

    type Proof = json_ld::Node<V::Iri, V::BlankId>;

    type ExtractProof<'a> = ExtractJsonLdProof<'a, I, V, L, T> where Self: 'a, V: 'a, I: 'a;
    
    fn extract_proof<'a>(
        self,
        vocabulary: &'a mut V,
        interpretation: &'a mut I
    ) -> Self::ExtractProof<'a> where Self: 'a {
        let options = json_ld::Options {
            expansion_policy: json_ld::expansion::Policy::Strictest,
            ..Default::default()
        };

        ExtractJsonLdProof {
            extract: LendingMutFuture::new((vocabulary, interpretation), |(vocabulary, interpretation)| {
                super::from_json_ld::ExtractJsonLdProof::new(
                    vocabulary,
                    interpretation,
                    self.loader,
                    self.document,
                    options
                )
            }),
			t: PhantomData
        }
    }
}

#[pin_project::pin_project]
pub struct ExtractJsonLdProof<'a, I: Interpretation, V: Vocabulary, L, T>
where
    V::Iri: Send,
    L: Loader<V::Iri> + ContextLoader<V::Iri>
{
    #[pin]
    extract: LendingMutFuture<super::from_json_ld::ExtractJsonLdProof<'a, I, V, L>, (&'a mut V, &'a mut I)>,
	t: PhantomData<T>
}

impl<'a, V: 'a + Vocabulary, I: Interpretation, L, T> Future for ExtractJsonLdProof<'a, I, V, L, T>
where
    I: InterpretationMut<V>
        + IriInterpretationMut<V::Iri>
        + BlankIdInterpretationMut<V::BlankId>
        + LiteralInterpretationMut<V::Literal>,
    I::Resource: Clone + Eq + Hash,
    V: IriVocabularyMut + LiteralVocabularyMut + LanguageTagVocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::Value: RdfLiteralValue,
    V::Type: RdfLiteralType<V>,
    V::LanguageTag: Clone,
    L: Loader<V::Iri> + ContextLoader<V::Iri>,
    T: LinkedDataDeserializeSubject<I, V>,
    // Required by `json-ld` for now
    V::Iri: Send,
{
    type Output = Result<(T, json_ld::Node<V::Iri, V::BlankId>), DecodeError<json_ld::ExpandError<(), L::Error, L::ContextError>>>;

    fn poll(self: Pin<&mut Self>, cx: &mut task::Context<'_>) -> task::Poll<Self::Output> {
        let this = self.project();

        this.extract.poll(cx).map(|(r, (vocabulary, interpretation))| {
            let (json_ld, proof) = r?;
            
            match json_ld.into_expanded().into_value().into_main_node() {
                Some(Meta(node, _)) => {
                    let (subject, quads) = linked_data::to_interpreted_subject_quads(
                        vocabulary,
                        interpretation,
                        None,
                        &node
                    ).unwrap();

                    let dataset: grdf::HashDataset<I::Resource> = quads.into_iter().collect();

                    let data = T::deserialize_subject(
                        vocabulary,
                        interpretation,
                        &dataset,
                        dataset.default_graph(),
                        &subject
                    ).unwrap();

                    Ok((data, proof))
                }
                None => Err(DecodeError::MissingSubject)
            }
        })
    }
}