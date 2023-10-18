// pub mod rdf;
use std::hash::Hash;
use std::pin::Pin;
use futures::Future;
use iref::Iri;
use locspan::{Stripped, Meta};
use json_ld::{RemoteDocumentReference, IntoDocumentResult, Loader, ContextLoader};
use linked_data::{FromLinkedDataError, LinkedDataDeserializeSubject, LinkedDataResource, LinkedDataSubject, IntoQuadsError, RdfLiteralValue, RdfLiteralType, LinkedDataGraph};
use rdf_types::{
    Triple, VocabularyMut, Vocabulary, IriVocabularyMut, InterpretationMut, IriInterpretationMut, BlankIdInterpretationMut, LiteralInterpretationMut, LiteralVocabularyMut, Interpretation, LanguageTagVocabularyMut, BlankIdVocabularyMut, Generator, interpretation
};
use ssi_vc::Verifiable;
use static_iref::iri;
use crate::{
    suite::{CryptographicSuiteInput, HashError, TransformError},
    CryptographicSuite, DataIntegrity, Proof, LinkedDataInput,
};

#[derive(Debug, thiserror::Error)]
pub enum DecodeError<I> {
    #[error("invalid linked-data: `{0}`")]
    InvalidLinkedData(IntoQuadsError),

    #[error("missing subject")]
    MissingSubject,

    #[error("missing proof")]
    MissingProof,

    #[error("missing proof graph")]
    MissingProofGraph,

    #[error("missing proof value")]
    MissingProofValue,

    #[error("invalid proof")]
    InvalidProof(FromLinkedDataError),

    #[error("invalid credential")]
    InvalidCredential(FromLinkedDataError),

    #[error("input transformation failed: {0}")]
    Transform(#[from] TransformError),

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),
    
    #[error(transparent)]
    Input(I)
}

type HashDataset<T> = grdf::HashDataset<T, T, T, T>;

const PROOF_IRI: &Iri = iri!("https://w3id.org/security#proof");
const PROOF_VALUE_IRI: &Iri = iri!("https://w3id.org/security#proofValue");

/// Data-Integrity input document.
/// 
/// This trait is implemented by any type that represents a Data-Integrity
/// credential or presentation with the embedded proof. It provides a method to
/// extract the Data-Integrity proof from the document.
pub trait DataIntegrityInput<I: Interpretation = (), V: Vocabulary = ()> {
    type Error;

    type Data;
    
    type Proof: LinkedDataGraph<I, V> + LinkedDataResource<I, V>;

    type ExtractProof<'a>: 'a + Future<Output = Result<(Self::Data, Self::Proof), DecodeError<Self::Error>>> where Self: 'a, V: 'a, I: 'a;

    fn extract_proof<'a>(
        self,
        vocabulary: &'a mut V,
        interpretation: &'a mut I
    ) -> Self::ExtractProof<'a> where Self: 'a;
}

/// JSON-LD Data-Integrity input.
/// 
/// This is a simple wrapper around [`RemoteDocumentReference<I>`] that adds
/// the ability to expand and extract a Data-Integrity proof from the wrapped
/// (remote) JSON-LD document.
pub struct JsonLdInput<'l, I, L> {
    document: RemoteDocumentReference<I>,
    loader: &'l mut L
}

impl<'l, I: Interpretation, V: Vocabulary, L> DataIntegrityInput<I, V> for JsonLdInput<'l, V::Iri, L>
where
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataSubject<I, V> + LinkedDataResource<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataSubject<I, V> + LinkedDataResource<I, V>,
    L: Loader<V::Iri> + ContextLoader<V::Iri>,
    L::Output: Into<json_ld::syntax::Value>,
    // Required by `json-ld` for now
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send,
    L::ContextError: Send
{
    type Error = json_ld::ExpandError<(), L::Error, L::ContextError>;

    type Data = json_ld::Document<V::Iri, V::BlankId>;

    type Proof = json_ld::Node<V::Iri, V::BlankId>;

    type ExtractProof<'a> = ExtractJsonLdProof<'a, I, V, L> where Self: 'a, V: 'a, I: 'a;
    
    fn extract_proof<'a>(
        self,
        vocabulary: &'a mut V,
        interpretation: &'a mut I
    ) -> Self::ExtractProof<'a> where Self: 'a {
        use json_ld::JsonLdProcessor;
        
        let options = json_ld::Options {
            expansion_policy: json_ld::expansion::Policy::Strictest,
            ..Default::default()
        };

        let vocabulary_ptr = vocabulary as *mut V;

        ExtractJsonLdProof {
            expand: self.document.into_document_with_using(
                vocabulary,
                self.loader,
                options
            ),
            vocabulary: vocabulary_ptr,
            interpretation
        }
    }
}

#[pin_project::pin_project]
pub struct ExtractJsonLdProof<'a, I: Interpretation, V: Vocabulary, L>
where
    V::Iri: Send,
    L: Loader<V::Iri> + ContextLoader<V::Iri>
{
    expand: Pin<Box<dyn 'a + Future<Output = IntoDocumentResult<V::Iri, V::BlankId, (), L>>>>,
    vocabulary: *mut V,
    interpretation: &'a mut I,
}

impl<'a, V: 'a + Vocabulary, I: Interpretation, L> Future for ExtractJsonLdProof<'a, I, V, L>
where
    V::Iri: Send + Eq + Hash,
    V::BlankId: Eq + Hash,
    L: Loader<V::Iri> + ContextLoader<V::Iri>
{
    type Output = Result<(json_ld::Document<V::Iri, V::BlankId>, json_ld::Node<V::Iri, V::BlankId>), DecodeError<json_ld::ExpandError<(), L::Error, L::ContextError>>>;

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> std::task::Poll<Self::Output> {
        let this = self.project();

        this.expand.as_mut().poll(cx).map(|r| {
            let (mut remote, Meta(expanded, meta)) = r.map_err(DecodeError::Input)?.into_parts();
            
            match remote.document_mut().0.as_object_mut() {
                Some(object) => {
                    let mut proofs = object.remove("proof");
                    if proofs.next().is_none() {
                        todo!()
                    }
                }
                None => {
                    todo!()
                }
            }

            match expanded.into_main_node() {
                Some(mut node) => {
                    let vocabulary: &'a mut V = unsafe {
                        // SAFETY: the only other mutable reference to
                        // `this.vocabulary` lived inside `this.expanded` and is
                        // now dropped (or at least never used again).
                        this.vocabulary.as_mut().unwrap()
                    };

                    match vocabulary.get(PROOF_IRI).map(json_ld::Id::iri) {
                        Some(proof_iri) => {
                            match node.properties_mut().remove(&proof_iri).and_then(|objects| objects.value.into_iter().next()) {
                                Some(Stripped(Meta(proof_object, _))) => {
                                    match proof_object.into_inner() {
                                        json_ld::Object::Node(proof_node) => {
                                            let document = json_ld::Document::new(
                                                remote,
                                                Meta(node.map(json_ld::Indexed::none).into(), meta)
                                            );

                                            Ok((document, *proof_node))
                                        }
                                        _ => {
                                            todo!()
                                        }
                                    }
                                }
                                None => {
                                    todo!()
                                }
                            }
                        }
                        None => {
                            todo!()
                        }
                    }
                }
                None => {
                    Err(DecodeError::MissingSubject)
                }
            }
        })
    }
}

impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
    /// Imports a Data Integrity credential or presentation.
    /// 
    /// This will extract the Data Integrity proof embedded in the input,
    /// decode the proof graph into a `Proof<S>` value and finally hash the
    /// proof-less input using the correct cryptographic suite. The result is a
    /// verifiable data integrity credential/presentation.
    pub async fn from_linked_data<I: Interpretation, V: Vocabulary, U, X>(
        mut ld_context: LinkedDataInput<I, V>,
        input: U,
        make_context: impl FnOnce(LinkedDataInput<I, V>) -> X,
    ) -> Result<Verifiable<Self>, DecodeError<U::Error>>
    where
        I: InterpretationMut<V>
            + IriInterpretationMut<V::Iri>
            + BlankIdInterpretationMut<V::BlankId>
            + LiteralInterpretationMut<V::Literal>,
        I::Resource: Clone + Eq + Hash,
        V: Vocabulary + IriVocabularyMut + LiteralVocabularyMut,
        V::Iri: Clone,
        V::BlankId: Clone,
        V::Value: RdfLiteralValue,
        V::Type: RdfLiteralType<V>,
        V::LanguageTag: Clone,
        Proof<S>: LinkedDataDeserializeSubject<I, V>,
        S: CryptographicSuiteInput<T, X>,
        U: DataIntegrityInput<I, V, Data = T>
    {
        // Extract the proof.
        let (data, proof) = input.extract_proof(&mut ld_context.vocabulary, &mut ld_context.interpretation).await?;

        // Turn the proof into RDF quads.
        let (proof_graph_id, quads) = linked_data::to_interpreted_graph_quads(
            &mut ld_context.vocabulary,
            &mut ld_context.interpretation,
            &proof
        ).map_err(DecodeError::InvalidLinkedData)?;

        // Organize the quads.
        let mut dataset: HashDataset<I::Resource> = quads
            .into_iter()
            .collect();

        // Process the proof graph.
        match dataset.remove_graph(&proof_graph_id) {
            Some(proof_graph) => {
                let proof_value_property = ld_context.interpretation.interpret_iri(ld_context.vocabulary.insert(PROOF_VALUE_IRI));
                match proof_graph.any_match(Triple(None, Some(&proof_value_property), None)) {
                    Some(Triple(proof_id, _, _)) => {
                        let proof = Proof::deserialize_subject(
                            &mut ld_context.vocabulary,
                            &mut ld_context.interpretation,
                            &dataset,
                            &proof_graph,
                            &proof_id
                        )
                        .map_err(DecodeError::InvalidProof)?;
                        
                        let transformed = proof
                            .suite()
                            .transform(&data, make_context(ld_context), proof.configuration()).await
                            .map_err(DecodeError::Transform)?;
                        let hashed = proof.suite().hash(transformed, proof.configuration())?;

                        Ok(Verifiable::new(
                            DataIntegrity::new_hashed(data, hashed),
                            proof,
                        ))
                    }
                    None => {
                        Err(DecodeError::MissingProofValue)
                    }
                }
            }
            None => {
                Err(DecodeError::MissingProofGraph)
            }
        }
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
    // pub async fn from_json_ld<'a, I, V, L, X>(
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
    //     T: LinkedDataDeserializeSubject<I, V>,
    //     S: CryptographicSuiteInput<T, X>,
    //     L: json_ld::Loader<V::Iri> + json_ld::ContextLoader<V::Iri>,
    //     L::Output: Into<json_ld::syntax::Value>,
    //     // TODO those bounds are required because of `json-ld`, and can't be
    //     //      avoided until `async fn` in traits are stabilized.
    //     V: Send + Sync,
    //     V::Iri: Send + Sync,
    //     V::BlankId: Send + Sync,
    //     L: Send + Sync,
    //     L::Error: Send,
    //     L::ContextError: Send
    // {
    //     use json_ld::JsonLdProcessor;
        
    //     let options = json_ld::Options {
    //         expansion_policy: json_ld::expansion::Policy::Strictest,
    //         ..Default::default()
    //     };

    //     let json_ld = input.expand_with_using(
    //         vocabulary,
    //         loader,
    //         options
    //     ).await.map_err(FromJsonLdError::Expansion)?.into_value();

    //     let subject: &json_ld::Node<V::Iri, V::BlankId> = json_ld.main_node().ok_or(FromJsonLdError::NoMainNode)?;
    //     Self::from_linked_data(vocabulary, interpretation, subject, make_context).await.map_err(FromJsonLdError::DataIntegrity)
    // }
}
