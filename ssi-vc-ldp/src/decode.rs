// pub mod rdf;
use std::hash::Hash;
use futures::Future;
use iref::Iri;
use linked_data::{FromLinkedDataError, LinkedDataDeserializeSubject, LinkedDataResource, LinkedDataSubject, IntoQuadsError, RdfLiteralValue, RdfLiteralType, LinkedDataGraph};
use rdf_types::{
    Triple, VocabularyMut, Vocabulary, IriVocabularyMut, InterpretationMut, IriInterpretationMut, BlankIdInterpretationMut, LiteralInterpretationMut, LiteralVocabularyMut, Interpretation, Generator, interpretation,
};
use ssi_vc::Verifiable;
use static_iref::iri;
use crate::{
    suite::{CryptographicSuiteInput, HashError, TransformError},
    CryptographicSuite, DataIntegrity, Proof, LinkedDataInput,
};

pub mod from_json_ld;
pub mod deserialized_from_json_ld;

pub use from_json_ld::JsonLdInput;
pub use deserialized_from_json_ld::DeserializedJsonLdInput;

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

impl<I> DecodeError<I> {
    pub fn map_input<J>(self, f: impl FnOnce(I) -> J) -> DecodeError<J> {
        match self {
            Self::InvalidLinkedData(e) => DecodeError::InvalidLinkedData(e),
            Self::MissingSubject => DecodeError::MissingSubject,
            Self::MissingProof => DecodeError::MissingProof,
            Self::MissingProofGraph => DecodeError::MissingProofGraph,
            Self::MissingProofValue => DecodeError::MissingProofValue,
            Self::InvalidProof(e) => DecodeError::InvalidProof(e),
            Self::InvalidCredential(e) => DecodeError::InvalidCredential(e),
            Self::Transform(e) => DecodeError::Transform(e),
            Self::HashFailed(e) => DecodeError::HashFailed(e),
            Self::Input(e) => DecodeError::Input(f(e))
        }
    }
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

impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
    /// Imports a Data Integrity credential or presentation.
    /// 
    /// This will extract the Data Integrity proof embedded in the input,
    /// decode the proof graph into a `Proof<S>` value and finally hash the
    /// proof-less input using the correct cryptographic suite. The result is a
    /// verifiable data integrity credential/presentation.
    pub async fn from_linked_data<G: Generator, U, X>(
        generator: G,
        input: U,
        make_context: impl FnOnce(LinkedDataInput<interpretation::WithGenerator<G>>) -> X,
    ) -> Result<Verifiable<Self>, DecodeError<U::Error>>
    where
        Proof<S>: LinkedDataDeserializeSubject<interpretation::WithGenerator<G>>,
        S: CryptographicSuiteInput<T, X>,
        U: DataIntegrityInput<interpretation::WithGenerator<G>, Data = T>
    {
        Self::from_linked_data_with(
            LinkedDataInput::from_generator(generator),
            input,
            make_context
        ).await
    }

    /// Imports a Data Integrity credential or presentation.
    /// 
    /// This will extract the Data Integrity proof embedded in the input,
    /// decode the proof graph into a `Proof<S>` value and finally hash the
    /// proof-less input using the correct cryptographic suite. The result is a
    /// verifiable data integrity credential/presentation.
    pub async fn from_linked_data_with<I: Interpretation, V: Vocabulary, U, X>(
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

    /// Imports a Data Integrity credential from a JSON-LD document.
    /// 
    /// This will expand the input document, put it in canonical form, give a
    /// name to all anonymous nodes using `generator` and finally call the
    /// `from_linked_data` function.
    /// 
    /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
    /// expansion policy. If it fails to expand a key in the input document,
    /// it will not be ignored and the whole process will fail.
    pub async fn deserialize_from_json_ld<'a, G: Generator, L, X>(
        generator: G,
        loader: &mut L,
        document: json_ld::RemoteDocumentReference,
        make_context: impl FnOnce(LinkedDataInput<interpretation::WithGenerator<G>>) -> X,
    ) -> Result<Verifiable<Self>, DecodeError<json_ld::ExpandError<(), L::Error, L::ContextError>>>
    where
        Proof<S>: LinkedDataDeserializeSubject<interpretation::WithGenerator<G>>,
        T: LinkedDataDeserializeSubject<interpretation::WithGenerator<G>>,
        S: CryptographicSuiteInput<T, X>,
        L: json_ld::Loader + json_ld::ContextLoader,
        L::Output: Into<json_ld::syntax::Value>,
        // TODO those bounds are required because of `json-ld`, and can't be
        //      avoided until `async fn` in traits are stabilized.
        L: Send + Sync,
        L::Error: Send,
        L::ContextError: Send
    {
        Self::deserialize_from_json_ld_with(
            LinkedDataInput::from_generator(generator),
            loader,
            document,
            make_context
        ).await
    }
    
    /// Imports a Data Integrity credential from a JSON-LD document.
    /// 
    /// This will expand the input document, put it in canonical form, give a
    /// name to all anonymous nodes using `generator` and finally call the
    /// `from_linked_data` function.
    /// 
    /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
    /// expansion policy. If it fails to expand a key in the input document,
    /// it will not be ignored and the whole process will fail.
    pub async fn deserialize_from_json_ld_with<'a, I, V, L, X>(
        ld_context: LinkedDataInput<I, V>,
        loader: &mut L,
        document: json_ld::RemoteDocumentReference<V::Iri>,
        make_context: impl FnOnce(LinkedDataInput<I, V>) -> X,
    ) -> Result<Verifiable<Self>, DecodeError<json_ld::ExpandError<(), L::Error, L::ContextError>>>
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
        Proof<S>: LinkedDataDeserializeSubject<I, V>,
        T: LinkedDataDeserializeSubject<I, V>,
        S: CryptographicSuiteInput<T, X>,
        L: json_ld::Loader<V::Iri> + json_ld::ContextLoader<V::Iri>,
        L::Output: Into<json_ld::syntax::Value>,
        // TODO those bounds are required because of `json-ld`, and can't be
        //      avoided until `async fn` in traits are stabilized.
        V: Send + Sync,
        V::Iri: Send + Sync,
        V::BlankId: Send + Sync,
        L: Send + Sync,
        L::Error: Send,
        L::ContextError: Send
    {
        Self::from_linked_data_with(
            ld_context,
            DeserializedJsonLdInput::new(loader, document),
            make_context
        ).await
    }
}

impl<S: CryptographicSuite> DataIntegrity<json_ld::Document, S> {
    /// Imports a Data Integrity credential from a JSON-LD document.
    /// 
    /// This will expand the input document, put it in canonical form, give a
    /// name to all anonymous nodes using `generator` and finally call the
    /// `from_linked_data` function.
    /// 
    /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
    /// expansion policy. If it fails to expand a key in the input document,
    /// it will not be ignored and the whole process will fail.
    pub async fn from_json_ld<'a, G: Generator, L, X>(
        generator: G,
        loader: &mut L,
        document: json_ld::RemoteDocumentReference,
        make_context: impl FnOnce(LinkedDataInput<interpretation::WithGenerator<G>>) -> X,
    ) -> Result<Verifiable<Self>, DecodeError<json_ld::ExpandError<(), L::Error, L::ContextError>>>
    where
        Proof<S>: LinkedDataDeserializeSubject<interpretation::WithGenerator<G>>,
        S: CryptographicSuiteInput<json_ld::Document, X>,
        L: json_ld::Loader + json_ld::ContextLoader,
        L::Output: Into<json_ld::syntax::Value>,
        // TODO those bounds are required because of `json-ld`, and can't be
        //      avoided until `async fn` in traits are stabilized.
        L: Send + Sync,
        L::Error: Send,
        L::ContextError: Send
    {
        Self::from_json_ld_with(
            LinkedDataInput::new((), interpretation::WithGenerator::new((), generator)),
            loader,
            document,
            make_context
        ).await
    }
}

impl<Iri, B, S: CryptographicSuite> DataIntegrity<json_ld::Document<Iri, B>, S> {
    /// Imports a Data Integrity credential from a JSON-LD document.
    /// 
    /// This will expand the input document, put it in canonical form, give a
    /// name to all anonymous nodes using `generator` and finally call the
    /// `from_linked_data` function.
    /// 
    /// The JSON-LD expansion algorithm is called with the [`Strictest`] key
    /// expansion policy. If it fails to expand a key in the input document,
    /// it will not be ignored and the whole process will fail.
    pub async fn from_json_ld_with<'a, I, V, L, X>(
        ld_context: LinkedDataInput<I, V>,
        loader: &mut L,
        document: json_ld::RemoteDocumentReference<V::Iri>,
        make_context: impl FnOnce(LinkedDataInput<I, V>) -> X,
    ) -> Result<Verifiable<Self>, DecodeError<json_ld::ExpandError<(), L::Error, L::ContextError>>>
    where
        I: InterpretationMut<V>
            + IriInterpretationMut<Iri>
            + BlankIdInterpretationMut<B>
            + LiteralInterpretationMut<V::Literal>,
        I::Resource: Clone + Eq + Hash,
        V: VocabularyMut<Iri = Iri, BlankId = B>,
        Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        B: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::Value: RdfLiteralValue,
        V::Type: RdfLiteralType<V>,
        V::LanguageTag: Clone,
        Proof<S>: LinkedDataDeserializeSubject<I, V>,
        S: CryptographicSuiteInput<json_ld::Document<Iri, B>, X>,
        L: json_ld::Loader<Iri> + json_ld::ContextLoader<Iri>,
        L::Output: Into<json_ld::syntax::Value>,
        // TODO those bounds are required because of `json-ld`, and can't be
        //      avoided until `async fn` in traits are stabilized.
        V: Send + Sync,
        Iri: Send + Sync,
        B: Send + Sync,
        L: Send + Sync,
        L::Error: Send,
        L::ContextError: Send
    {
        Self::from_linked_data_with(
            ld_context,
            JsonLdInput::new(loader, document),
            make_context
        ).await
    }
}