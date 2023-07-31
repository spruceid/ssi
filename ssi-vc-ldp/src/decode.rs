// pub mod rdf;

use std::hash::Hash;

use iref::Iri;
use json_ld::RdfQuads;
use rdf_types::{
    Interpret, IriVocabulary, LanguageTagVocabulary, TermInterpretationMut, Triple, VocabularyMut,
};
use ssi_rdf::DatasetWithEntryPoint;
use ssi_vc::Verifiable;
use static_iref::iri;
use treeldr_rust_prelude::{grdf, locspan::Meta, FromRdf, FromRdfError};

use crate::{
    suite::{CryptographicSuiteInput, HashError, VerificationParameters},
    CryptographicSuite, DataIntegrity, Proof,
};

#[derive(Debug, thiserror::Error)]
pub enum Error<T> {
    #[error("missing credential")]
    MissingCredential,

    #[error("missing proof")]
    MissingProof,

    #[error("missing proof graph")]
    MissingProofGraph,

    #[error("missing proof value")]
    MissingProofValue,

    #[error("invalid proof")]
    InvalidProof(FromRdfError),

    #[error("invalid credential")]
    InvalidCredential(FromRdfError),

    #[error("input transformation failed: {0}")]
    Transform(T),

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),
}

type HashDataset<T> = grdf::HashDataset<T, T, T, T>;

const PROOF_IRI: Iri<'static> = iri!("https://w3id.org/security#proof");
const PROOF_VALUE_IRI: Iri<'static> = iri!("https://w3id.org/security#proofValue");

impl<C: Sync, S: CryptographicSuite> DataIntegrity<C, S> {
    /// Imports a Data Integrity credential from a JSON-LD document.
    ///
    /// The cryptographic suite is applied on the RDF graph represented by the
    /// input document.
    pub fn from_json_ld<'a, V, I, M: Clone>(
        &self,
        vocabulary: &'a mut V,
        generator: &mut impl json_ld::Generator<V, M>,
        interpretation: &'a mut I,
        mut input: json_ld::ExpandedDocument<V::Iri, V::BlankId, M>,
        params: S::VerificationParameters,
    ) -> Result<Verifiable<Self>, Error<S::TransformError>>
    where
        V: VocabularyMut<
            Type = rdf_types::literal::Type<
                <V as IriVocabulary>::Iri,
                <V as LanguageTagVocabulary>::LanguageTag,
            >,
            Value = String,
        >,
        V::Iri: Clone + Eq + Hash,
        V::BlankId: Clone + Eq + Hash,
        V::Literal: Clone,
        I: TermInterpretationMut<V::Iri, V::BlankId, V::Literal>,
        I::Resource: Clone + Eq + Hash,
        Proof<S>: FromRdf<V, I>,
        C: FromRdf<V, I>,
        S: CryptographicSuiteInput<DatasetWithEntryPoint<'a, V, I>>,
    {
        input.relabel_and_canonicalize_with(vocabulary, generator);

        let proof_property: I::Resource =
            interpretation.interpret_iri(vocabulary.insert(PROOF_IRI));

        let mut entry_point: Option<I::Resource> = None;
        for object in &input {
            if let Some(Meta(json_ld::Id::Valid(id), _)) = object.id() {
                entry_point = Some(id.clone().interpret(interpretation));
            }
        }

        let entry_point = entry_point.ok_or(Error::MissingCredential)?;

        let mut dataset: HashDataset<I::Resource> = input
            .rdf_quads_with(vocabulary, generator, None)
            .cloned()
            .map(|quad| quad.interpret(interpretation))
            .collect();

        match dataset.default_graph().any_match(Triple(
            Some(&entry_point),
            Some(&proof_property),
            None,
        )) {
            Some(Triple(s, p, proof_graph_id)) => {
                let s = s.clone();
                let p = p.clone();
                let proof_graph_id = proof_graph_id.clone();
                dataset
                    .default_graph_mut()
                    .remove(Triple(&s, &p, &proof_graph_id));
                match dataset.remove_graph(&proof_graph_id) {
                    Some(proof_graph) => {
                        let proof_value_property =
                            interpretation.interpret_iri(vocabulary.insert(PROOF_VALUE_IRI));
                        match proof_graph.any_match(Triple(None, Some(&proof_value_property), None))
                        {
                            Some(Triple(proof_id, _, _)) => {
                                let proof = Proof::from_rdf(
                                    vocabulary,
                                    interpretation,
                                    &proof_graph,
                                    proof_id,
                                )
                                .map_err(Error::InvalidProof)?;

                                let credential = C::from_rdf(
                                    vocabulary,
                                    interpretation,
                                    dataset.default_graph(),
                                    &entry_point,
                                )
                                .map_err(Error::InvalidCredential)?;

                                let data = DatasetWithEntryPoint {
                                    vocabulary,
                                    interpretation,
                                    dataset,
                                    entry_point,
                                };

                                let transformed = proof
                                    .suite()
                                    .transform(data, params.transformation_parameters())
                                    .map_err(Error::Transform)?;
                                let hashed = proof
                                    .suite()
                                    .hash(transformed, params.into_hash_parameters())?;

                                Ok(Verifiable::new(
                                    DataIntegrity::new(credential, hashed),
                                    proof,
                                ))
                            }
                            None => Err(Error::MissingProofValue),
                        }
                    }
                    None => Err(Error::MissingProofGraph),
                }
            }
            None => Err(Error::MissingProof),
        }
    }
}
