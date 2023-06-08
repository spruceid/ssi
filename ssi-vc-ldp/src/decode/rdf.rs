use std::marker::PhantomData;
use async_trait::async_trait;

use iref::Iri;
use rdf_types::{Namespace, Triple};
use ssi_vc::Verifiable;

const PROOF_IRI: Iri<'static> = static_iref::iri!("https://w3id.org/security#proof");
const PROOF_VALUE_IRI: Iri<'static> = static_iref::iri!("https://w3id.org/security#proofValue");

/// Data Integrity VC RDF graph decoder.
/// 
/// This decoder can extract a VC from any RDF graph following the Verifiable
/// Credential Data Integrity specification, where the proof term is embedded
/// into the VC data through the `https://w3id.org/security#proof` property.
pub struct RdfDecoder<C, P> {
	cp: PhantomData<(C, P)>
}

/// Entry point to the decoded RDF value.
pub struct EntryPoint<'a, N: Namespace, L, D: treeldr_rust_prelude::grdf::Dataset<GraphLabel = N::Id>> {
	value: &'a treeldr_rust_prelude::rdf_types::Object<N::Id, L>,
	dataset: &'a D,
	graph: &'a D::Graph,
}

pub enum FromRdfError<P> {
    CredentialError(treeldr_rust_prelude::FromRdfError),
    MissingProof,
    UnexpectedLiteralProof,
    MissingProofGraph,
    MissingProofValue,
    ProofError(P)
}

pub trait ProofFromRdf<N, L>: Sized {
    type Error;

    fn proof_from_rdf<G>(
        namespace: &mut N,
        value: &N::Id,
        graph: &G,
    ) -> Result<Self, Self::Error>
    where
        N: Namespace + treeldr_rust_prelude::rdf_types::IriVocabularyMut,
        N::Id: treeldr_rust_prelude::rdf_types::FromIri<Iri = N::Iri>,
        G: treeldr_rust_prelude::grdf::Graph<Subject = N::Id, Predicate = N::Id, Object = treeldr_rust_prelude::rdf_types::Object<N::Id, L>>;
}

#[async_trait]
impl<'a, N, L, D, C, P> ssi_vc::Decoder<N, EntryPoint<'a, N, L, D>> for RdfDecoder<C, P>
where
	N: Namespace + treeldr_rust_prelude::rdf_types::IriVocabularyMut + Sync + Send,
	N::Id: treeldr_rust_prelude::rdf_types::FromIri<Iri = N::Iri> + Send + Sync,
	L: Sync + Send,
	D: treeldr_rust_prelude::grdf::Dataset<GraphLabel = N::Id> + Sync,
	D::Graph: treeldr_rust_prelude::grdf::Graph<Subject = N::Id, Predicate = N::Id, Object = treeldr_rust_prelude::rdf_types::Object<N::Id, L>> + Send + Sync,
	C: treeldr_rust_prelude::FromRdf<N, L> + Sync + Send,
	P: ProofFromRdf<N, L> + Sync + Send,
	P::Error: Sync + Send
{
	type Credential = C;
	type Proof = P;

	type Error = FromRdfError<P::Error>;

	async fn decode(&mut self, namespace: &mut N, e: EntryPoint<'a, N, L, D>) -> Result<Verifiable<Self::Credential, Self::Proof>, Self::Error> {
        use treeldr_rust_prelude::grdf::Graph;

        match e.value.as_id() {
            Some(id) => {
                let proof_iri = <N::Id as treeldr_rust_prelude::rdf_types::FromIri>::from_iri(namespace.insert(PROOF_IRI));

                let proof_triple = e.graph.any_match(Triple(
                    Some(id),
                    Some(&proof_iri),
                    None
                ));

                match proof_triple {
                    Some(proof_triple) => {
                        match proof_triple.object() {
                            treeldr_rust_prelude::rdf_types::Object::Id(proof_graph_iri) => {
                                match e.dataset.graph(Some(proof_graph_iri)) {
                                    Some(proof_graph) => {
                                        let proof_value_iri = <N::Id as treeldr_rust_prelude::rdf_types::FromIri>::from_iri(namespace.insert(PROOF_VALUE_IRI));
                                        let proof_value_triple = proof_graph.any_match(Triple(
                                            None,
                                            Some(&proof_value_iri),
                                            None
                                        ));

                                        match proof_value_triple {
                                            Some(proof_value_triple) => {
                                                let proof_subject = proof_value_triple.subject();
                                                let proof = P::proof_from_rdf(namespace, proof_subject, proof_graph).map_err(FromRdfError::ProofError)?;
                                                let credential = C::from_rdf(namespace, e.value, e.graph).map_err(FromRdfError::CredentialError)?;
                                                
                                                Ok(Verifiable::new(credential, proof))
                                            }
                                            None => {
                                                Err(FromRdfError::MissingProofValue)
                                            }
                                        }
                                    }
                                    None => {
                                        Err(FromRdfError::MissingProofGraph)
                                    }
                                }
                            }
                            treeldr_rust_prelude::rdf_types::Object::Literal(_) => {
                                Err(FromRdfError::UnexpectedLiteralProof)
                            }
                        }
                    }
                    None => Err(FromRdfError::MissingProof)
                }
            }
            None => {
                Err(FromRdfError::CredentialError(treeldr_rust_prelude::FromRdfError::UnexpectedLiteralValue))
            }
        }
    }
}