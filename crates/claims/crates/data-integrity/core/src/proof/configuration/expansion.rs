use ::linked_data::{LinkedDataResource, LinkedDataSubject};
use iref::IriBuf;
use linked_data::LinkedData;
use rdf_types::{
    dataset::{BTreeGraph, IndexedBTreeDataset, PatternMatchingDataset},
    interpretation::{ReverseTermInterpretation, WithGenerator},
    vocabulary::IriVocabulary,
    Id, InterpretationMut, LexicalQuad, Quad, Term, Triple, Vocabulary, VocabularyMut,
};
use serde::Serialize;
use ssi_json_ld::{
    CompactJsonLd, Expandable, ExpandedDocument, JsonLdError, JsonLdLoaderProvider,
    JsonLdNodeObject, JsonLdObject, JsonLdTypes, Loader,
};
use ssi_rdf::{urdna2015, Interpretation, IntoNQuads, LdEnvironment};
use std::{borrow::Cow, hash::Hash};

use crate::{suite::SerializeCryptographicSuite, CryptographicSuite, ProofConfigurationRef};

impl<'a, S: CryptographicSuite> ProofConfigurationRef<'a, S> {
    pub fn embed<'d>(
        self,
        document: &'d impl JsonLdNodeObject,
    ) -> EmbeddedProofConfigurationRef<'d, 'a, S> {
        EmbeddedProofConfigurationRef {
            context: document.json_ld_context(),
            type_: document.json_ld_type(),
            proof: self,
        }
    }

    pub async fn expand(
        self,
        environment: &impl JsonLdLoaderProvider,
        document: &impl JsonLdNodeObject,
    ) -> Result<ExpandedProofConfiguration, ConfigurationExpansionError>
    where
        S: SerializeCryptographicSuite,
    {
        let embedded = self.embed(document);
        let expanded = embedded.expand(environment.loader()).await?;
        let mut interpretation = WithGenerator::new((), ssi_rdf::generator::Blank::new());
        expanded.extract(&mut (), &mut interpretation)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigurationExpansionError {
    #[error("JSON-LD expansion failed: {0}")]
    Expansion(#[from] JsonLdError),

    #[error(transparent)]
    IntoQuads(#[from] ::linked_data::IntoQuadsError),

    #[error("missing proof configuration")]
    MissingProof,

    #[error("missing proof configuration value")]
    InvalidProofValue,

    #[error("invalid proof type")]
    InvalidProofType,

    #[error("missing proof configuration graph")]
    MissingProofGraph,

    #[error("invalid JSON-LD context")]
    InvalidContext,
}

#[derive(Serialize)]
#[serde(bound = "S: SerializeCryptographicSuite")]
pub struct EmbeddedProofConfigurationRef<'d, 'a, S: CryptographicSuite> {
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    context: Option<Cow<'d, ssi_json_ld::syntax::Context>>,

    #[serde(rename = "type", skip_serializing_if = "JsonLdTypes::is_empty")]
    type_: JsonLdTypes<'d>,

    proof: ProofConfigurationRef<'a, S>,
}

impl<'d, 'a, S: CryptographicSuite> JsonLdObject for EmbeddedProofConfigurationRef<'d, 'a, S> {
    fn json_ld_context(&self) -> Option<Cow<ssi_json_ld::syntax::Context>> {
        self.context.as_deref().map(Cow::Borrowed)
    }
}

impl<'d, 'a, S: CryptographicSuite> JsonLdNodeObject for EmbeddedProofConfigurationRef<'d, 'a, S> {
    fn json_ld_type(&self) -> JsonLdTypes {
        self.type_.reborrow()
    }
}

impl<'d, 'a, S: SerializeCryptographicSuite> Expandable
    for EmbeddedProofConfigurationRef<'d, 'a, S>
{
    type Error = ConfigurationExpansionError;
    type Expanded<I, V> = ExpandedEmbeddedProofConfiguration<V::Iri, V::BlankId>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    {
        let json = json_syntax::to_value(self).unwrap();
        let mut expanded = CompactJsonLd(json).expand_with(ld, loader).await?;
        expanded.canonicalize();
        Ok(ExpandedEmbeddedProofConfiguration(expanded))
    }
}

pub struct ExpandedEmbeddedProofConfiguration<I, B>(ssi_json_ld::ExpandedDocument<I, B>);

impl<I, B> ExpandedEmbeddedProofConfiguration<I, B>
where
    I: Clone + Eq + Hash,
    B: Clone + Eq + Hash,
{
    pub fn extract<V, R>(
        self,
        vocabulary: &mut V,
        interpretation: &mut R,
    ) -> Result<ExpandedProofConfiguration, ConfigurationExpansionError>
    where
        R: InterpretationMut<V>
            + ReverseTermInterpretation<Iri = I, BlankId = B, Literal = V::Literal>,
        R::Resource: Clone,
        V: VocabularyMut<Iri = I, BlankId = B>,
        I: LinkedDataResource<R, V> + LinkedDataSubject<R, V>,
        B: LinkedDataResource<R, V> + LinkedDataSubject<R, V>,
    {
        match self.0.into_main_node() {
            Some(node) => {
                // Get the proof type IRI.
                let proof_prop = ssi_json_ld::Id::iri(
                    vocabulary
                        .get(ssi_security::PROOF)
                        .ok_or(ConfigurationExpansionError::MissingProof)?,
                );
                let proof_type = match node.get_any(&proof_prop) {
                    Some(proof) => match proof.as_node() {
                        Some(proof) => match &proof.graph {
                            Some(proof_graph) => match proof_graph.first() {
                                Some(proof) => match proof.as_node() {
                                    Some(proof) => match proof.types() {
                                        [ssi_json_ld::Id::Valid(Id::Iri(iri))] => {
                                            Ok(vocabulary.iri(iri).unwrap().to_owned())
                                        }
                                        _ => Err(ConfigurationExpansionError::InvalidProofType),
                                    },
                                    None => Err(ConfigurationExpansionError::InvalidProofValue),
                                },
                                None => Err(ConfigurationExpansionError::MissingProof),
                            },
                            None => Err(ConfigurationExpansionError::InvalidProofValue),
                        },
                        None => Err(ConfigurationExpansionError::InvalidProofValue),
                    },
                    None => Err(ConfigurationExpansionError::MissingProof),
                }?;

                let (subject, quads) = ::linked_data::to_lexical_subject_quads_with(
                    vocabulary,
                    interpretation,
                    None,
                    &node,
                )?;

                let subject = Term::Id(subject);

                let mut dataset: IndexedBTreeDataset = quads
                    .into_iter()
                    .map(|q| Quad(Term::Id(q.0), Term::iri(q.1), q.2, q.3.map(Term::Id)))
                    .collect();

                let proof_prop = Term::iri(ssi_security::PROOF.to_owned());
                match dataset.quad_objects(None, &subject, &proof_prop).next() {
                    Some(Term::Id(proof_id)) => {
                        let proof_id = Term::Id(proof_id.clone());
                        match dataset.remove_graph(Some(&proof_id)) {
                            Some(graph) => Ok(ExpandedProofConfiguration {
                                type_iri: proof_type,
                                graph,
                            }),
                            None => Err(ConfigurationExpansionError::MissingProofGraph),
                        }
                    }
                    Some(Term::Literal(_)) => Err(ConfigurationExpansionError::InvalidProofValue),
                    None => Err(ConfigurationExpansionError::MissingProof),
                }
            }
            None => Err(ConfigurationExpansionError::InvalidContext),
        }
    }
}

impl<I: Interpretation, V: Vocabulary> LinkedData<I, V>
    for ExpandedEmbeddedProofConfiguration<V::Iri, V::BlankId>
where
    ExpandedDocument<V::Iri, V::BlankId>: LinkedData<I, V>,
{
    fn visit<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::Visitor<I, V>,
    {
        self.0.visit(visitor)
    }
}

/// Linked-Data proof configuration.
pub struct ExpandedProofConfiguration {
    pub type_iri: IriBuf,
    pub graph: BTreeGraph,
}

impl ExpandedProofConfiguration {
    /// Returns the quads of the proof configuration, in canonical form.
    pub fn quads(&self) -> impl '_ + Iterator<Item = LexicalQuad> {
        let quads = self.graph.iter().map(|Triple(s, p, o)| {
            Quad(
                s.as_lexical_term_ref().into_id().unwrap(),
                p.as_lexical_term_ref().into_iri().unwrap(),
                o.as_lexical_term_ref(),
                None,
            )
        });

        urdna2015::normalize(quads)
    }

    /// Returns the quads of the proof configuration, in canonical form.
    pub fn nquads_lines(&self) -> Vec<String> {
        self.quads().into_nquads_lines()
    }

    /// Returns the quads of the proof configuration, in canonical form.
    pub fn nquads(&self) -> String {
        self.quads().into_nquads()
    }
}
