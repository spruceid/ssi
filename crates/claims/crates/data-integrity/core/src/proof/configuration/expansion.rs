use core::fmt;
use std::{borrow::Cow, hash::Hash};

use ::linked_data::{LinkedDataResource, LinkedDataSubject};
use iref::IriBuf;
use rdf_types::{
    dataset::{BTreeGraph, IndexedBTreeDataset, PatternMatchingDataset},
    interpretation::ReverseTermInterpretation,
    vocabulary::IriVocabulary,
    Id, Interpretation, InterpretationMut, LexicalQuad, Quad, Term, Triple, VocabularyMut,
};
use serde::Serialize;
use ssi_json_ld::{
    AnyJsonLdEnvironment, CompactJsonLd, JsonLdNodeObject, JsonLdObject, JsonLdTypes,
};
use ssi_rdf::{urdna2015, AnyLdEnvironment, Expandable, IntoNQuads};

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
        environment: &mut impl ConfigurationExpandingEnvironment,
        document: &impl JsonLdNodeObject,
    ) -> Result<ExpandedProofConfiguration, ConfigurationExpansionError>
    where
        S: SerializeCryptographicSuite,
    {
        environment.expand_configuration(document, self).await
    }
}

/// Any environment able to expand a proof configuration.
///
/// This trait only exists to alias all the trait bounds required for its
/// unique implementation.
pub trait ConfigurationExpandingEnvironment {
    #[allow(async_fn_in_trait)]
    async fn expand_configuration<S: SerializeCryptographicSuite>(
        &mut self,
        document: &impl JsonLdNodeObject,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<ExpandedProofConfiguration, ConfigurationExpansionError>;
}

impl<E, V, I, L> ConfigurationExpandingEnvironment for E
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Interpretation = I, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    I: InterpretationMut<V>
        + ReverseTermInterpretation<Iri = V::Iri, BlankId = V::BlankId, Literal = V::Literal>,
    I::Resource: Clone,
    L: json_ld::Loader<V::Iri>,
    L::Error: fmt::Display,
{
    async fn expand_configuration<S: SerializeCryptographicSuite>(
        &mut self,
        document: &impl JsonLdNodeObject,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<ExpandedProofConfiguration, ConfigurationExpansionError> {
        let embedded = proof_configuration.embed(document);
        let expanded = embedded.expand(self).await?;
        expanded.extract(self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ConfigurationExpansionError {
    #[error("JSON-LD expansion failed: {0}")]
    Expansion(String),

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

impl<E: fmt::Display> From<ssi_json_ld::JsonLdError<E>> for ConfigurationExpansionError {
    fn from(value: ssi_json_ld::JsonLdError<E>) -> Self {
        Self::Expansion(value.to_string())
    }
}

#[derive(Serialize)]
#[serde(bound = "S: SerializeCryptographicSuite")]
pub struct EmbeddedProofConfigurationRef<'d, 'a, S: CryptographicSuite> {
    #[serde(rename = "@context", default, skip_serializing_if = "Option::is_none")]
    context: Option<Cow<'d, json_ld::syntax::Context>>,

    #[serde(rename = "type", skip_serializing_if = "JsonLdTypes::is_empty")]
    type_: JsonLdTypes<'d>,

    proof: ProofConfigurationRef<'a, S>,
}

impl<'d, 'a, S: CryptographicSuite> JsonLdObject for EmbeddedProofConfigurationRef<'d, 'a, S> {
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        self.context.as_deref().map(Cow::Borrowed)
    }
}

impl<'d, 'a, S: CryptographicSuite> JsonLdNodeObject for EmbeddedProofConfigurationRef<'d, 'a, S> {
    fn json_ld_type(&self) -> JsonLdTypes {
        self.type_.reborrow()
    }
}

impl<'d, 'a, S: SerializeCryptographicSuite, E, V, L> Expandable<E>
    for EmbeddedProofConfigurationRef<'d, 'a, S>
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    L::Error: fmt::Display,
{
    type Error = ConfigurationExpansionError;
    type Expanded = ExpandedEmbeddedProofConfiguration<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let json = json_syntax::to_value(self).unwrap();
        Ok(ExpandedEmbeddedProofConfiguration(
            CompactJsonLd(json).expand(environment).await?,
        ))
    }
}

pub struct ExpandedEmbeddedProofConfiguration<I, B>(json_ld::ExpandedDocument<I, B>);

impl<I, B> ExpandedEmbeddedProofConfiguration<I, B>
where
    I: Clone + Eq + Hash,
    B: Clone + Eq + Hash,
{
    pub fn extract<E, V>(
        self,
        environment: &mut E,
    ) -> Result<ExpandedProofConfiguration, ConfigurationExpansionError>
    where
        E: AnyLdEnvironment<Vocabulary = V>,
        E::Interpretation: InterpretationMut<V>
            + ReverseTermInterpretation<Iri = I, BlankId = B, Literal = V::Literal>,
        <E::Interpretation as Interpretation>::Resource: Clone,
        V: VocabularyMut<Iri = I, BlankId = B>,
        I: LinkedDataResource<E::Interpretation, V> + LinkedDataSubject<E::Interpretation, V>,
        B: LinkedDataResource<E::Interpretation, V> + LinkedDataSubject<E::Interpretation, V>,
    {
        match self.0.into_main_node() {
            Some(node) => {
                let env = environment.as_ld_environment_mut();

                // Get the proof type IRI.
                let proof_prop = json_ld::Id::iri(
                    env.vocabulary
                        .get(ssi_security::PROOF)
                        .ok_or(ConfigurationExpansionError::MissingProof)?,
                );
                let proof_type = match node.get_any(&proof_prop) {
                    Some(proof) => match proof.as_node() {
                        Some(proof) => match &proof.graph {
                            Some(proof_graph) => match proof_graph.first() {
                                Some(proof) => match proof.as_node() {
                                    Some(proof) => match proof.types() {
                                        [json_ld::Id::Valid(Id::Iri(iri))] => {
                                            Ok(env.vocabulary.iri(iri).unwrap().to_owned())
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
                    env.vocabulary,
                    env.interpretation,
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
