//! Linked-Data types.
mod context;

use std::hash::Hash;

pub use context::*;
use json_ld::{Expand, Loader};
use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::{
    BlankIdInterpretationMut, Interpretation, InterpretationMut, IriInterpretationMut, IriVocabulary, LiteralInterpretationMut, Vocabulary, VocabularyMut
};
use ssi_rdf::{AnyLdEnvironment, Expandable, Expanded, LdEnvironment};

pub trait AnyJsonLdEnvironment: AnyLdEnvironment where Self::Vocabulary: IriVocabulary {
    type Loader: Loader<<Self::Vocabulary as IriVocabulary>::Iri>;

    fn as_json_ld_environment_mut(&mut self) -> JsonLdEnvironment<&mut Self::Vocabulary, &mut Self::Interpretation, &mut Self::Loader>;
}

#[derive(Debug, thiserror::Error)]
pub enum JsonLdError<E> {
    #[error("expansion error: {0}")]
    Expansion(#[from] json_ld::expansion::Error<E>),

    #[error("interpretation error: {0}")]
    Interpretation(#[from] linked_data::IntoQuadsError),
}

pub struct JsonLdEnvironment<V = (), I = (), L = ContextLoader> {
    /// Vocabulary.
    pub vocabulary: V,

    /// Interpretation.
    pub interpretation: I,

    /// Document loader.
    pub loader: L,
}

impl<V: IriVocabulary, I: Interpretation, L> AnyLdEnvironment for JsonLdEnvironment<V, I, L> {
    type Vocabulary = V;
    type Interpretation = I;

    fn as_ld_environment_mut(&mut self) -> LdEnvironment<&mut Self::Vocabulary, &mut Self::Interpretation> {
        LdEnvironment {
            vocabulary: &mut self.vocabulary,
            interpretation: &mut self.interpretation
        }
    }
}

impl<V: IriVocabulary, I: Interpretation, L: Loader<V::Iri>> AnyJsonLdEnvironment for JsonLdEnvironment<V, I, L> {
    type Loader = L;

    fn as_json_ld_environment_mut(&mut self) -> JsonLdEnvironment<&mut Self::Vocabulary, &mut Self::Interpretation, &mut Self::Loader> {
        JsonLdEnvironment {
            vocabulary: &mut self.vocabulary,
            interpretation: &mut self.interpretation,
            loader: &mut self.loader
        }
    }
}

pub struct CompactJsonLd(pub json_syntax::Value);

impl<V, I, L, E> Expandable<E> for CompactJsonLd
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Interpretation = I, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::LanguageTag: Clone,
    V::Value: From<String> + From<xsd_types::Value> + From<json_syntax::Value>,
    V::Type: From<rdf_types::literal::Type<V::Iri, V::LanguageTag>>,
    I: InterpretationMut<V>
        + IriInterpretationMut<V::Iri>
        + BlankIdInterpretationMut<V::BlankId>
        + LiteralInterpretationMut<V::Literal>,
    I::Resource: Clone + Ord,
    L: json_ld::Loader<V::Iri>,
    //
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send,
{
    type Error = JsonLdError<L::Error>;

    type Resource = I::Resource;

    async fn expand(
        self,
        environment: &mut E,
    ) -> Result<Expanded<Self, I::Resource>, Self::Error> {
        let environment = environment.as_json_ld_environment_mut();

        let expanded = self.0
            .expand_with(environment.vocabulary, environment.loader)
            .await?;

        match expanded.into_main_node() {
            Some(node) => {
                let (subject, quads) = linked_data::to_interpreted_subject_quads(
                    environment.vocabulary,
                    environment.interpretation,
                    None,
                    &node,
                )?;

                Ok(Expanded::new(self, quads.into_iter().collect(), subject))
            }
            None => {
                todo!()
            }
        }
    }
}