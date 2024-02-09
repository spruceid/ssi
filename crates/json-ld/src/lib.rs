//! Linked-Data types.
mod context;

use std::{borrow::Cow, hash::Hash};

pub use context::*;
use json_ld::{Expand, Loader};
use linked_data::{LinkedDataResource, LinkedDataSubject};
use mown::Mown;
use rdf_types::{
    generator, interpretation::WithGenerator, BlankIdInterpretationMut, Interpretation,
    InterpretationMut, IriInterpretationMut, IriVocabulary, LiteralInterpretationMut, Vocabulary,
    VocabularyMut,
};
use ssi_rdf::{AnyLdEnvironment, Expandable, LdEnvironment};

pub trait AnyJsonLdEnvironment: AnyLdEnvironment
where
    Self::Vocabulary: IriVocabulary,
{
    type Loader: Loader<<Self::Vocabulary as IriVocabulary>::Iri>;

    fn as_json_ld_environment_mut(
        &mut self,
    ) -> JsonLdEnvironment<&mut Self::Vocabulary, &mut Self::Interpretation, &mut Self::Loader>;
}

#[derive(Debug, thiserror::Error)]
pub enum JsonLdError<E> {
    #[error("expansion error: {0}")]
    Expansion(#[from] json_ld::expansion::Error<E>),

    #[error("interpretation error: {0}")]
    Interpretation(#[from] linked_data::IntoQuadsError),
}

pub struct JsonLdEnvironment<V = (), I = WithGenerator<generator::Blank>, L = ContextLoader> {
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

    fn as_ld_environment_mut(
        &mut self,
    ) -> LdEnvironment<&mut Self::Vocabulary, &mut Self::Interpretation> {
        LdEnvironment {
            vocabulary: &mut self.vocabulary,
            interpretation: &mut self.interpretation,
        }
    }
}

impl<V: IriVocabulary, I: Interpretation, L: Loader<V::Iri>> AnyJsonLdEnvironment
    for JsonLdEnvironment<V, I, L>
{
    type Loader = L;

    fn as_json_ld_environment_mut(
        &mut self,
    ) -> JsonLdEnvironment<&mut Self::Vocabulary, &mut Self::Interpretation, &mut Self::Loader>
    {
        JsonLdEnvironment {
            vocabulary: &mut self.vocabulary,
            interpretation: &mut self.interpretation,
            loader: &mut self.loader,
        }
    }
}

impl Default for JsonLdEnvironment {
    fn default() -> Self {
        Self {
            vocabulary: (),
            interpretation: WithGenerator::new((), generator::Blank::new()),
            loader: ContextLoader::default(),
        }
    }
}

#[repr(transparent)]
pub struct CompactJsonLd(pub json_syntax::Value);

impl CompactJsonLd {
    pub fn from_value_ref(value: &json_syntax::Value) -> &Self {
        unsafe { std::mem::transmute(value) }
    }
}

impl<V, L, E> Expandable<E> for CompactJsonLd
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    //
    V: Send + Sync,
    V::Iri: Send + Sync,
    V::BlankId: Send + Sync,
    L: Send + Sync,
    L::Error: Send,
{
    type Error = JsonLdError<L::Error>;

    // type Resource = I::Resource;
    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        let environment = environment.as_json_ld_environment_mut();

        let expanded = self
            .0
            .expand_with(environment.vocabulary, environment.loader)
            .await?;

        // match expanded.into_main_node() {
        //     Some(node) => {
        //         let (subject, quads) = linked_data::to_interpreted_subject_quads(
        //             environment.vocabulary,
        //             environment.interpretation,
        //             None,
        //             &node,
        //         )?;

        //         Ok(Expanded::new(self, quads.into_iter().collect(), subject))
        //     }
        //     None => {
        //         todo!()
        //     }
        // }
        Ok(expanded)
    }
}
