//! Linked-Data types.
mod context;

use std::{hash::Hash, ops::Deref};

pub use context::*;
use grdf::BTreeDataset;
use json_ld::Expand;
use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::{
    BlankIdInterpretationMut, Interpretation, InterpretationMut, IriInterpretationMut,
    LiteralInterpretationMut, Vocabulary, VocabularyMut,
};

/// LD-Expandable value.
pub trait Expandable<R, E>: Sized {
    type Error;

    #[allow(async_fn_in_trait)]
    async fn expand(self, environment: E) -> Result<Expanded<Self, R>, Self::Error>;
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
    vocabulary: V,

    /// Interpretation.
    interpretation: I,

    /// Document loader.
    loader: L,
}

impl<V, I, L> Expandable<I::Resource, JsonLdEnvironment<V, I, L>> for json_syntax::Value
where
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

    async fn expand(
        self,
        mut environment: JsonLdEnvironment<V, I, L>,
    ) -> Result<Expanded<Self, I::Resource>, Self::Error> {
        let expanded = self
            .expand_with(&mut environment.vocabulary, &mut environment.loader)
            .await?;

        match expanded.into_main_node() {
            Some(node) => {
                let (subject, quads) = linked_data::to_interpreted_subject_quads(
                    &mut environment.vocabulary,
                    &mut environment.interpretation,
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

pub struct LdEnvironment<V = (), I = ()> {
    /// Vocabulary.
    vocabulary: V,

    /// Interpretation.
    interpretation: I,
}

impl<I, V, T> Expandable<I::Resource, LdEnvironment<V, I>> for T
where
    T: linked_data::LinkedDataSubject<I, V> + linked_data::LinkedDataResource<I, V>,
    V: VocabularyMut,
    V::Iri: Clone + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::BlankId: Clone + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    V::LanguageTag: Clone,
    V::Value: From<String> + From<xsd_types::Value> + From<json_syntax::Value>,
    V::Type: From<rdf_types::literal::Type<V::Iri, V::LanguageTag>>,
    I: InterpretationMut<V>
        + IriInterpretationMut<V::Iri>
        + BlankIdInterpretationMut<V::BlankId>
        + LiteralInterpretationMut<V::Literal>,
    I::Resource: Clone + Ord,
{
    type Error = linked_data::IntoQuadsError;

    async fn expand(
        self,
        mut environment: LdEnvironment<V, I>,
    ) -> Result<Expanded<Self, I::Resource>, Self::Error> {
        let (subject, quads) = linked_data::to_interpreted_subject_quads(
            &mut environment.vocabulary,
            &mut environment.interpretation,
            None,
            &self,
        )?;

        Ok(Expanded::new(self, quads.into_iter().collect(), subject))
    }
}

/// LD-Expanded value.
pub struct Expanded<C, R> {
    /// Compact value.
    compact: C,

    /// Expanded value (the RDF dataset).
    dataset: BTreeDataset<R>,

    /// Resource representing the compact value in the dataset.
    subject: R,
}

impl<C, R> Expanded<C, R> {
    pub fn new(compact: C, dataset: BTreeDataset<R>, subject: R) -> Self {
        Self {
            compact,
            dataset,
            subject,
        }
    }

    pub fn rdf_dataset(&self) -> &BTreeDataset<R> {
        &self.dataset
    }

    pub fn rdf_subject(&self) -> &R {
        &self.subject
    }
}

impl<C, R> Deref for Expanded<C, R> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.compact
    }
}

impl<I, V, C> linked_data::LinkedDataSubject<I, V> for Expanded<C, I::Resource>
where
    I: Interpretation,
    I::Resource: Ord + Hash + LinkedDataResource<I, V>,
    V: Vocabulary,
{
    fn visit_subject<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        self.dataset
            .view(None, &self.subject, grdf::IdentityAccess)
            .visit_subject(serializer)
    }
}
