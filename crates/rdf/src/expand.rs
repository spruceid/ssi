use linked_data::LinkedData;
use rdf_types::{
    interpretation::ReverseTermInterpretation,
    vocabulary::{BlankIdVocabulary, IriVocabulary, LiteralVocabulary},
    Interpretation, InterpretationMut, Vocabulary,
};

/// LD-Expandable value.
pub trait Expandable<E>: Sized {
    type Error: std::fmt::Display;

    type Expanded;

    #[allow(async_fn_in_trait)]
    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error>;
}

pub trait AnyLdEnvironment {
    type Vocabulary;

    type Interpretation: Interpretation;

    fn as_ld_environment_mut(
        &mut self,
    ) -> LdEnvironment<&mut Self::Vocabulary, &mut Self::Interpretation>;

    /// Returns the list of quads in the dataset.
    ///
    /// The order in which quads are returned is unspecified.
    fn quads_of<T: LinkedData<Self::Interpretation, Self::Vocabulary>>(
        &mut self,
        input: &T,
    ) -> Result<Vec<rdf_types::LexicalQuad>, linked_data::IntoQuadsError>
    where
        Self::Vocabulary: Vocabulary,
        Self::Interpretation: InterpretationMut<Self::Vocabulary>
            + ReverseTermInterpretation<
                Iri = <Self::Vocabulary as IriVocabulary>::Iri,
                BlankId = <Self::Vocabulary as BlankIdVocabulary>::BlankId,
                Literal = <Self::Vocabulary as LiteralVocabulary>::Literal,
            >,
    {
        let this = self.as_ld_environment_mut();
        linked_data::to_lexical_quads_with(this.vocabulary, this.interpretation, input)
    }

    fn canonical_quads_of<T: LinkedData<Self::Interpretation, Self::Vocabulary>>(
        &mut self,
        input: &T,
    ) -> Result<Vec<rdf_types::LexicalQuad>, linked_data::IntoQuadsError>
    where
        Self::Vocabulary: Vocabulary,
        Self::Interpretation: InterpretationMut<Self::Vocabulary>
            + ReverseTermInterpretation<
                Iri = <Self::Vocabulary as IriVocabulary>::Iri,
                BlankId = <Self::Vocabulary as BlankIdVocabulary>::BlankId,
                Literal = <Self::Vocabulary as LiteralVocabulary>::Literal,
            >,
    {
        let quads = self.quads_of(input)?;
        Ok(
            crate::urdna2015::normalize(quads.iter().map(|quad| quad.as_lexical_quad_ref()))
                .collect(),
        )
    }

    /// Returns the canonical form of the dataset, in the N-Quads format.
    fn canonical_form_of<T: LinkedData<Self::Interpretation, Self::Vocabulary>>(
        &mut self,
        input: &T,
    ) -> Result<Vec<String>, linked_data::IntoQuadsError>
    where
        Self::Vocabulary: Vocabulary,
        Self::Interpretation: InterpretationMut<Self::Vocabulary>
            + ReverseTermInterpretation<
                Iri = <Self::Vocabulary as IriVocabulary>::Iri,
                BlankId = <Self::Vocabulary as BlankIdVocabulary>::BlankId,
                Literal = <Self::Vocabulary as LiteralVocabulary>::Literal,
            >,
    {
        let quads = self.quads_of(input)?;
        Ok(
            crate::urdna2015::normalize(quads.iter().map(|quad| quad.as_lexical_quad_ref()))
                .into_nquads_lines(),
        )
    }
}

pub struct LdEnvironment<V = (), I = ()> {
    /// Vocabulary.
    pub vocabulary: V,

    /// Interpretation.
    pub interpretation: I,
}

impl<V, I> LdEnvironment<V, I> {
    pub fn new(vocabulary: V, interpretation: I) -> Self {
        Self {
            vocabulary,
            interpretation,
        }
    }
}

impl<V, I: Interpretation> AnyLdEnvironment for LdEnvironment<V, I> {
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

// impl<I, V, T> Expandable<LdEnvironment<V, I>> for T
// where
//     T: linked_data::LinkedDataSubject<I, V> + linked_data::LinkedDataResource<I, V>,
//     V: VocabularyMut,
//     V::Iri: Clone + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
//     V::BlankId: Clone + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
//     V::LanguageTag: Clone,
//     V::Value: From<String> + From<xsd_types::Value> + From<json_syntax::Value>,
//     V::Type: From<rdf_types::literal::Type<V::Iri, V::LanguageTag>>,
//     I: InterpretationMut<V>
//         + IriInterpretationMut<V::Iri>
//         + BlankIdInterpretationMut<V::BlankId>
//         + LiteralInterpretationMut<V::Literal>,
//     I::Resource: Clone + Ord,
// {
//     type Error = linked_data::IntoQuadsError;

//     type Resource = I::Resource;

//     async fn expand(
//         self,
//         environment: &mut LdEnvironment<V, I>,
//     ) -> Result<Expanded<Self, I::Resource>, Self::Error> {
//         let (subject, quads) = linked_data::to_interpreted_subject_quads(
//             &mut environment.vocabulary,
//             &mut environment.interpretation,
//             None,
//             &self,
//         )?;

//         Ok(Expanded::new(self, quads.into_iter().collect(), subject))
//     }
// }

// /// LD-Expanded value.
// pub struct Expanded<C, R = rdf_types::Term> {
//     /// Compact value.
//     compact: C,

//     /// Expanded value (the RDF dataset).
//     dataset: BTreeDataset<R>,

//     /// Resource representing the compact value in the dataset.
//     subject: R,
// }

// impl<C, R> Expanded<C, R> {
//     pub fn new(compact: C, dataset: BTreeDataset<R>, subject: R) -> Self {
//         Self {
//             compact,
//             dataset,
//             subject,
//         }
//     }

//     pub fn rdf_dataset(&self) -> &BTreeDataset<R> {
//         &self.dataset
//     }

//     pub fn rdf_subject(&self) -> &R {
//         &self.subject
//     }

//     pub fn into_rdf_parts(self) -> (BTreeDataset<R>, R) {
//         (self.dataset, self.subject)
//     }
// }

// impl<C, R> Deref for Expanded<C, R> {
//     type Target = C;

//     fn deref(&self) -> &Self::Target {
//         &self.compact
//     }
// }

// impl<C: serde::Serialize, R> serde::Serialize for Expanded<C, R> {
//     fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//         where
//             S: serde::Serializer {
//         self.compact.serialize(serializer)
//     }
// }

// impl<I, V, C> linked_data::LinkedDataResource<I, V> for Expanded<C, I::Resource>
// where
//     I: Interpretation,
//     V: Vocabulary,
// {
//     fn interpretation(
//         &self,
//         _vocabulary: &mut V,
//         _interpretation: &mut I,
//     ) -> linked_data::ResourceInterpretation<I, V> {
//         linked_data::ResourceInterpretation::Interpreted(&self.subject)
//     }
// }

// impl<I, V, C> linked_data::LinkedDataSubject<I, V> for Expanded<C, I::Resource>
// where
//     I: Interpretation,
//     I::Resource: Ord + Hash + LinkedDataResource<I, V>,
//     V: Vocabulary,
// {
//     fn visit_subject<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: linked_data::SubjectVisitor<I, V>,
//     {
//         self.dataset
//             .view(None, &self.subject, grdf::IdentityAccess)
//             .visit_subject(serializer)
//     }
// }

// impl<I, V, C> linked_data::LinkedDataPredicateObjects<I, V> for Expanded<C, I::Resource>
// where
//     I: Interpretation,
//     I::Resource: Ord + Hash + LinkedDataResource<I, V>,
//     V: Vocabulary,
// {
//     fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
//         where
//             S: linked_data::PredicateObjectsVisitor<I, V> {
//         visitor.object(self)?;
//         visitor.end()
//     }
// }

// impl<I, V, C> linked_data::LinkedDataGraph<I, V> for Expanded<C, I::Resource>
// where
//     I: Interpretation,
//     I::Resource: Ord + Hash + LinkedDataResource<I, V>,
//     V: Vocabulary,
// {
//     fn visit_graph<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
//         where
//             S: linked_data::GraphVisitor<I, V> {
//         visitor.subject(self)?;
//         visitor.end()
//     }
// }

// impl<I, V, C> linked_data::LinkedData<I, V> for Expanded<C, I::Resource>
// where
//     I: Interpretation,
//     I::Resource: Ord + Hash + LinkedDataResource<I, V>,
//     V: Vocabulary,
// {
//     fn visit<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
//         where
//             S: linked_data::Visitor<I, V> {
//         visitor.default_graph(self)?;
//         visitor.end()
//     }
// }
