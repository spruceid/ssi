use linked_data::LinkedData;
use rdf_types::{
    generator,
    interpretation::{ReverseTermInterpretation, WithGenerator},
    vocabulary::{BlankIdVocabulary, IriVocabulary, LiteralVocabulary},
    Interpretation, InterpretationMut, Vocabulary,
};

pub trait AnyLdEnvironment {
    type Vocabulary;

    type Interpretation: Interpretation;

    fn as_ld_environment(&self) -> LdEnvironment<&Self::Vocabulary, &Self::Interpretation>;

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

pub struct LdEnvironment<V = (), I = WithGenerator<generator::Blank>> {
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

impl Default for LdEnvironment {
    fn default() -> Self {
        Self::new((), WithGenerator::new((), generator::Blank::new()))
    }
}

impl<V, I: Interpretation> AnyLdEnvironment for LdEnvironment<V, I> {
    type Vocabulary = V;
    type Interpretation = I;

    fn as_ld_environment(&self) -> LdEnvironment<&Self::Vocabulary, &Self::Interpretation> {
        LdEnvironment {
            vocabulary: &self.vocabulary,
            interpretation: &self.interpretation,
        }
    }

    fn as_ld_environment_mut(
        &mut self,
    ) -> LdEnvironment<&mut Self::Vocabulary, &mut Self::Interpretation> {
        LdEnvironment {
            vocabulary: &mut self.vocabulary,
            interpretation: &mut self.interpretation,
        }
    }
}
