//! Resource Description Framework (RDF) utilities, including the URDNA2015
//! canonicalization algorithm.
use std::{borrow::Borrow, fmt};

mod expand;
pub mod urdna2015;

pub use expand::*;
use rdf_types::{
    dataset::IndexedBTreeDataset,
    interpretation::{ReverseTermInterpretation, WithGenerator},
    vocabulary::{ByRef, ExtractFromVocabulary, Predicate},
};

pub use rdf_types::{
    generator, interpretation, vocabulary, Interpretation, InterpretationMut, LexicalQuad,
    LexicalQuadRef, Vocabulary, VocabularyMut,
};

pub use linked_data::{LinkedData, LinkedDataResource, LinkedDataSubject};

pub type LexicalInterpretation = WithGenerator<generator::Blank>;

/// Interpreted RDF dataset with an entry point.
pub struct DatasetWithEntryPoint<'a, V, I: Interpretation> {
    pub vocabulary: &'a V,
    pub interpretation: &'a I,
    pub dataset: IndexedBTreeDataset<I::Resource>,
    pub entry_point: I::Resource,
}

impl<'a, V, I: Interpretation> DatasetWithEntryPoint<'a, V, I> {
    pub fn new(
        vocabulary: &'a V,
        interpretation: &'a I,
        dataset: IndexedBTreeDataset<I::Resource>,
        entry_point: I::Resource,
    ) -> Self {
        Self {
            vocabulary,
            interpretation,
            dataset,
            entry_point,
        }
    }

    /// Returns the list of quads in the dataset.
    ///
    /// The order in which quads are returned is unspecified.
    pub fn into_quads(&self) -> Vec<LexicalQuad>
    where
        V: Vocabulary,
        I: ReverseTermInterpretation<Iri = V::Iri, BlankId = V::BlankId, Literal = V::Literal>,
    {
        // TODO: make sure that a blank node identifier is assigned to resources
        //       without lexical representation.
        self.dataset
            .iter()
            .flat_map(|quad| {
                self.interpretation.quads_of(quad).map(|q| {
                    ByRef(q.map_predicate(Predicate)).extract_from_vocabulary(self.vocabulary)
                })
            })
            .collect()
    }

    /// Returns the canonical form of the dataset, in the N-Quads format.
    pub fn canonical_form(&self) -> String
    where
        V: Vocabulary,
        I: ReverseTermInterpretation<Iri = V::Iri, BlankId = V::BlankId, Literal = V::Literal>,
    {
        let quads = self.into_quads();
        urdna2015::normalize(quads.iter().map(|quad| quad.as_lexical_quad_ref())).into_nquads()
    }
}

/// RDF DataSet produced form a JSON-LD document.
pub type DataSet = IndexedBTreeDataset<rdf_types::Term>;

/// Quad iterator extension to produce an N-Quads document.
///
/// See <https://www.w3.org/TR/n-quads/>.
pub trait IntoNQuads: Sized {
    fn into_nquads_lines(self) -> Vec<String>;

    fn into_nquads(self) -> String {
        self.into_nquads_lines().join("")
    }
}

impl<Q: IntoIterator> IntoNQuads for Q
where
    Q::Item: Borrow<LexicalQuad>,
{
    fn into_nquads_lines(self) -> Vec<String> {
        let mut lines = self
            .into_iter()
            .map(|quad| NQuadsStatement(quad.borrow()).to_string())
            .collect::<Vec<String>>();
        lines.sort();
        lines.dedup();
        lines
    }
}

/// Wrapper to display an RDF Quad as an N-Quads statement.
pub struct NQuadsStatement<'a>(pub &'a LexicalQuad);

impl<'a> fmt::Display for NQuadsStatement<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} .", self.0)
    }
}
