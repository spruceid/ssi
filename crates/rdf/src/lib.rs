//! Resource Description Framework (RDF) utilities, including the URDNA2015
//! canonicalization algorithm.
use std::{borrow::Borrow, fmt};

mod expand;
pub mod urdna2015;

pub use expand::*;
use iref::IriBuf;
use rdf_types::{
    ExportRefFromVocabulary, Interpretation, IriVocabulary, LanguageTagVocabulary, Quad,
    ReverseTermInterpretation, Vocabulary,
};

/// Interpreted RDF dataset with an entry point.
pub struct DatasetWithEntryPoint<'a, V, I: Interpretation> {
    pub vocabulary: &'a V,
    pub interpretation: &'a I,
    pub dataset: grdf::HashDataset<I::Resource, I::Resource, I::Resource, I::Resource>,
    pub entry_point: I::Resource,
}

impl<'a, V, I: Interpretation> DatasetWithEntryPoint<'a, V, I> {
    pub fn new(
        vocabulary: &'a V,
        interpretation: &'a I,
        dataset: grdf::HashDataset<I::Resource, I::Resource, I::Resource, I::Resource>,
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
    pub fn into_quads(&self) -> Vec<Quad>
    where
        V: Vocabulary<
            Type = rdf_types::literal::Type<
                <V as IriVocabulary>::Iri,
                <V as LanguageTagVocabulary>::LanguageTag,
            >,
            Value = String,
        >,
        I: ReverseTermInterpretation<Iri = V::Iri, BlankId = V::BlankId, Literal = V::Literal>,
    {
        // TODO: make sure that a blank node identifier is assigned to resources
        //       without lexical representation.
        self.dataset
            .quads()
            .flat_map(|quad| {
                self.interpretation.quads_of(quad).map(|Quad(s, p, o, g)| {
                    Quad(
                        s.export_ref_from_vocabulary(self.vocabulary),
                        self.vocabulary.iri(p).unwrap().to_owned(),
                        o.export_ref_from_vocabulary(self.vocabulary),
                        g.export_ref_from_vocabulary(self.vocabulary),
                    )
                })
            })
            .collect()
    }

    /// Returns the canonical form of the dataset, in the N-Quads format.
    pub fn canonical_form(&self) -> String
    where
        V: Vocabulary<
            Type = rdf_types::literal::Type<
                <V as IriVocabulary>::Iri,
                <V as LanguageTagVocabulary>::LanguageTag,
            >,
            Value = String,
        >,
        I: ReverseTermInterpretation<Iri = V::Iri, BlankId = V::BlankId, Literal = V::Literal>,
    {
        let quads = self.into_quads();
        urdna2015::normalize(quads.iter().map(|quad| quad.as_quad_ref())).into_nquads()
    }
}

/// RDF DataSet produced form a JSON-LD document.
pub type DataSet =
    grdf::HashDataset<rdf_types::Subject, IriBuf, rdf_types::Object, rdf_types::GraphLabel>;

/// Quad iterator extension to produce an N-Quads document.
///
/// See <https://www.w3.org/TR/n-quads/>.
pub trait IntoNQuads {
    fn into_nquads(self) -> String;
}

impl<Q: IntoIterator> IntoNQuads for Q
where
    Q::Item: Borrow<Quad>,
{
    fn into_nquads(self) -> String {
        let mut lines = self
            .into_iter()
            .map(|quad| NQuadsStatement(quad.borrow()).to_string())
            .collect::<Vec<String>>();
        lines.sort();
        lines.dedup();
        lines.join("")
    }
}

/// Wrapper to display an RDF Quad as an N-Quads statement.
pub struct NQuadsStatement<'a>(pub &'a Quad);

impl<'a> fmt::Display for NQuadsStatement<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} .", self.0)
    }
}
