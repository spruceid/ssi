use std::{borrow::Borrow, fmt};

use iref::IriBuf;
use rdf_types::Quad;

/// RDF DataSet produced form a JSON-LD document.
pub type DataSet =
    grdf::HashDataset<rdf_types::Subject, IriBuf, rdf_types::Object, rdf_types::GraphLabel>;

/// Quad iterator extension to produce an N-Quads document.
///
/// See <https://www.w3.org/TR/n-quads/>.
pub trait IntoNQuads {
    fn into_nquads(self) -> String;
    fn into_nquads_vec(self) -> Vec<String>;
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

    fn into_nquads_vec(self) -> Vec<String> {
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
pub struct NQuadsStatement<'a>(pub &'a Quad);

impl<'a> fmt::Display for NQuadsStatement<'a> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} .", self.0)
    }
}
