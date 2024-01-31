use crate::{Provable, Verifiable};
use linked_data::{rdf_types::{Interpretation, Vocabulary}, LinkedData, Visitor};

/// Linked-Data claims.
pub trait LinkedDataClaims<I: Interpretation, V: Vocabulary>: Provable {
    fn visit_with_proof<S>(&self, proof: &Self::Proof, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: Visitor<I, V>;
}

impl<I: Interpretation, V: Vocabulary, C: LinkedDataClaims<I, V>> LinkedData<I, V> for Verifiable<C> {
    fn visit<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: Visitor<I, V>
    {
        self.claims.visit_with_proof(&self.proof, visitor)
    }
}