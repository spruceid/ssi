use crate::{Provable, Verifiable};
use linked_data::{
    rdf_types::{Interpretation, Vocabulary},
    GraphVisitor, LinkedData, LinkedDataGraph, LinkedDataResource, LinkedDataSubject,
    SubjectVisitor, Visitor,
};

impl<I: Interpretation, V: Vocabulary, C: Provable + LinkedDataResource<I, V>>
    LinkedDataResource<I, V> for Verifiable<C>
{
    fn interpretation(
        &self,
        vocabulary: &mut V,
        interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        self.claims.interpretation(vocabulary, interpretation)
    }
}

/// Linked-Data claims.
pub trait LinkedDataClaims<I: Interpretation, V: Vocabulary>: Provable {
    fn visit_with_proof<S>(&self, proof: &Self::Proof, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: Visitor<I, V>;
}

impl<I: Interpretation, V: Vocabulary, C: LinkedDataClaims<I, V>> LinkedData<I, V>
    for Verifiable<C>
{
    fn visit<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: Visitor<I, V>,
    {
        self.claims.visit_with_proof(&self.proof, visitor)
    }
}

/// Linked-Data subject claims.
pub trait LinkedDataSubjectClaims<I: Interpretation, V: Vocabulary>: Provable {
    fn visit_subject_with_proof<S>(
        &self,
        proof: &Self::Proof,
        visitor: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: SubjectVisitor<I, V>;
}

impl<I: Interpretation, V: Vocabulary, C: LinkedDataSubjectClaims<I, V>> LinkedDataSubject<I, V>
    for Verifiable<C>
{
    fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: SubjectVisitor<I, V>,
    {
        self.claims.visit_subject_with_proof(&self.proof, visitor)
    }
}

/// Linked-Data graph claims.
pub trait LinkedDataGraphClaims<I: Interpretation, V: Vocabulary>: Provable {
    fn visit_graph_with_proof<S>(&self, proof: &Self::Proof, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: GraphVisitor<I, V>;
}

impl<I: Interpretation, V: Vocabulary, C: LinkedDataGraphClaims<I, V>> LinkedDataGraph<I, V>
    for Verifiable<C>
{
    fn visit_graph<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: GraphVisitor<I, V>,
    {
        self.claims.visit_graph_with_proof(&self.proof, visitor)
    }
}
