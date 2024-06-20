use crate::{Proof, Verifiable};
use linked_data::{
    rdf_types::{Interpretation, Vocabulary},
    GraphVisitor, LinkedData, LinkedDataGraph, LinkedDataResource, LinkedDataSubject,
    SubjectVisitor, Visitor,
};

impl<I: Interpretation, V: Vocabulary, C: LinkedDataResource<I, V>, P: Proof>
    LinkedDataResource<I, V> for Verifiable<C, P>
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
pub trait LinkedDataClaims<P: Proof, I: Interpretation, V: Vocabulary> {
    fn visit_with_proof<S>(&self, proof: &P::Prepared, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: Visitor<I, V>;
}

impl<I: Interpretation, V: Vocabulary, C: LinkedDataClaims<P, I, V>, P: Proof> LinkedData<I, V>
    for Verifiable<C, P>
{
    fn visit<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: Visitor<I, V>,
    {
        self.claims.visit_with_proof(&self.proof, visitor)
    }
}

/// Linked-Data subject claims.
pub trait LinkedDataSubjectClaims<P: Proof, I: Interpretation, V: Vocabulary> {
    fn visit_subject_with_proof<S>(
        &self,
        proof: &P::Prepared,
        visitor: S,
    ) -> Result<S::Ok, S::Error>
    where
        S: SubjectVisitor<I, V>;
}

impl<I: Interpretation, V: Vocabulary, C: LinkedDataSubjectClaims<P, I, V>, P: Proof>
    LinkedDataSubject<I, V> for Verifiable<C, P>
{
    fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: SubjectVisitor<I, V>,
    {
        self.claims.visit_subject_with_proof(&self.proof, visitor)
    }
}

/// Linked-Data graph claims.
pub trait LinkedDataGraphClaims<P: Proof, I: Interpretation, V: Vocabulary> {
    fn visit_graph_with_proof<S>(&self, proof: &P::Prepared, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: GraphVisitor<I, V>;
}

impl<I: Interpretation, V: Vocabulary, C: LinkedDataGraphClaims<P, I, V>, P: Proof>
    LinkedDataGraph<I, V> for Verifiable<C, P>
{
    fn visit_graph<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: GraphVisitor<I, V>,
    {
        self.claims.visit_graph_with_proof(&self.proof, visitor)
    }
}
