use linked_data::{LinkedDataResource, LinkedDataSubject};
use rdf_types::{Interpretation, VocabularyMut};
use ssi_claims_core::linked_data::{
    LinkedDataClaims, LinkedDataGraphClaims, LinkedDataSubjectClaims,
};

use crate::verification::{Claims, ProofType};

#[derive(linked_data::Serialize)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
struct ClaimsWithProofs<'a, T, P> {
    #[ld(flatten)]
    claims: &'a T,

    #[ld("sec:proof", graph)]
    proofs: &'a [P],
}

impl<I: Interpretation, V: VocabularyMut, T, P: ProofType> LinkedDataClaims<I, V> for Claims<T, P>
where
    V::Value: From<String> + From<xsd_types::Value> + From<linked_data::json_syntax::Value>,
    T: LinkedDataSubject<I, V>,
    P::Prepared: LinkedDataSubject<I, V> + LinkedDataResource<I, V>,
{
    fn visit_with_proof<R>(&self, proofs: &Self::Proof, visitor: R) -> Result<R::Ok, R::Error>
    where
        R: linked_data::Visitor<I, V>,
    {
        linked_data::LinkedData::visit(
            &ClaimsWithProofs {
                claims: &**self,
                proofs,
            },
            visitor,
        )
    }
}

impl<I: Interpretation, V: VocabularyMut, T, P: ProofType> LinkedDataSubjectClaims<I, V>
    for Claims<T, P>
where
    V::Value: From<String> + From<xsd_types::Value> + From<linked_data::json_syntax::Value>,
    T: LinkedDataSubject<I, V>,
    P::Prepared: LinkedDataSubject<I, V> + LinkedDataResource<I, V>,
{
    fn visit_subject_with_proof<R>(
        &self,
        proofs: &Self::Proof,
        visitor: R,
    ) -> Result<R::Ok, R::Error>
    where
        R: linked_data::SubjectVisitor<I, V>,
    {
        linked_data::LinkedDataSubject::visit_subject(
            &ClaimsWithProofs {
                claims: &**self,
                proofs,
            },
            visitor,
        )
    }
}

impl<I: Interpretation, V: VocabularyMut, T, P: ProofType> LinkedDataGraphClaims<I, V>
    for Claims<T, P>
where
    V::Value: From<String> + From<xsd_types::Value> + From<linked_data::json_syntax::Value>,
    T: LinkedDataSubject<I, V>,
    P::Prepared: LinkedDataSubject<I, V> + LinkedDataResource<I, V>,
{
    fn visit_graph_with_proof<R>(&self, proofs: &Self::Proof, visitor: R) -> Result<R::Ok, R::Error>
    where
        R: linked_data::GraphVisitor<I, V>,
    {
        linked_data::LinkedDataGraph::visit_graph(
            &ClaimsWithProofs {
                claims: &**self,
                proofs,
            },
            visitor,
        )
    }
}
