use linked_data::{LinkedDataPredicateObjects, LinkedDataSubject};
use rdf_types::{Interpretation, VocabularyMut};
use ssi_claims_core::linked_data::{
    LinkedDataClaims, LinkedDataGraphClaims, LinkedDataSubjectClaims,
};

use crate::{CryptographicSuite, DataIntegrity, DataIntegrityWithProof};

impl<I: Interpretation, V: VocabularyMut, T, S: CryptographicSuite> LinkedDataClaims<I, V>
    for DataIntegrity<T, S>
where
    V::Value: From<String> + From<xsd_types::Value> + From<linked_data::json_syntax::Value>,
    T: LinkedDataSubject<I, V>,
    S::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    S::Options: LinkedDataSubject<I, V>,
    S::Signature: LinkedDataSubject<I, V>,
{
    fn visit_with_proof<R>(&self, proof: &Self::Proof, visitor: R) -> Result<R::Ok, R::Error>
    where
        R: linked_data::Visitor<I, V>,
    {
        linked_data::LinkedData::visit(
            &DataIntegrityWithProof {
                claims: self,
                proof,
            },
            visitor,
        )
    }
}

impl<I: Interpretation, V: VocabularyMut, T, S: CryptographicSuite> LinkedDataSubjectClaims<I, V>
    for DataIntegrity<T, S>
where
    V::Value: From<String> + From<xsd_types::Value> + From<linked_data::json_syntax::Value>,
    T: LinkedDataSubject<I, V>,
    S::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    S::Options: LinkedDataSubject<I, V>,
    S::Signature: LinkedDataSubject<I, V>,
{
    fn visit_subject_with_proof<R>(
        &self,
        proof: &Self::Proof,
        visitor: R,
    ) -> Result<R::Ok, R::Error>
    where
        R: linked_data::SubjectVisitor<I, V>,
    {
        linked_data::LinkedDataSubject::visit_subject(
            &DataIntegrityWithProof {
                claims: self,
                proof,
            },
            visitor,
        )
    }
}

impl<I: Interpretation, V: VocabularyMut, T, S: CryptographicSuite> LinkedDataGraphClaims<I, V>
    for DataIntegrity<T, S>
where
    V::Value: From<String> + From<xsd_types::Value> + From<linked_data::json_syntax::Value>,
    T: LinkedDataSubject<I, V>,
    S::VerificationMethod: LinkedDataPredicateObjects<I, V>,
    S::Options: LinkedDataSubject<I, V>,
    S::Signature: LinkedDataSubject<I, V>,
{
    fn visit_graph_with_proof<R>(&self, proof: &Self::Proof, visitor: R) -> Result<R::Ok, R::Error>
    where
        R: linked_data::GraphVisitor<I, V>,
    {
        linked_data::LinkedDataGraph::visit_graph(
            &DataIntegrityWithProof {
                claims: self,
                proof,
            },
            visitor,
        )
    }
}
