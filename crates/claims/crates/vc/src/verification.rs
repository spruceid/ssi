// use std::{marker::PhantomData, ops::Deref};

// use educe::Educe;
// use linked_data::{LinkedData, LinkedDataGraph, LinkedDataPredicateObjects, LinkedDataSubject};
// use rdf_types::{Interpretation, Vocabulary};
// use ssi_claims_core::{Verifiable, VerifiableWith};

// use crate::{Credential, Presentation, Validate, VerifiableClaims};

// impl<T, P> ssi_claims_core::Provable for Claims<T, P>
// where
//     P: ProofType,
// {
//     type Proof = Vec<P::Prepared>;
// }

// impl<T, P, V> VerifiableWith<V> for Claims<T, P>
// where
//     T: Validate,
//     P: ProofType,
//     P::Prepared: VerifyPreparedWith<V>,
// {
//     type Error = <P::Prepared as VerifyPreparedWith<V>>::Error;

//     async fn verify_with<'a>(
//         &'a self,
//         verifier: &'a V,
//         proof: &'a Self::Proof,
//     ) -> Result<ssi_claims_core::ProofValidity, Self::Error> {
//         if !self.is_valid() {
//             // The proof is invalidated by impossible claims.
//             return Ok(ssi_claims_core::ProofValidity::Invalid);
//         }

//         if proof.is_empty() {
//             // No proof means no valid proof.
//             return Ok(ssi_claims_core::ProofValidity::Invalid);
//         }

//         for p in proof {
//             if p.verify_prepared_with(verifier).await?.is_invalid() {
//                 return Ok(ssi_claims_core::ProofValidity::Invalid);
//             }
//         }

//         Ok(ssi_claims_core::ProofValidity::Valid)
//     }
// }

// impl<I: Interpretation, V: Vocabulary, T: LinkedDataSubject<I, V>, P> LinkedDataSubject<I, V>
//     for Claims<T, P>
// {
//     fn visit_subject<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
//     where
//         S: linked_data::SubjectVisitor<I, V>,
//     {
//         self.value.visit_subject(serializer)
//     }
// }

// impl<I: Interpretation, V: Vocabulary, T: LinkedDataPredicateObjects<I, V>, P>
//     LinkedDataPredicateObjects<I, V> for Claims<T, P>
// {
//     fn visit_objects<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
//     where
//         S: linked_data::PredicateObjectsVisitor<I, V>,
//     {
//         self.value.visit_objects(visitor)
//     }
// }

// impl<I: Interpretation, V: Vocabulary, T: LinkedDataGraph<I, V>, P> LinkedDataGraph<I, V>
//     for Claims<T, P>
// {
//     fn visit_graph<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
//     where
//         S: linked_data::GraphVisitor<I, V>,
//     {
//         self.value.visit_graph(visitor)
//     }
// }

// impl<I: Interpretation, V: Vocabulary, T: LinkedData<I, V>, P> LinkedData<I, V> for Claims<T, P> {
//     fn visit<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
//     where
//         S: linked_data::Visitor<I, V>,
//     {
//         self.value.visit(visitor)
//     }
// }

// pub trait VerifyPreparedWith<V> {
//     type Error;

//     #[allow(async_fn_in_trait)]
//     async fn verify_prepared_with<'a>(
//         &'a self,
//         verifier: &'a V,
//     ) -> Result<ssi_claims_core::ProofValidity, Self::Error>;
// }
