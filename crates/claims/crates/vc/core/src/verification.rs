use std::{marker::PhantomData, ops::Deref};

use educe::Educe;
use linked_data::{LinkedData, LinkedDataGraph, LinkedDataPredicateObjects, LinkedDataSubject};
use rdf_types::{Interpretation, Vocabulary};
use ssi_claims_core::{Verifiable, VerifiableWith};

use crate::{Credential, Presentation, Validate, VerifiableClaims};

/// Proof extraction trait.
///
/// Implemented by credential and presentation types that can be separated from
/// their proof value(s).
pub trait ExtractProofs: Sized + VerifiableClaims {
    type Proofless;

    fn extract_proofs(self) -> (Self::Proofless, Vec<Self::Proof>);
}

pub trait MergeWithProofs<P> {
    type WithProofs;

    fn merge_with_proofs(self, proofs: Vec<P>) -> Self::WithProofs;
}

/// Proof type.
pub trait ProofType {
    /// Prepared proof type.
    type Prepared;
}

pub trait PrepareWith<T, E = ()>: ProofType {
    type Error;

    #[allow(async_fn_in_trait)]
    async fn prepare_with(
        self,
        value: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, Self::Error>;
}

/// Prepared verifiable credential or presentation.
#[derive(Educe)]
#[educe(
    Debug(bound = "T: core::fmt::Debug"),
    Clone(bound = "T: Clone"),
    PartialEq(bound = "T: PartialEq"),
    Eq(bound = "T: Eq"),
    PartialOrd(bound = "T: PartialOrd"),
    Ord(bound = "T: Ord"),
    Hash(bound = "T: core::hash::Hash")
)]
pub struct Claims<T, P> {
    /// Credential or presentation without the proof.
    value: T,

    /// Prepared proofs.
    proofs: PhantomData<P>,
}

impl<T, P> Claims<T, P> {
    pub fn value(&self) -> &T {
        &self.value
    }
}

impl<T: Credential, P> Claims<T, P> {
    pub fn credential(&self) -> &T {
        &self.value
    }
}

impl<T: Presentation, P> Claims<T, P> {
    pub fn presentation(&self) -> &T {
        &self.value
    }
}

impl<T: Copy, P> Copy for Claims<T, P> {}

impl<T, P> Deref for Claims<T, P> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.value
    }
}

/// Verifiable credential (or presentation) claims, without the proof.
impl<T, P> Claims<T, P> {
    pub fn from_proofless(value: T) -> Self {
        Self {
            value,
            proofs: PhantomData,
        }
    }

    pub async fn new<U, E>(value: U) -> Result<Verifiable<Self>, P::Error>
    where
        U: ExtractProofs<Proofless = T, Proof = P>,
        P: ProofType + PrepareWith<T, E>,
        E: Default,
    {
        Self::new_with(value, E::default()).await
    }

    pub async fn new_with<U, E>(value: U, mut environment: E) -> Result<Verifiable<Self>, P::Error>
    where
        U: ExtractProofs<Proofless = T, Proof = P>,
        P: ProofType + PrepareWith<T, E>,
    {
        let (value, raw_proofs) = value.extract_proofs();

        let mut proofs = Vec::with_capacity(raw_proofs.len());
        for p in raw_proofs {
            proofs.push(p.prepare_with(&value, &mut environment).await?)
        }

        Ok(Verifiable::new(Self::from_proofless(value), proofs))
    }

    /// Merge the claims with their proof(s).
    ///
    /// This will effectively unprepare the proof and make them unverifiable
    /// until [`Self::new`] is called again.
    pub fn unprepare(this: Verifiable<Self>) -> T::WithProofs
    where
        T: MergeWithProofs<P>,
        P: ProofType,
        P::Prepared: UnprepareProof<Unprepared = P>,
    {
        let (claims, prepared_proofs) = this.into_parts();
        let proofs = prepared_proofs
            .into_iter()
            .map(P::Prepared::unprepare)
            .collect();
        T::merge_with_proofs(claims.value, proofs)
    }

    /// Tamper with the claims without changing the proofs.
    ///
    /// The proofs may become invalid.
    pub async fn tamper<U, E>(
        verifiable_claims: Verifiable<Self>,
        environment: E,
        f: impl FnOnce(T) -> U,
    ) -> Result<Verifiable<Claims<U, P>>, P::Error>
    where
        P: ProofType,
        P: PrepareWith<U, E>,
        P::Prepared: UnprepareProof<Unprepared = P>,
    {
        Self::tamper_with_proofs(verifiable_claims, environment, f, |p| p).await
    }

    /// Tamper with the claims and proofs.
    ///
    /// The proofs may become invalid.
    pub async fn tamper_with_proofs<U, E>(
        verifiable_claims: Verifiable<Self>,
        mut environment: E,
        f: impl FnOnce(T) -> U,
        mut g: impl FnMut(P) -> P,
    ) -> Result<Verifiable<Claims<U, P>>, P::Error>
    where
        P: ProofType,
        P: PrepareWith<U, E>,
        P::Prepared: UnprepareProof<Unprepared = P>,
    {
        verifiable_claims
            .async_try_map(|value, proofs| async {
                let u = f(value.value);

                let mut new_proofs = Vec::with_capacity(proofs.len());
                for p in proofs {
                    let unprepared_proof = g(p.unprepare());
                    new_proofs.push(unprepared_proof.prepare_with(&u, &mut environment).await?)
                }

                Ok((Claims::from_proofless(u), new_proofs))
            })
            .await
    }
}

pub trait UnprepareProof {
    type Unprepared: ProofType<Prepared = Self>;

    fn unprepare(self) -> Self::Unprepared;
}

impl<T, P> ssi_claims_core::Provable for Claims<T, P>
where
    P: ProofType,
{
    type Proof = Vec<P::Prepared>;
}

impl<T, P, V> VerifiableWith<V> for Claims<T, P>
where
    T: Validate,
    P: ProofType,
    P::Prepared: VerifyPreparedWith<V>,
{
    type Error = <P::Prepared as VerifyPreparedWith<V>>::Error;

    async fn verify_with<'a>(
        &'a self,
        verifier: &'a V,
        proof: &'a Self::Proof,
    ) -> Result<ssi_claims_core::ProofValidity, Self::Error> {
        if !self.is_valid() {
            // The proof is invalidated by impossible claims.
            return Ok(ssi_claims_core::ProofValidity::Invalid);
        }

        if proof.is_empty() {
            // No proof means no valid proof.
            return Ok(ssi_claims_core::ProofValidity::Invalid);
        }

        for p in proof {
            if p.verify_prepared_with(verifier).await?.is_invalid() {
                return Ok(ssi_claims_core::ProofValidity::Invalid);
            }
        }

        Ok(ssi_claims_core::ProofValidity::Valid)
    }
}

impl<I: Interpretation, V: Vocabulary, T: LinkedDataSubject<I, V>, P> LinkedDataSubject<I, V>
    for Claims<T, P>
{
    fn visit_subject<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        self.value.visit_subject(serializer)
    }
}

impl<I: Interpretation, V: Vocabulary, T: LinkedDataPredicateObjects<I, V>, P>
    LinkedDataPredicateObjects<I, V> for Claims<T, P>
{
    fn visit_objects<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        self.value.visit_objects(visitor)
    }
}

impl<I: Interpretation, V: Vocabulary, T: LinkedDataGraph<I, V>, P> LinkedDataGraph<I, V>
    for Claims<T, P>
{
    fn visit_graph<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::GraphVisitor<I, V>,
    {
        self.value.visit_graph(visitor)
    }
}

impl<I: Interpretation, V: Vocabulary, T: LinkedData<I, V>, P> LinkedData<I, V> for Claims<T, P> {
    fn visit<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::Visitor<I, V>,
    {
        self.value.visit(visitor)
    }
}

pub trait VerifyPreparedWith<V> {
    type Error;

    #[allow(async_fn_in_trait)]
    async fn verify_prepared_with<'a>(
        &'a self,
        verifier: &'a V,
    ) -> Result<ssi_claims_core::ProofValidity, Self::Error>;
}
