mod verification;
use std::ops::Deref;

pub use verification::*;

/// Claims serialization utils.
#[cfg(feature = "serde")]
pub mod serde;

/// Claims data-integrity serialization utils.
#[cfg(feature = "linked-data")]
pub mod linked_data;

/// Verifiable claims, and their proof.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Verifiable<Claims, P: Proof> {
    /// Claims.
    claims: Claims,

    /// Credential proof.
    proof: P::Prepared,
}

impl<T, P: Proof> Verifiable<T, P> {
    pub fn from_parts(claims: T, proof: P::Prepared) -> Self {
        Self { claims, proof }
    }

    pub async fn new<U, E>(value: U) -> Result<Self, P::Error>
    where
        U: ExtractProof<Proofless = T, Proof = P>,
        P: PrepareWith<T, E>,
        E: Default,
    {
        Self::new_with(value, E::default()).await
    }

    pub async fn new_with<U, E>(value: U, mut environment: E) -> Result<Self, P::Error>
    where
        U: ExtractProof<Proofless = T, Proof = P>,
        P: PrepareWith<T, E>,
    {
        let (value, raw_proof) = value.extract_proof();
        let proof = raw_proof.prepare_with(&value, &mut environment).await?;
        Ok(Verifiable::from_parts(value, proof))
    }

    /// Merge the claims with their proof(s).
    ///
    /// This will effectively unprepare the proof and make them unverifiable
    /// until [`Self::new`] is called again.
    pub fn unprepare(self) -> T::WithProofs
    where
        T: MergeWithProof<P>,
        P::Prepared: UnprepareProof<Unprepared = P>,
    {
        let (claims, prepared_proof) = self.into_parts();
        let proof = prepared_proof.unprepare();
        T::merge_with_proof(claims, proof)
    }

    /// Tamper with the claims without changing the proofs.
    ///
    /// The proofs may become invalid.
    pub async fn tamper<U, E>(
        self,
        environment: E,
        f: impl FnOnce(T) -> U,
    ) -> Result<Verifiable<U, P>, P::Error>
    where
        P: PrepareWith<U, E>,
        P::Prepared: UnprepareProof<Unprepared = P>,
    {
        self.tamper_with_proofs(environment, f, |p| p).await
    }

    /// Tamper with the claims and proofs.
    ///
    /// The proofs may become invalid.
    pub async fn tamper_with_proofs<U, E>(
        self,
        mut environment: E,
        f: impl FnOnce(T) -> U,
        mut g: impl FnMut(P) -> P,
    ) -> Result<Verifiable<U, P>, P::Error>
    where
        P: PrepareWith<U, E>,
        P::Prepared: UnprepareProof<Unprepared = P>,
    {
        self.async_try_map(|value, proof| async {
            let u = f(value);

            let unprepared_proof = g(proof.unprepare());
            let new_proof = unprepared_proof.prepare_with(&u, &mut environment).await?;

            Ok((u, new_proof))
        })
        .await
    }

    pub fn claims(&self) -> &T {
        &self.claims
    }

    pub fn claims_mut(&mut self) -> &mut T {
        &mut self.claims
    }

    pub fn proof(&self) -> &P::Prepared {
        &self.proof
    }

    pub fn proof_mut(&mut self) -> &mut P::Prepared {
        &mut self.proof
    }

    pub async fn verify<V, E>(&self, verifier: &V) -> Result<ProofValidity, E>
    where
        T: Validate,
        P::Prepared: VerifyClaimsWith<T, V, Error = E>,
    {
        if self.claims.is_valid() {
            self.proof.verify_claims_with(&self.claims, verifier).await
        } else {
            // Claims are not valid on their own.
            Ok(ProofValidity::Invalid)
        }
    }

    pub fn map<D, Q: Proof>(
        self,
        f: impl FnOnce(T, P::Prepared) -> (D, Q::Prepared),
    ) -> Verifiable<D, Q> {
        let (claims, proof) = f(self.claims, self.proof);

        Verifiable { claims, proof }
    }

    pub fn try_map<D, Q: Proof, E>(
        self,
        f: impl FnOnce(T, P::Prepared) -> Result<(D, Q::Prepared), E>,
    ) -> Result<Verifiable<D, Q>, E> {
        let (claims, proof) = f(self.claims, self.proof)?;

        Ok(Verifiable { claims, proof })
    }

    pub async fn async_map<D, Q: Proof, F>(
        self,
        f: impl FnOnce(T, P::Prepared) -> F,
    ) -> Verifiable<D, Q>
    where
        F: std::future::Future<Output = (D, Q::Prepared)>,
    {
        let (claims, proof) = f(self.claims, self.proof).await;

        Verifiable { claims, proof }
    }

    pub async fn async_try_map<D, Q: Proof, E, F>(
        self,
        f: impl FnOnce(T, P::Prepared) -> F,
    ) -> Result<Verifiable<D, Q>, E>
    where
        F: std::future::Future<Output = Result<(D, Q::Prepared), E>>,
    {
        let (claims, proof) = f(self.claims, self.proof).await?;

        Ok(Verifiable { claims, proof })
    }

    pub fn into_parts(self) -> (T, P::Prepared) {
        (self.claims, self.proof)
    }
}

impl<C, P: Proof> Deref for Verifiable<C, P> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.claims
    }
}
