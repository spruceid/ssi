use educe::Educe;

mod verification;
pub use verification::*;

/// Claims serialization utils.
#[cfg(feature = "serde")]
pub mod serde;

/// Claims data-integrity serialization utils.
#[cfg(feature = "linked-data")]
pub mod linked_data;

/// Verifiable claims.
#[derive(Educe)]
#[educe(Clone(bound = "C: Clone, C::Proof: Clone"))]
pub struct Verifiable<C: Provable> {
    /// Claims.
    claims: C,

    /// Credential proof.
    proof: C::Proof,
}

impl<C: Provable> Verifiable<C> {
    pub fn new(claims: C, proof: C::Proof) -> Self {
        Self { claims, proof }
    }

    pub fn claims(&self) -> &C {
        &self.claims
    }

    pub fn claims_mut(&mut self) -> &mut C {
        &mut self.claims
    }

    pub fn proof(&self) -> &C::Proof {
        &self.proof
    }

    pub fn proof_mut(&mut self) -> &mut C::Proof {
        &mut self.proof
    }

    pub async fn verify<V>(&self, verifier: &V) -> Result<ProofValidity, C::Error>
    where
        C: VerifiableWith<V>,
    {
        self.claims.verify_with(verifier, &self.proof).await
    }

    pub fn map<D: Provable>(self, f: impl FnOnce(C, C::Proof) -> (D, D::Proof)) -> Verifiable<D> {
        let (claims, proof) = f(self.claims, self.proof);

        Verifiable { claims, proof }
    }

    pub fn try_map<D: Provable, E>(
        self,
        f: impl FnOnce(C, C::Proof) -> Result<(D, D::Proof), E>,
    ) -> Result<Verifiable<D>, E> {
        let (claims, proof) = f(self.claims, self.proof)?;

        Ok(Verifiable { claims, proof })
    }

    pub async fn async_map<D: Provable, F>(self, f: impl FnOnce(C, C::Proof) -> F) -> Verifiable<D>
    where
        F: std::future::Future<Output = (D, D::Proof)>,
    {
        let (claims, proof) = f(self.claims, self.proof).await;

        Verifiable { claims, proof }
    }

    pub async fn async_try_map<D: Provable, E, F>(
        self,
        f: impl FnOnce(C, C::Proof) -> F,
    ) -> Result<Verifiable<D>, E>
    where
        F: std::future::Future<Output = Result<(D, D::Proof), E>>,
    {
        let (claims, proof) = f(self.claims, self.proof).await?;

        Ok(Verifiable { claims, proof })
    }
}
