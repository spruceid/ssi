use std::ops::Deref;

mod signature;
pub use signature::*;

mod verification;
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
    pub claims: Claims,

    /// Prepared proof.
    ///
    /// This is not just the proof, but also any information derived from the
    /// claims and/or proof required for the verification.
    pub proof: P::Prepared,
}

impl<T, P: Proof> Verifiable<T, P> {
    pub fn from_parts(claims: T, proof: P::Prepared) -> Self {
        Self { claims, proof }
    }

    pub async fn new<U>(value: U) -> Result<Self, ProofPreparationError>
    where
        U: ExtractProof<Proofless = T, Proof = P> + DefaultEnvironment,
        P: PrepareWith<T, U::Environment>,
    {
        Self::new_with(value, U::Environment::default()).await
    }

    pub async fn new_with<U, E>(value: U, mut environment: E) -> Result<Self, ProofPreparationError>
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
    pub fn unprepare(self) -> P::Attached
    where
        P: AttachProof<T>,
        P::Prepared: UnprepareProof<Unprepared = P>,
    {
        let (claims, prepared_proof) = self.into_parts();
        prepared_proof.unprepare().attach_to(claims)
    }

    /// Tamper with the claims without changing the proofs.
    ///
    /// The proofs may become invalid.
    pub async fn tamper<U, E>(
        self,
        environment: E,
        f: impl FnOnce(T) -> U,
    ) -> Result<Verifiable<U, P>, ProofPreparationError>
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
    ) -> Result<Verifiable<U, P>, ProofPreparationError>
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

    /// Validates the claims and verify them against the proof.
    pub async fn verify<V>(&self, verifier: &V) -> Result<Verification, ProofValidationError>
    where
        T: Validate<ValidationEnvironment, P>,
        P::Prepared: ValidateProof<T, V>,
    {
        let env = ValidationEnvironment::default();
        self.verify_with(verifier, &env).await
    }

    /// Validates the claims and verify them against the proof.
    pub async fn verify_with<V, E>(
        &self,
        verifier: &V,
        env: &E,
    ) -> Result<Verification, ProofValidationError>
    where
        T: Validate<E, P>,
        P::Prepared: ValidateProof<T, V>,
    {
        match self.claims.validate(env, &self.proof) {
            Ok(_) => self
                .proof
                .validate_proof(&self.claims, verifier)
                .await
                .map(|r| r.map_err(Invalid::Proof)),
            Err(e) => {
                // Claims are not valid on their own.
                Ok(Err(Invalid::Claims(e)))
            }
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
