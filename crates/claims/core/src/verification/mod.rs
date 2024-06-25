//! Claims verification traits.
//!
//! This modules defines all the trait taking part in the verification pipeline.
//!
//! # Verification pipeline
//!
//! The "verification pipeline" is the sequence of steps executed by this
//! library to go from a set of verifiable claims ([`VerifiableClaims`]) to a
//! [`ProofValidity`] result.
//! It is defined as follows:
//!   - Proof extraction: the claims are separated from the proof using the
//!     [`ExtractProof`] trait.
//!   - Proof preparation: the proof is *prepared* to verify the input claims
//!     using the [`PrepareWith`] trait. This steps computes any information
//!     derived from the claims and/or proof required for the verification.
//!     At this point, the claims and prepared proof are stored together in a
//!     [`Verifiable`](crate::Verifiable) instance, ready for verification.
//!   - Claims validation: the claims are validated using the [`Validate`]
//!     trait.
//!   - Proof validation: the claims verified against the proof using the
//!     [`ValidateProof`] trait.
mod claims;
pub use claims::*;
mod proof;
pub use proof::*;

/// Verifiable Claims.
///
/// Set of claims bundled with a proof.
pub trait VerifiableClaims {
    /// Claims type.
    type Claims;

    /// Proof type.
    type Proof;

    fn claims(&self) -> &Self::Claims;

    fn proof(&self) -> &Self::Proof;

    /// Validates the claims and verify them against the proof.
    #[allow(async_fn_in_trait)]
    async fn verify<V>(&self, verifier: &V) -> Result<Verification, ProofValidationError>
    where
        Self: DefaultVerificationEnvironment,
        Self::Claims: Validate<Self::Environment, Self::Proof>,
        Self::Proof: ValidateProof<Self::Claims, Self::Environment, V>,
    {
        self.verify_with(verifier, Self::Environment::default())
            .await
    }

    /// Validates the claims and verify them against the proof.
    #[allow(async_fn_in_trait)]
    async fn verify_with<V, E>(
        &self,
        verifier: &V,
        env: E,
    ) -> Result<Verification, ProofValidationError>
    where
        Self::Claims: Validate<E, Self::Proof>,
        Self::Proof: ValidateProof<Self::Claims, E, V>,
    {
        match self.claims().validate(&env, self.proof()) {
            Ok(_) => self
                .proof()
                .validate_proof(&env, self.claims(), verifier)
                .await
                .map(|r| r.map_err(Invalid::Proof)),
            Err(e) => {
                // Claims are not valid on their own.
                Ok(Err(Invalid::Claims(e)))
            }
        }
    }
}

/// Proof bundling trait.
///
/// Provides a method to bundle the set of claims with a proof.
pub trait AttachProof<T> {
    /// Set of claims with a proof.
    type Attached;

    /// Bundles the given claims with this proof.
    fn attach_to(self, claims: T) -> Self::Attached;
}

/// Verification outcome.
pub type Verification = Result<(), Invalid>;

/// Invalid verifiable claims.
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum Invalid {
    #[error("invalid claims: {0}")]
    Claims(#[from] InvalidClaims),

    #[error("invalid proof: {0}")]
    Proof(#[from] InvalidProof),
}
