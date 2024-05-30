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

use crate::Verifiable;

/// Verifiable Claims.
///
/// Set of claims bundled with a proof.
pub trait VerifiableClaims {
    /// Proof type.
    type Proof;

    #[allow(async_fn_in_trait)]
    async fn into_verifiable(
        self,
    ) -> Result<Verifiable<Self::Proofless, Self::Proof>, ProofPreparationError>
    where
        Self: ExtractProof + DefaultEnvironment,
        Self::Proof: PrepareWith<Self::Proofless, Self::Environment>,
    {
        Verifiable::new(self).await
    }

    #[allow(async_fn_in_trait)]
    async fn into_verifiable_with<T, E>(
        self,
        env: E,
    ) -> Result<Verifiable<T, Self::Proof>, ProofPreparationError>
    where
        Self: ExtractProof<Proofless = T>,
        Self::Proof: PrepareWith<T, E>,
    {
        Verifiable::new_with(self, env).await
    }
}

pub trait DefaultEnvironment {
    type Environment: Default;
}

/// Proof extraction trait.
///
/// Implemented by credential and presentation types that can be separated from
/// their proof value(s).
pub trait ExtractProof: Sized + VerifiableClaims {
    /// Set of claims without the proof.
    type Proofless;

    /// Separates the set of claims from the proof.
    fn extract_proof(self) -> (Self::Proofless, Self::Proof);
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
