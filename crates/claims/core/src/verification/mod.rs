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
use ssi_crypto::{Error, RejectedSignature};

mod claims;
mod proof;

pub use claims::*;
pub use proof::*;

use crate::Parameters;

/// Verifiable Claims.
///
/// Set of claims bundled with a proof.
pub trait VerifiableClaims {
    /// Claims type.
    type Claims;

    /// Proof type.
    type Proof;

    /// The claims.
    fn claims(&self) -> &Self::Claims;

    /// The proof.
    fn proof(&self) -> &Self::Proof;

    /// Validates the claims and proof.
    ///
    /// The `params` argument provides all the verification parameters required
    /// to validate the claims and proof.
    #[allow(async_fn_in_trait)]
    async fn verify<V>(&self, verifier: V) -> Result<Verification, Error>
    where
        Self::Claims: ValidateClaims<Self::Proof>,
        Self::Proof: ValidateProof<Self::Claims, V>,
    {
        let params = Parameters::default();
        self.verify_with(verifier, &params).await
    }

    /// Validates the claims and proof.
    ///
    /// The `params` argument provides all the verification parameters required
    /// to validate the claims and proof.
    #[allow(async_fn_in_trait)]
    async fn verify_with<V>(&self, verifier: V, params: &Parameters) -> Result<Verification, Error>
    where
        Self::Claims: ValidateClaims<Self::Proof>,
        Self::Proof: ValidateProof<Self::Claims, V>,
    {
        match self.claims().validate_claims(params, self.proof()) {
            Ok(_) => self
                .proof()
                .validate_proof(&verifier, self.claims(), params)
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
    Proof(#[from] RejectedSignature),
}
