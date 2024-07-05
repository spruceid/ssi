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

use chrono::{DateTime, Utc};
pub use claims::*;
mod proof;
pub use proof::*;
mod parameters;
pub use parameters::*;

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
    ///
    /// # What verification parameters should I use?
    ///
    /// It really depends on the claims type `Self::Claims` and proof type
    /// `Self::Proof`, but the [`VerificationParameters`] type is a good
    /// starting point that should work most of the time.
    ///
    /// # Passing the parameters by reference
    ///
    /// If the validation traits are implemented for `P`, they will be
    /// implemented for `&P` as well. This means the parameters can be passed
    /// by move *or* by reference.
    #[allow(async_fn_in_trait)]
    async fn verify<P>(&self, params: P) -> Result<Verification, ProofValidationError>
    where
        Self::Claims: ValidateClaims<P, Self::Proof>,
        Self::Proof: ValidateProof<P, Self::Claims>,
    {
        match self.claims().validate_claims(&params, self.proof()) {
            Ok(_) => self
                .proof()
                .validate_proof(&params, self.claims())
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

/// Arbitrary resource provider.
pub trait ResourceProvider<T> {
    /// Returns a reference to the resource of type `T`.
    fn get_resource(&self) -> &T;
}

/// Anything can return the unit resource.
impl<T> ResourceProvider<()> for T {
    fn get_resource(&self) -> &() {
        &()
    }
}

/// Type that provides a public key resolver.
pub trait ResolverProvider {
    /// Public key resolver.
    type Resolver;

    /// Returns a reference to the environment's public key resolver.
    fn resolver(&self) -> &Self::Resolver;
}

impl<'a, E: ResolverProvider> ResolverProvider for &'a E {
    type Resolver = E::Resolver;

    fn resolver(&self) -> &Self::Resolver {
        E::resolver(*self)
    }
}

/// Type that provides date and time.
///
/// Used to check the validity period of given claims.
pub trait DateTimeProvider {
    /// Returns the current date and time.
    fn date_time(&self) -> DateTime<Utc>;
}

impl<'a, E: DateTimeProvider> DateTimeProvider for &'a E {
    fn date_time(&self) -> DateTime<Utc> {
        E::date_time(*self)
    }
}
