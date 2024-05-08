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
//!   - Claims verification: the claims verified against the proof using the
//!     [`VerifyClaimsWith`] trait.

use std::borrow::Cow;

/// Verifiable Claims.
///
/// Set of claims bundled with a proof.
pub trait VerifiableClaims {
    /// Proof type.
    type Proof;
}

/// Claims that can be validated.
///
/// Validation consists in verifying that the claims themselves are
/// consistent and valid with regard to the verification environment.
/// For instance, checking that a credential's expiration date is not in the
/// past, or the issue date not in the future.
///
/// Validation may fail even if the claims's proof is successfully verified.
pub trait Validate {
    /// Validates the claims.
    fn is_valid(&self) -> bool;
}

impl Validate for () {
    fn is_valid(&self) -> bool {
        true
    }
}

impl Validate for [u8] {
    fn is_valid(&self) -> bool {
        true
    }
}

impl Validate for Vec<u8> {
    fn is_valid(&self) -> bool {
        true
    }
}

impl<'a, T: ?Sized + ToOwned + Validate> Validate for Cow<'a, T> {
    fn is_valid(&self) -> bool {
        self.as_ref().is_valid()
    }
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
pub trait MergeWithProof<P> {
    /// Set of claims with a proof.
    type WithProofs;

    /// Bundles this set of claims with the given proof.
    fn merge_with_proof(self, proof: P) -> Self::WithProofs;
}

/// Proof type.
pub trait Proof {
    /// Prepared proof type.
    ///
    /// A prepared proof also contains any information derived from the claims
    /// and/or unprepared proof required for the verification.
    /// Examples of information may be:
    ///   - a hash of the claims;
    ///   - JSON-LD expansion of the proof;
    ///   - canonical form of the claims;
    ///   - etc.
    type Prepared;
}

/// A list of proofs is also a proof.
impl<P: Proof> Proof for Vec<P> {
    type Prepared = Vec<P::Prepared>;
}

/// Proof that can be prepared to verify `T` claims.
///
/// Preparation consists in computing any information derived from the claims
/// and/or proof required for verification.
/// Examples of information may be:
///   - a hash of the claims;
///   - JSON-LD expansion of the proof;
///   - canonical form of the claims;
///   - etc.
///
/// An environment of type `E` is provided with all the data required for the
/// preparation. For instance, JSON-LD proofs will require a JSON-LD document
/// loader to fetch remote JSON-LD contexts.
pub trait PrepareWith<T, E = ()>: Proof {
    /// Error that can occur during preparation.
    type Error;

    /// Prepare this proof to verify the given claims.
    #[allow(async_fn_in_trait)]
    async fn prepare_with(
        self,
        claims: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, Self::Error>;
}

impl<T, E, P: PrepareWith<T, E>> PrepareWith<T, E> for Vec<P> {
    type Error = P::Error;

    async fn prepare_with(
        self,
        claims: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, Self::Error> {
        let mut prepared = Vec::with_capacity(self.len());

        for p in self {
            prepared.push(p.prepare_with(claims, environment).await?)
        }

        Ok(prepared)
    }
}

/// Reverse proof preparation.
///
/// Provides a method to strip a proof from its preparation data.
/// This is the inverse of [`PrepareWith`].
pub trait UnprepareProof {
    /// Unprepared proof.
    type Unprepared: Proof<Prepared = Self>;

    /// Reverses the proof preparation.
    fn unprepare(self) -> Self::Unprepared;
}

impl<P: UnprepareProof> UnprepareProof for Vec<P> {
    type Unprepared = Vec<P::Unprepared>;

    fn unprepare(self) -> Self::Unprepared {
        self.into_iter().map(P::unprepare).collect()
    }
}

/// Proof that can verify `T` claims with a verifier of type `V`.
pub trait VerifyClaimsWith<T, V> {
    /// Error that can occur during verification.
    type Error;

    /// Verifies the input claim's proof using the given verifier.
    #[allow(async_fn_in_trait)]
    async fn verify_claims_with<'a>(
        &'a self,
        claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, Self::Error>;
}

impl<T, V, P: VerifyClaimsWith<T, V>> VerifyClaimsWith<T, V> for Vec<P> {
    type Error = P::Error;

    async fn verify_claims_with<'a>(
        &'a self,
        claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, Self::Error> {
        if self.is_empty() {
            // No proof.
            Ok(ProofValidity::Invalid)
        } else {
            for p in self {
                if p.verify_claims_with(claims, verifier).await?.is_invalid() {
                    return Ok(ProofValidity::Invalid);
                }
            }

            Ok(ProofValidity::Valid)
        }
    }
}

/// Error raised when a proof verification fails.
#[derive(Debug, thiserror::Error)]
#[error("invalid proof")]
pub struct InvalidProof;

/// Result of claims verification.
pub enum ProofValidity {
    /// The proof is valid.
    Valid,

    /// The proof is invalid.
    Invalid, // TODO add a reason for the proof invalidity.
}

impl ProofValidity {
    pub fn is_valid(&self) -> bool {
        matches!(self, Self::Valid)
    }

    pub fn is_invalid(&self) -> bool {
        matches!(self, Self::Invalid)
    }

    pub fn into_result(self) -> Result<(), InvalidProof> {
        match self {
            Self::Valid => Ok(()),
            Self::Invalid => Err(InvalidProof),
        }
    }
}

impl From<bool> for ProofValidity {
    fn from(value: bool) -> Self {
        if value {
            Self::Valid
        } else {
            Self::Invalid
        }
    }
}

impl From<ProofValidity> for bool {
    fn from(value: ProofValidity) -> Self {
        match value {
            ProofValidity::Valid => true,
            ProofValidity::Invalid => false,
        }
    }
}
