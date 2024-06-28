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
    /// The `verifier` argument is a environment providing all the resources
    /// necessary for the validation of the claims and proof. This is highly
    /// dependent on the type of claims/proof you want to verify, but in most
    /// cases you can use the built-in [`Verifier`] type. This type provides the
    /// most common required resources such as a public key resolver and
    /// JSON-LD document loader.
    #[allow(async_fn_in_trait)]
    async fn verify<V>(&self, verifier: V) -> Result<Verification, ProofValidationError>
    where
        Self::Claims: ValidateClaims<V, Self::Proof>,
        Self::Proof: ValidateProof<V, Self::Claims>,
    {
        match self.claims().validate_claims(&verifier, self.proof()) {
            Ok(_) => self
                .proof()
                .validate_proof(&verifier, self.claims())
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

/// Public key resolver environment.
pub trait ResolverEnvironment {
    /// Public key resolver.
    type Resolver;

    /// Returns a reference to the environment's public key resolver.
    fn resolver(&self) -> &Self::Resolver;
}

impl<'a, E: ResolverEnvironment> ResolverEnvironment for &'a E {
    type Resolver = E::Resolver;

    fn resolver(&self) -> &Self::Resolver {
        E::resolver(*self)
    }
}

/// Environment that provides date and time.
///
/// Used to check the validity period of given claims.
pub trait DateTimeEnvironment {
    /// Returns the current date and time.
    fn date_time(&self) -> DateTime<Utc>;
}

impl<'a, E: DateTimeEnvironment> DateTimeEnvironment for &'a E {
    fn date_time(&self) -> DateTime<Utc> {
        E::date_time(*self)
    }
}

/// Default verifier.
///
/// The [`VerifiableClaims::verify`] function expects a verification environment
/// (called the `verifier`) providing all the resources necessary for the
/// validation of claims and signature.
///
/// Required resources depend on the actual type of claims and signature you
/// want to validate, however we can identify a set of resources that are
/// commonly required, namely:
///  - A public key resolver,
///  - a JSON-LD document loader,
///  - an EIP-712 types definition loader,
///  - the date and time.
///
/// This type defines an environment providing those resources. In most cases,
/// this will be sufficient to verify all your secured claims.
///
/// The `from_resolver` constructor provides sensible defaults for the JSON-LD
/// document loader, EIP-712 loader, date and time. You still need to provide
/// public key resolver.
#[derive(Debug, Clone, Copy)]
pub struct Verifier<R, L1 = ssi_json_ld::ContextLoader, L2 = ()> {
    /// Public key resolver.
    pub resolver: R,

    /// JSON-LD loader.
    pub json_ld_loader: L1,

    /// EIP-712 types loader.
    pub eip712_types_loader: L2,

    /// Date-time.
    pub date_time: DateTime<Utc>,
}

impl<R> Verifier<R> {
    pub fn from_resolver(resolver: R) -> Self {
        Self {
            resolver,
            json_ld_loader: ssi_json_ld::ContextLoader::default(),
            eip712_types_loader: (),
            date_time: Utc::now(),
        }
    }
}

impl<R, L1, L2> Verifier<R, L1, L2> {
    pub fn with_date_time(mut self, date_time: DateTime<Utc>) -> Self {
        self.date_time = date_time;
        self
    }

    pub fn with_json_ld_loader<L>(self, loader: L) -> Verifier<R, L, L2> {
        Verifier {
            resolver: self.resolver,
            json_ld_loader: loader,
            eip712_types_loader: self.eip712_types_loader,
            date_time: self.date_time,
        }
    }

    pub fn with_eip712_types_loader<L>(self, loader: L) -> Verifier<R, L1, L> {
        Verifier {
            resolver: self.resolver,
            json_ld_loader: self.json_ld_loader,
            eip712_types_loader: loader,
            date_time: self.date_time,
        }
    }
}

impl<R, L1, L2> ResolverEnvironment for Verifier<R, L1, L2> {
    type Resolver = R;

    fn resolver(&self) -> &Self::Resolver {
        &self.resolver
    }
}

impl<R, L1: ssi_json_ld::Loader, L2> ContextLoaderEnvironment for Verifier<R, L1, L2> {
    type Loader = L1;

    fn loader(&self) -> &Self::Loader {
        &self.json_ld_loader
    }
}

impl<R, L1, L2: ssi_eip712::TypesProvider> Eip712TypesEnvironment for Verifier<R, L1, L2> {
    type Provider = L2;

    fn eip712_types(&self) -> &Self::Provider {
        &self.eip712_types_loader
    }
}

impl<R, L1, L2> DateTimeEnvironment for Verifier<R, L1, L2> {
    fn date_time(&self) -> DateTime<Utc> {
        self.date_time
    }
}
