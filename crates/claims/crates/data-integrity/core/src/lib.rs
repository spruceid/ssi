//! Verifiable Credential Data Integrity 1.0 core implementation.
//!
//! See: <https://www.w3.org/TR/vc-data-integrity/>
use std::ops::{Deref, DerefMut};

pub mod canonicalization;
mod de;
mod decode;
mod document;
pub mod hashing;
mod options;
mod proof;
pub mod signing;
pub mod suite;

pub use decode::*;
use educe::Educe;
pub use options::ProofOptions;
pub use proof::*;
use serde::Serialize;
use ssi_claims_core::{
    ProofValidationError, ValidateClaims, ValidateProof, VerifiableClaims, Verification,
};
pub use suite::{
    CloneCryptographicSuite, CryptographicSuite, DebugCryptographicSuite,
    DeserializeCryptographicSuite, SerializeCryptographicSuite, StandardCryptographicSuite,
};

pub use document::*;
#[doc(hidden)]
pub use ssi_rdf;

/// Data-Integrity-secured document.
#[derive(Educe, Serialize)]
#[serde(bound(serialize = "T: Serialize, S: SerializeCryptographicSuite"))]
#[educe(Debug(bound("T: std::fmt::Debug, S: DebugCryptographicSuite")))]
#[educe(Clone(bound("T: Clone, S: CloneCryptographicSuite")))]
pub struct DataIntegrity<T, S: CryptographicSuite> {
    #[serde(flatten)]
    pub claims: T,

    #[serde(rename = "proof", skip_serializing_if = "Proofs::is_empty")]
    pub proofs: Proofs<S>,
}

impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
    /// Create new Data-Integrity-secured claims by providing the proofs.
    pub fn new(claims: T, proofs: Proofs<S>) -> Self {
        Self { claims, proofs }
    }

    /// Verify the claims and proofs.
    ///
    /// The `params` argument provides all the verification parameters required
    /// to validate the claims and proof.
    ///
    /// # What verification parameters should I use?
    ///
    /// It really depends on the claims type `T` and cryptosuite type `S`,
    /// but the `ssi::claims::VerificationParameters` type is a good starting
    /// point that should work most of the time.
    ///
    /// # Passing the parameters by reference
    ///
    /// If the validation traits are implemented for `P`, they will be
    /// implemented for `&P` as well. This means the parameters can be passed
    /// by move *or* by reference.
    pub async fn verify<P>(&self, params: P) -> Result<Verification, ProofValidationError>
    where
        T: ValidateClaims<P, Proofs<S>>,
        Proofs<S>: ValidateProof<P, T>,
    {
        VerifiableClaims::verify(self, params).await
    }
}

// impl<T, S: CryptographicSuite> DataIntegrity<T, S>
// where
//     T: ValidateClaims<VerificationParameters, Proofs<S>>,
//     Proofs<S>: ValidateProof<VerificationParameters, T>,
// {
//     /// Verify the claims and proofs with the default verification parameters.
//     ///
//     /// This function should be available for most claims and cryptosuite.
//     /// If you need to customize the verification parameters, such as
//     /// changing the verification date and time or the JSON-LD context loader,
//     /// use the [`Self::verify_with`] method.
//     ///
//     /// See the [`VerificationParameters`] type for more information about the
//     /// default verification parameters.
//     pub async fn verify(&self) -> Result<Verification, ProofValidationError> {
//         VerifiableClaims::verify(self, VerificationParameters::default()).await
//     }
// }

impl<T, S: CryptographicSuite> Deref for DataIntegrity<T, S> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.claims
    }
}

impl<T, S: CryptographicSuite> DerefMut for DataIntegrity<T, S> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.claims
    }
}

impl<T, S: CryptographicSuite> VerifiableClaims for DataIntegrity<T, S> {
    type Claims = T;
    type Proof = Proofs<S>;

    fn claims(&self) -> &Self::Claims {
        &self.claims
    }

    fn proof(&self) -> &Self::Proof {
        &self.proofs
    }
}
