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
use suite::{CryptographicSuiteSelect, SelectionError};

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

    /// Select a subset of claims to disclose.
    ///
    /// The `params` argument is similar to the verification parameters of the
    /// `verify` function. It must provides resources necessary to the selection
    /// of claims. This depends on the cryptosuite type `S`, but probably
    /// includes a verification method resolver.
    /// Using `ssi::claims::VerificationParameters` will work in most cases.
    pub async fn select<P>(
        &self,
        params: P,
        options: S::SelectionOptions,
    ) -> Result<DataIntegrity<ssi_json_ld::syntax::Object, S>, SelectionError>
    where
        S: CryptographicSuiteSelect<T, P>,
    {
        match self.proofs.split_first() {
            Some((proof, [])) => {
                proof
                    .suite()
                    .select(&self.claims, proof.borrowed(), params, options)
                    .await
            }
            Some(_) => Err(SelectionError::AmbiguousProof),
            None => Err(SelectionError::MissingProof),
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> DataIntegrity<U, S> {
        DataIntegrity {
            claims: f(self.claims),
            proofs: self.proofs,
        }
    }
}

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
