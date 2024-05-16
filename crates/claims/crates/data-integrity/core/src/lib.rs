//! Data Integrity Proofs format for Verifiable Credentials.

mod de;
mod decode;
mod proof;
pub mod signing;
pub mod suite;

use std::fmt::Debug;
use std::ops::{Deref, DerefMut};

pub use decode::*;
use educe::Educe;
pub use proof::*;
use serde::Serialize;
pub use signing::sign;
use ssi_claims_core::{ExtractProof, VerifiableClaims};
pub use suite::{CryptographicSuite, CryptographicSuiteInput};

#[doc(hidden)]
pub use ssi_rdf;

/// Data-Integrity-secured document.
#[derive(Educe, Serialize)]
#[serde(
    bound = "T: Serialize, S::VerificationMethod: Serialize, S::Options: Serialize, S::Signature: Serialize"
)]
#[educe(Debug(bound("T: Debug, S: CryptographicSuite + Debug, S::VerificationMethod: Debug, S::Options: Debug, S::Signature: Debug")))]
#[educe(Clone(bound("T: Clone, S: CryptographicSuite + Clone, S::VerificationMethod: Clone, S::Options: Clone, S::Signature: Clone")))]
pub struct DataIntegrity<T, S: CryptographicSuite> {
    #[serde(flatten)]
    pub claims: T,

    #[serde(rename = "proof", skip_serializing_if = "Proofs::is_empty")]
    pub proofs: Proofs<S>,
}

impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
    pub fn new(claims: T, proofs: Proofs<S>) -> Self {
        Self { claims, proofs }
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
    type Proof = Proofs<S>;
}

impl<T, S: CryptographicSuite> ExtractProof for DataIntegrity<T, S> {
    type Proofless = T;

    fn extract_proof(self) -> (Self::Proofless, Self::Proof) {
        (self.claims, self.proofs)
    }
}
