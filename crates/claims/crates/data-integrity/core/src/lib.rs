//! Verifiable Credential Data Integrity 1.0 core implementation.
//!
//! See: <https://www.w3.org/TR/vc-data-integrity/>
use std::ops::{Deref, DerefMut};

pub mod canonicalization;
mod de;
mod decode;
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
use ssi_claims_core::{DefaultEnvironment, ExtractProof, VerifiableClaims};
pub use suite::{
    CloneCryptographicSuite, CryptographicSuite, DebugCryptographicSuite,
    DeserializeCryptographicSuite, SerializeCryptographicSuite, StandardCryptographicSuite,
};

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

impl<T, S: CryptographicSuite + DefaultEnvironment> DefaultEnvironment for DataIntegrity<T, S> {
    type Environment = S::Environment;
}

impl<T, S: CryptographicSuite> ExtractProof for DataIntegrity<T, S> {
    type Proofless = T;

    fn extract_proof(self) -> (Self::Proofless, Self::Proof) {
        (self.claims, self.proofs)
    }
}
