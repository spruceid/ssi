use async_trait::async_trait;
use ssi_verification_methods::{Verifier, VerificationError};

use crate::Verifiable;

/// Credential verifiable with a proof of type `Self::Proof`.
#[async_trait]
pub trait VerifiableWith {
    /// Verification method.
    type Method;

    /// Proof type.
    type Proof;

    async fn verify_with(
        &self,
        verifier: &impl Verifier<Self::Method>,
        proof: &Self::Proof,
    ) -> Result<ProofValidity, VerificationError>;

    fn with_proof(self, proof: Self::Proof) -> Verifiable<Self>
    where
        Self: Sized,
    {
        Verifiable::new(self, proof)
    }
}

/// Error raised when a proof verification fails.
#[derive(Debug, thiserror::Error)]
#[error("invalid proof")]
pub struct InvalidProof;

/// Result of a credential verification.
pub enum ProofValidity {
    /// The proof is valid.
    Valid,

    /// The proof is invalid.
    Invalid,
}

impl ProofValidity {
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
