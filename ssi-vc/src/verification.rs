use ssi_verification_methods::{Referencable, VerificationError, Verifier};

use crate::Verifiable;

/// Credential verifiable with a proof of type `Self::Proof`.
pub trait VerifiableWith {
    /// Verification method.
    type Method: Referencable;

    /// Proof type.
    type Proof;

    #[allow(async_fn_in_trait)]
    async fn verify_with<'a, V: Verifier<Self::Method>>(
        &'a self,
        verifier: &'a V,
        proof: &'a Self::Proof,
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
