use ssi_verification_methods::VerificationMethodResolutionError;

use crate::{CryptographicSuite, DataIntegrity, ProofRef};

#[derive(Debug, thiserror::Error)]
pub enum SelectionError {
    #[error("missing proof")]
    MissingProof,

    #[error("ambiguous proof")]
    AmbiguousProof,

    #[error(transparent)]
    VerificationMethodResolution(#[from] VerificationMethodResolutionError),

    #[error("proof derivation failed: {0}")]
    ProofDerivation(String),

    #[error("non-selective cryptographic suite")]
    NonSelectiveSuite,
}

impl SelectionError {
    pub fn proof_derivation(e: impl ToString) -> Self {
        Self::ProofDerivation(e.to_string())
    }
}

/// Cryptographic suite with selective disclosure capabilities.
pub trait SelectiveCryptographicSuite: CryptographicSuite {
    /// Options specifying what claims to select and how.
    type SelectionOptions;
}

/// Cryptographic suite with selective disclosure capabilities on a given type
/// `T`.
///
/// Provides the `select` method on the cryptosuite.
pub trait CryptographicSuiteSelect<T, P>: SelectiveCryptographicSuite {
    /// Select a subset of claims to disclose.
    #[allow(async_fn_in_trait)]
    async fn select(
        &self,
        unsecured_document: &T,
        proof: ProofRef<'_, Self>,
        params: P,
        options: Self::SelectionOptions,
    ) -> Result<DataIntegrity<ssi_json_ld::syntax::Object, Self>, SelectionError>;
}
