use super::CryptographicSuite;
use crate::ProofRef;
use ssi_claims_core::{ProofValidationError, ProofValidity};

pub trait CryptographicSuiteVerification<T, C, V>: CryptographicSuite {
    #[allow(async_fn_in_trait)]
    async fn verify_proof(
        &self,
        context: &C,
        verifier: &V,
        claims: &T,
        proof: ProofRef<'_, Self>,
    ) -> Result<ProofValidity, ProofValidationError>;
}
