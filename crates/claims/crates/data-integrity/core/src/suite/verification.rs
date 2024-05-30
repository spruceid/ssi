use super::CryptographicSuite;
use crate::ProofRef;
use ssi_claims_core::{ProofValidationError, ProofValidity};

pub trait CryptographicSuiteVerification<V>: CryptographicSuite {
    #[allow(async_fn_in_trait)]
    async fn verify_prepared_claims(
        &self,
        verifier: &V,
        prepared_claims: &Self::PreparedClaims,
        proof: ProofRef<'_, Self>,
    ) -> Result<ProofValidity, ProofValidationError>;
}
