use super::{CryptographicSuite, TransformationOptions};
use crate::ProofRef;
use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_verification_methods::VerificationMethodVerifierRegistry;

pub trait CryptographicSuiteVerification<T>: CryptographicSuite {
    #[allow(async_fn_in_trait)]
    async fn verify_proof(
        &self,
        verifier_registry: impl VerificationMethodVerifierRegistry,
        claims: &T,
        proof: ProofRef<'_, Self>,
        transformation_options: TransformationOptions<Self>,
    ) -> Result<ProofValidity, ProofValidationError>;
}