use crate::{CryptographicSuite, PreparedProof};
use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_verification_methods_core::VerificationMethodResolver;

impl<T, S: CryptographicSuite, V: VerificationMethodResolver<Method = S::VerificationMethod>>
    ssi_claims_core::ValidateProof<T, V> for PreparedProof<S>
{
    async fn validate_proof<'a>(
        &'a self,
        _claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, ProofValidationError> {
        let suite = self.proof().suite();
        suite
            .verify_proof(self.hash(), verifier, self.proof().borrowed())
            .await
    }
}
