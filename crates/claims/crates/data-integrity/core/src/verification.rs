use crate::{CryptographicSuite, PreparedProof};
use ssi_verification_methods_core::{VerificationError, VerificationMethodResolver};

impl<T, S: CryptographicSuite, V: VerificationMethodResolver<Method = S::VerificationMethod>>
    ssi_claims_core::VerifyClaimsWith<T, V> for PreparedProof<S>
{
    type Error = VerificationError;

    async fn verify_claims_with<'a>(
        &'a self,
        _claims: &'a T,
        verifier: &'a V,
    ) -> Result<ssi_claims_core::ProofValidity, Self::Error> {
        let suite = self.proof().suite();
        suite
            .verify_proof(self.hash(), verifier, self.proof().borrowed())
            .await
    }
}
