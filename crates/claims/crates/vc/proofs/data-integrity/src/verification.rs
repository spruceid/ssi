use method::{VerificationError, Verifier};
use ssi_claims_core::ProofValidity;

use crate::{CryptographicSuite, DataIntegrity, Proof};

pub use method::{ReferenceOrOwned as MethodReferenceOrOwned, VerificationMethod};
pub use ssi_verification_methods as method;

impl<T, S: CryptographicSuite> ssi_claims_core::Provable for DataIntegrity<T, S> {
    type Proof = Proof<S>;
}

impl<T, S: CryptographicSuite, V: Verifier<S::VerificationMethod>>
    ssi_claims_core::VerifiableWith<V> for DataIntegrity<T, S>
where
    S::VerificationMethod: VerificationMethod,
{
    type Error = VerificationError;

    async fn verify_with<'a>(
        &'a self,
        verifier: &'a V,
        proof: &'a Self::Proof,
    ) -> Result<ProofValidity, VerificationError> {
        let suite = proof.suite();
        suite
            .verify_proof(&self.hash, verifier, proof.untyped().borrowed())
            .await
    }
}
