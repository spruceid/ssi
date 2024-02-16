use crate::{CryptographicSuite, PreparedProof};
pub use method::{ReferenceOrOwned as MethodReferenceOrOwned, VerificationMethod};
use method::{VerificationError, Verifier};
pub use ssi_verification_methods as method;

// impl<T, S: CryptographicSuite> ssi_claims_core::Provable for DataIntegrity<T, S> {
//     type Proof = Proof<S>;
// }

// impl<T, S: CryptographicSuite, V: Verifier<S::VerificationMethod>>
//     ssi_claims_core::VerifiableWith<V> for DataIntegrity<T, S>
// where
//     S::VerificationMethod: VerificationMethod,
// {
//     type Error = VerificationError;

//     async fn verify_with<'a>(
//         &'a self,
//         verifier: &'a V,
//         proof: &'a Self::Proof,
//     ) -> Result<ProofValidity, VerificationError> {
//         let suite = proof.suite();
//         suite
//             .verify_proof(&self.hash, verifier, proof.untyped().borrowed())
//             .await
//     }
// }

impl<T, S: CryptographicSuite, V: Verifier<S::VerificationMethod>>
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
