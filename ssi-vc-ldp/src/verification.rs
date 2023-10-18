use method::Verifier;

use crate::{suite::VerifyProof, CryptographicSuite, DataIntegrity, Proof};

pub use method::{ReferenceOrOwned as MethodReferenceOrOwned, VerificationMethod};
pub use ssi_verification_methods as method;

impl<T, S: CryptographicSuite> ssi_vc::VerifiableWith for DataIntegrity<T, S>
where
    S::VerificationMethod: VerificationMethod
{
    type Proof = Proof<S>;
    type Method = S::VerificationMethod;

    type VerifyWith<'a, V: Verifier<S::VerificationMethod>> = VerifyProof<'a, S, V> where Self: 'a, V: 'a;

    fn verify_with<'a, V: Verifier<Self::Method>>(
        &'a self,
        verifier: &'a V,
        proof: &'a Self::Proof,
    ) -> VerifyProof<'a, S, V> {
        let suite = proof.suite();
        suite.verify_proof(&self.hash, verifier, proof.untyped().borrowed())
    }
}
