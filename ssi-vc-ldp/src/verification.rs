use std::{future::Future, pin::Pin};

use ssi_crypto::{VerificationError, Verifier};
use ssi_vc::ProofValidity;

use crate::{CryptographicSuite, DataIntegrity, Proof};

pub use method::{
    Reference as MethodReference, ReferenceOrOwned as MethodReferenceOrOwned, VerificationMethod,
};
pub use ssi_verification_methods as method;

impl<T: Sync, S: CryptographicSuite> ssi_vc::VerifiableWith for DataIntegrity<T, S> {
    type Proof = Proof<S>;
    type Method = S::VerificationMethod;

    fn verify_with<'life0, 'life1, 'life2, 'async_trait>(
        &'life0 self,
        verifier: &'life1 (impl 'async_trait + Verifier<Self::Method>),
        proof: &'life2 Self::Proof,
    ) -> Pin<Box<dyn Future<Output = Result<ProofValidity, VerificationError>> + Send + 'async_trait>>
    where
        'life0: 'async_trait,
        'life1: 'async_trait,
        'life2: 'async_trait,
        Self: 'async_trait,
    {
        let suite = proof.suite();
        suite.verify_proof(&self.hash, verifier, proof.untyped().as_proof_ref())
    }
}
