use async_trait::async_trait;
use ssi_crypto::{ProofPurpose, VerificationError, Verifier};
use ssi_vc::{ProofValidity, VerifiableWith};
use treeldr_rust_prelude::iref::IriBuf;

use crate::{Proof, VcJwt};

#[async_trait]
impl<C: Sync> VerifiableWith for VcJwt<C> {
    type Proof = Proof;
    type Method = Method;

    async fn verify_with(
        &self,
        verifier: &impl Verifier<Self::Method>,
        proof: &Proof,
    ) -> Result<ProofValidity, VerificationError> {
        Ok(verifier
            .verify(
                &proof.method,
                ProofPurpose::AssertionMethod,
                self.signing_bytes(),
                &proof.signature,
            )
            .await?
            .into())
    }
}

/// Verification method.
///
/// Used to retrieve the signing key.
pub struct Method {
    pub issuer: Option<IriBuf>,
    pub key_id: Option<String>,
}

impl Method {
    pub fn new(issuer: Option<IriBuf>, key_id: Option<String>) -> Self {
        Self { issuer, key_id }
    }
}
