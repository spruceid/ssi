use async_trait::async_trait;
use ssi_vc::{ProofValidity, VerifiableWith};
use ssi_verification_methods::{Verifier, ProofPurpose, VerificationError};
use treeldr_rust_prelude::iref::IriBuf;

use crate::{Proof, VcJwt, signing::VcJwtSignature};

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
                VcJwtSignature,
                &proof.method,
                ProofPurpose::Assertion,
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