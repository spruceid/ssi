use ssi_crypto::Verifier;
use ssi_vc::{ProofValidity, VerifiableWith, VerificationError};
use treeldr_rust_prelude::iref::IriBuf;

use crate::{Encoded, Proof};

impl<C> VerifiableWith<Proof> for Encoded<C> {
    type Method = Method;
    type Parameters = ();
    type Transformed = ();
    type Error = VerificationError;

    fn verify_with(
        &self,
        _context: &mut impl ssi_vc::Context<Self, Proof>,
        verifiers: &impl ssi_crypto::VerifierProvider<Self::Method>,
        proof: &Proof,
        _parameters: Self::Parameters,
    ) -> Result<ProofValidity, VerificationError> {
        match proof.algorithm {
            ssi_jwk::Algorithm::None => Ok(ProofValidity::Valid),
            algo => {
                let algo = ssi_crypto::Algorithm::try_from(algo)?;
                let verifier = verifiers
                    .get_verifier(&proof.method)
                    .ok_or(VerificationError::UnknownVerificationMethod)?;
                Ok(verifier
                    .verify(algo, self.signing_bytes(), &proof.signature)?
                    .into())
            }
        }
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
