use ssi_claims_core::{ProofValidationError, ProofValidity};
use ssi_crypto::VerifyingKey;
use ssi_verification_methods::VerificationMethod;

use crate::{CryptographicSuite, ProofRef};

pub trait VerificationAlgorithm<S: CryptographicSuite> {
    fn verify(
        &self,
        verifier: impl VerifyingKey,
        method: &VerificationMethod,
        prepared_claims: <S as CryptographicSuite>::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ProofValidity, ProofValidationError>;
}
