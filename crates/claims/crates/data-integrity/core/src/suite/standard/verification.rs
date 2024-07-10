use ssi_claims_core::{ProofValidationError, ProofValidity};

use crate::{CryptographicSuite, ProofRef};

pub trait VerificationAlgorithm<S: CryptographicSuite> {
    fn verify(
        method: &S::VerificationMethod,
        prepared_claims: <S as CryptographicSuite>::PreparedClaims,
        proof: ProofRef<S>,
    ) -> Result<ProofValidity, ProofValidationError>;
}
