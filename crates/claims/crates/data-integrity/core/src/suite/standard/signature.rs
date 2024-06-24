use ssi_claims_core::SignatureError;

use crate::{CryptographicSuite, ProofConfigurationRef};

pub trait SignatureAndVerificationAlgorithm {
    type Signature: AsRef<str>;
}

pub trait SignatureAlgorithm<S: CryptographicSuite, T>: SignatureAndVerificationAlgorithm {
    #[allow(async_fn_in_trait)]
    async fn sign(
        verification_method: &S::VerificationMethod,
        signer: T,
        prepared_claims: S::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError>;
}
