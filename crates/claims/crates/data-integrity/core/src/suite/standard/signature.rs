use ssi_crypto::{SignatureError, Signer};
use ssi_verification_methods::VerificationMethod;

use crate::{CryptographicSuite, ProofConfigurationRef};

pub trait SignatureAndVerificationAlgorithm {
    type Signature: AsRef<str>;
}

pub trait SignatureAlgorithm<S: CryptographicSuite>: SignatureAndVerificationAlgorithm {
    #[allow(async_fn_in_trait)]
    async fn sign(
        verification_method: &VerificationMethod,
        signer: impl Signer,
        prepared_claims: S::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, S>,
    ) -> Result<Self::Signature, SignatureError>;
}