use crate::ProofConfigurationRef;
use ssi_claims_core::SignatureError;

use super::CryptographicSuite;

pub trait CryptographicSuiteSigning<R, S>: CryptographicSuite {
    #[allow(async_fn_in_trait)]
    async fn sign_prepared_claims(
        &self,
        resolver: R,
        signer: S,
        prepared_claims: &Self::PreparedClaims,
        proof_configuration: ProofConfigurationRef<'_, Self>,
    ) -> Result<Self::Signature, SignatureError>;
}
