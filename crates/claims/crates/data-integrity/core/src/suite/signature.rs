use ssi_claims_core::VerificationParameters;
use ssi_crypto::{SignatureError, Signer};
use ssi_verification_methods::VerificationMethodIssuer;

use crate::ProofConfigurationRef;

use super::{CryptographicSuite, TransformationOptions};

pub trait CryptographicSuiteSigning<T>: CryptographicSuite {
    #[allow(async_fn_in_trait)]
    async fn generate_signature(
        &self,
        context: &VerificationParameters,
        signer: impl VerificationMethodIssuer,
        claims: &T,
        proof_configuration: ProofConfigurationRef<'_, Self>,
        transformation_options: TransformationOptions<Self>,
    ) -> Result<Self::Signature, SignatureError>;
}