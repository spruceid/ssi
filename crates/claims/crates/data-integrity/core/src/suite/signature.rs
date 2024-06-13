use crate::ProofConfigurationRef;
use ssi_claims_core::SignatureError;

use super::{CryptographicSuite, TransformationOptions};

pub trait CryptographicSuiteSigning<T, C, R, S>: CryptographicSuite {
    #[allow(async_fn_in_trait)]
    async fn generate_signature(
        &self,
        context: &C,
        resolver: R,
        signer: S,
        claims: &T,
        proof_configuration: ProofConfigurationRef<'_, Self>,
        transformation_options: TransformationOptions<Self>,
    ) -> Result<Self::Signature, SignatureError>;
}
