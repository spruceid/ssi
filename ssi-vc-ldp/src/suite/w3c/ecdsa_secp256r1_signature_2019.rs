use ssi_verification_methods::EcdsaSecp256r1VerificationKey2019;
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError},
    verification, CryptographicSuite, ProofConfiguration, ProofOptions,
};

/// ECDSA Cryptosuite v2019 `EcdsaSecp256r1Signature2019`.
///
/// See: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1signature2019>
pub struct EcdsaSecp256r1Signature2019;

impl_rdf_input_urdna2015!(EcdsaSecp256r1Signature2019);

#[async_trait::async_trait]
impl CryptographicSuite for EcdsaSecp256r1Signature2019 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod =
        verification::MethodReferenceOrOwned<EcdsaSecp256r1VerificationKey2019>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#EcdsaSecp256r1Signature2019")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }
}
