use ssi_verification_methods::EcdsaSecp256k1VerificationKey2019;
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError},
    verification, CryptographicSuite, ProofConfiguration, ProofOptions,
};

/// Ecdsa Secp256k1 Signature 2019.
///
/// See: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/>
pub struct EcdsaSecp256k1Signature2019;

impl_rdf_input_urdna2015!(EcdsaSecp256k1Signature2019);

#[async_trait::async_trait]
impl CryptographicSuite for EcdsaSecp256k1Signature2019 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod =
        verification::MethodReferenceOrOwned<EcdsaSecp256k1VerificationKey2019>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#EcdsaSecp256k1Signature2019")
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
