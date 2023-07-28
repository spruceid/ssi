use ssi_verification_methods::JsonWebKey2020;
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, verification, CryptographicSuite, ProofConfiguration, ProofOptions,
};

use crate::suite::{sha256_hash, HashError};

/// JSON Web Signature 2020.
///
/// See: <https://w3c-ccg.github.io/lds-jws2020/>
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonWebSignature2020;

impl_rdf_input_urdna2015!(JsonWebSignature2020);

#[async_trait::async_trait]
impl CryptographicSuite for JsonWebSignature2020 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod = verification::MethodReferenceOrOwned<JsonWebKey2020>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#JsonWebSignature2020")
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
