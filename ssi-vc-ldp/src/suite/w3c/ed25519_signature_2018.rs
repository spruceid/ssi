use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, verification, CryptographicSuite, ProofConfiguration, ProofOptions,
};

use crate::suite::{sha256_hash, HashError};

pub use verification::method::Ed25519VerificationKey2018;

/// Ed25519 Signature 2018.
///
/// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2018;

impl_rdf_input_urdna2015!(Ed25519Signature2018);

#[async_trait::async_trait]
impl CryptographicSuite for Ed25519Signature2018 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod = verification::MethodReferenceOrOwned<Ed25519VerificationKey2018>;

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#Ed25519Signature2018")
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
