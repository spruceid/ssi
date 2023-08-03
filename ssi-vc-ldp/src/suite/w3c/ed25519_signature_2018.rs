use ssi_jws::CompactJWSString;
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, verification, CryptographicSuite, ProofConfiguration
};

use crate::suite::{sha256_hash, HashError};

pub use verification::method::Ed25519VerificationKey2018;

/// Ed25519 Signature 2018.
///
/// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2018;

impl_rdf_input_urdna2015!(Ed25519Signature2018);

impl CryptographicSuite for Ed25519Signature2018 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = Ed25519VerificationKey2018;

    type Signature = Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#Ed25519Signature2018")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: &ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

/// Signature.
pub struct Signature {
    /// JSON Web Signature.
    pub jws: CompactJWSString
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<Ed25519VerificationKey2018> for SignatureAlgorithm {
    type Signature = Signature;

    type Protocol = ();

    fn sign<S: ssi_crypto::MessageSigner<Self::Protocol>>(
            &self,
            method: &Ed25519VerificationKey2018,
            bytes: &[u8],
            signer: &S
        ) -> Result<Self::Signature, ssi_verification_methods::SignatureError> {
        todo!()
    }

    fn verify(&self,
            signature: &Self::Signature,
            method: &Ed25519VerificationKey2018,
            bytes: &[u8]
        ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}