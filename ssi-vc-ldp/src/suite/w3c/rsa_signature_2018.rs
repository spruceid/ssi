use ssi_verification_methods::RsaVerificationKey2018;
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError},
    CryptographicSuite, ProofConfiguration
};

/// RSA Signature Suite 2018.
///
/// See: <https://w3c-ccg.github.io/lds-rsa2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct RsaSignature2018;

impl_rdf_input_urdna2015!(RsaSignature2018);

impl CryptographicSuite for RsaSignature2018 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = RsaVerificationKey2018;

    type Signature = Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#RsaSignature2018")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: &ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm
    }
}

/// Signature type.
pub struct Signature {
    /// Signature value.
    pub signature_value: String
}

/// Signature algorithm.
pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<RsaVerificationKey2018> for SignatureAlgorithm {
    type Signature = Signature;

    type Protocol = ();

    fn sign<S: ssi_crypto::MessageSigner<Self::Protocol>>(
        &self,
        method: &RsaVerificationKey2018,
        bytes: &[u8],
        signer: &S
    ) -> Result<Self::Signature, ssi_verification_methods::SignatureError> {
        todo!()
    }

    fn verify(&self,
            signature: &Self::Signature,
            method: &RsaVerificationKey2018,
            bytes: &[u8]
        ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}