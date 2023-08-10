use std::future;

use ssi_crypto::MessageSigner;
use ssi_verification_methods::SignatureError;
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, verification, CryptographicSuite, ProofConfiguration,
    ProofConfigurationRef,
};

use crate::suite::{sha256_hash, HashError, JwsSignature, JwsSignatureRef};

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

    type Signature = JwsSignature;

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
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<Ed25519VerificationKey2018>
    for SignatureAlgorithm
{
    type Signature = JwsSignature;

    type Protocol = ();

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> =
        future::Ready<Result<Self::Signature, SignatureError>>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        method: &Ed25519VerificationKey2018,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        todo!()
    }

    fn verify(
        &self,
        signature: JwsSignatureRef,
        method: &Ed25519VerificationKey2018,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
