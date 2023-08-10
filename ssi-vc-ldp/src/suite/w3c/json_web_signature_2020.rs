use std::future;

use ssi_crypto::MessageSigner;
use ssi_verification_methods::{JsonWebKey2020, SignatureError};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, CryptographicSuite, ProofConfiguration, ProofConfigurationRef,
};

use crate::suite::{sha256_hash, HashError, JwsSignature, JwsSignatureRef};

/// JSON Web Signature 2020.
///
/// See: <https://w3c-ccg.github.io/lds-jws2020/>
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonWebSignature2020;

impl_rdf_input_urdna2015!(JsonWebSignature2020);

impl CryptographicSuite for JsonWebSignature2020 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = JsonWebKey2020;

    type Signature = JwsSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#JsonWebSignature2020")
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

impl ssi_verification_methods::SignatureAlgorithm<JsonWebKey2020> for SignatureAlgorithm {
    type Signature = JwsSignature;

    type Protocol = ();

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> =
        future::Ready<Result<Self::Signature, SignatureError>>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        method: &JsonWebKey2020,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        todo!()
    }

    fn verify(
        &self,
        signature: JwsSignatureRef,
        method: &JsonWebKey2020,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
