use ssi_crypto::MessageSigner;
use ssi_verification_methods::SignatureError;
use static_iref::iri;

use crate::{impl_rdf_input_urdna2015, verification, CryptographicSuite, ProofConfigurationRef};

use crate::suite::{sha256_hash, HashError, JwsSignature, JwsSignatureRef};

pub use verification::method::Ed25519VerificationKey2018;

/// Ed25519 Signature 2018.
///
/// See: <https://w3c-ccg.github.io/lds-ed25519-2018/>
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2018;

impl Ed25519Signature2018 {
    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#Ed25519Signature2018");
}

impl_rdf_input_urdna2015!(Ed25519Signature2018);

impl CryptographicSuite for Ed25519Signature2018 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = Ed25519VerificationKey2018;

    type Signature = JwsSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::EdDSA;

    type Options = ();

    fn iri(&self) -> &iref::Iri {
        Self::IRI
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
    type Options = ();

    type Signature = JwsSignature;

    type Protocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::EdDSA;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        options: <Self::Options as ssi_verification_methods::Referencable>::Reference<'_>,
        method: <Ed25519VerificationKey2018 as ssi_verification_methods::Referencable>::Reference<
            '_,
        >,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        JwsSignature::sign_detached(bytes, signer, None, ssi_jwk::algorithm::EdDSA).await
    }

    fn verify(
        &self,
        _options: (),
        signature: JwsSignatureRef,
        method: &Ed25519VerificationKey2018,
        message: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        let (signing_bytes, signature_bytes) = signature.decode(message)?;
        method.verify_bytes(&signing_bytes, &signature_bytes)
    }
}
