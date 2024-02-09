use ssi_crypto::MessageSigner;
use ssi_verification_methods::{
    ecdsa_secp_256k1_verification_key_2019::DigestFunction, EcdsaSecp256k1VerificationKey2019,
    SignatureError,
};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{sha256_hash, HashError, JwsSignature, JwsSignatureRef},
    CryptographicSuite, ProofConfigurationRef,
};

/// Ecdsa Secp256k1 Signature 2019.
///
/// See: <https://w3c-ccg.github.io/lds-ecdsa-secp256k1-2019/>
pub struct EcdsaSecp256k1Signature2019;

impl EcdsaSecp256k1Signature2019 {
    pub const NAME: &'static str = "EcdsaSecp256k1Signature2019";

    pub const IRI: &'static iref::Iri =
        iri!("https://w3id.org/security#EcdsaSecp256k1Signature2019");
}

impl_rdf_input_urdna2015!(EcdsaSecp256k1Signature2019);

impl CryptographicSuite for EcdsaSecp256k1Signature2019 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = EcdsaSecp256k1VerificationKey2019;

    type Signature = JwsSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::ES256K;

    type Options = ();

    fn name(&self) -> &str {
        Self::NAME
    }

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

impl ssi_verification_methods::SignatureAlgorithm<EcdsaSecp256k1VerificationKey2019>
    for SignatureAlgorithm
{
    type Options = ();

    type Signature = JwsSignature;

    type Protocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::ES256K;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        _method: <EcdsaSecp256k1VerificationKey2019 as ssi_core::Referencable>::Reference<'_>,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        eprintln!("message: {}", hex::encode(bytes));
        JwsSignature::sign_detached(bytes, signer, None, ssi_jwk::algorithm::ES256K).await
    }

    fn verify(
        &self,
        _options: (),
        signature: JwsSignatureRef,
        method: &EcdsaSecp256k1VerificationKey2019,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        let (signing_bytes, signature_bytes, _) = signature.decode(bytes)?;
        method.verify_bytes(&signing_bytes, &signature_bytes, DigestFunction::Sha256)
    }
}
