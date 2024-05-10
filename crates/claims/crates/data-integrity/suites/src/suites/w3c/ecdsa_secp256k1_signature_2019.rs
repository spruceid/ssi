use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_data_integrity_core::{suite::HashError, CryptographicSuite, ExpandedConfiguration};
use ssi_verification_methods::{
    ecdsa_secp_256k1_verification_key_2019::DigestFunction, EcdsaSecp256k1VerificationKey2019,
    MessageSigner,
};
use static_iref::iri;

use crate::{impl_rdf_input_urdna2015, suites::sha256_hash, JwsSignature};

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
        proof_configuration: ExpandedConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    async fn sign_hash(
        &self,
        _options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        _method: <Self::VerificationMethod as ssi_core::Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signer: impl MessageSigner<Self::MessageSignatureAlgorithm, Self::SignatureProtocol>,
    ) -> Result<Self::Signature, SignatureError> {
        JwsSignature::sign_detached(bytes, signer, None, ssi_jwk::algorithm::ES256K).await
    }

    fn verify_hash(
        &self,
        _options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as ssi_core::Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signature: <Self::Signature as ssi_core::Referencable>::Reference<'_>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let (signing_bytes, signature_bytes, _) = signature.decode(bytes)?;
        method
            .verify_bytes(&signing_bytes, &signature_bytes, DigestFunction::Sha256)
            .map(Into::into)
    }
}
