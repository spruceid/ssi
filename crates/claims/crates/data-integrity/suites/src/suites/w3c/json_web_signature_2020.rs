use ssi_crypto::MessageSigner;
use ssi_data_integrity_core::{suite::HashError, CryptographicSuite, ExpandedConfiguration};
use ssi_verification_methods::{JsonWebKey2020, SignatureError};
use static_iref::iri;

use crate::{impl_rdf_input_urdna2015, suites::sha256_hash, JwsSignature};

/// JSON Web Signature 2020.
///
/// See: <https://w3c-ccg.github.io/lds-jws2020/>
#[derive(Debug, Default, Clone, Copy)]
pub struct JsonWebSignature2020;

impl JsonWebSignature2020 {
    pub const NAME: &'static str = "JsonWebSignature2020";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#JsonWebSignature2020");
}

impl_rdf_input_urdna2015!(JsonWebSignature2020);

impl CryptographicSuite for JsonWebSignature2020 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = JsonWebKey2020;

    type Signature = JwsSignature;

    type SignatureProtocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::Algorithm;

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

    async fn sign(
        &self,
        _options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        _method: <Self::VerificationMethod as ssi_core::Referencable>::Reference<'_>,
        _bytes: &Self::Hashed,
        _signer: impl MessageSigner<Self::MessageSignatureAlgorithm, Self::SignatureProtocol>,
    ) -> Result<Self::Signature, SignatureError> {
        todo!()
    }

    fn verify(
        &self,
        _options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as ssi_core::Referencable>::Reference<'_>,
        bytes: &Self::Hashed,
        signature: <Self::Signature as ssi_core::Referencable>::Reference<'_>,
    ) -> Result<ssi_claims_core::ProofValidity, ssi_verification_methods::VerificationError> {
        let (signing_bytes, signature_bytes, algorithm) = signature.decode(bytes)?;
        method
            .verify_bytes(&signing_bytes, &signature_bytes, Some(algorithm))
            .map(Into::into)
    }
}
