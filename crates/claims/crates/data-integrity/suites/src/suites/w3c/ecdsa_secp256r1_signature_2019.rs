use ssi_crypto::MessageSigner;
use ssi_data_integrity_core::{suite::HashError, CryptographicSuite, ExpandedConfiguration};
use ssi_verification_methods::{EcdsaSecp256r1VerificationKey2019, SignatureError};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, suites::sha256_hash, MultibaseSignature, MultibaseSignatureRef,
};

/// ECDSA Cryptosuite v2019 `EcdsaSecp256r1Signature2019`.
///
/// See: <https://www.w3.org/community/reports/credentials/CG-FINAL-di-ecdsa-2019-20220724/#ecdsasecp256r1signature2019>
pub struct EcdsaSecp256r1Signature2019;

impl EcdsaSecp256r1Signature2019 {
    pub const NAME: &'static str = "EcdsaSecp256r1Signature2019";

    pub const IRI: &'static iref::Iri =
        iri!("https://w3id.org/security#EcdsaSecp256r1Signature2019");
}

impl_rdf_input_urdna2015!(EcdsaSecp256r1Signature2019);

impl CryptographicSuite for EcdsaSecp256r1Signature2019 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = EcdsaSecp256r1VerificationKey2019;

    type Signature = MultibaseSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::ES256;

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

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<EcdsaSecp256r1VerificationKey2019>
    for SignatureAlgorithm
{
    type Options = ();

    type Signature = MultibaseSignature;

    type Protocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::ES256;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        _method: <EcdsaSecp256r1VerificationKey2019 as ssi_core::Referencable>::Reference<'_>,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        Ok(MultibaseSignature::new_base58btc(
            signer.sign(ssi_jwk::algorithm::ES256, (), bytes).await?,
        ))
    }

    fn verify(
        &self,
        _options: (),
        signature: MultibaseSignatureRef,
        method: &EcdsaSecp256r1VerificationKey2019,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        let signature_bytes = signature.decode()?;
        method.verify_bytes(bytes, &signature_bytes)
    }
}