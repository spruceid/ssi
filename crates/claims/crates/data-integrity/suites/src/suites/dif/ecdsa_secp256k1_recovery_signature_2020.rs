use iref::Iri;
use ssi_core::Referencable;
use ssi_crypto::MessageSigner;
use ssi_data_integrity_core::{suite::HashError, CryptographicSuite, ExpandedConfiguration};
use ssi_verification_methods::{
    ecdsa_secp_256k1_recovery_method_2020::DigestFunction, EcdsaSecp256k1RecoveryMethod2020,
    SignatureError, VerificationError,
};
use static_iref::iri;

use crate::{impl_rdf_input_urdna2015, suites::sha256_hash, JwsSignature, JwsSignatureRef};

/// `EcdsaSecp256k1RecoverySignature2020`.
///
/// See: <https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/>
pub struct EcdsaSecp256k1RecoverySignature2020;

impl EcdsaSecp256k1RecoverySignature2020 {
    pub const NAME: &'static str = "EcdsaSecp256k1RecoverySignature2020";

    pub const IRI: &'static Iri = iri!("https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoverySignature2020");
}

impl_rdf_input_urdna2015!(EcdsaSecp256k1RecoverySignature2020);

impl CryptographicSuite for EcdsaSecp256k1RecoverySignature2020 {
    type Transformed = String;

    type Hashed = [u8; 64];

    type VerificationMethod = EcdsaSecp256k1RecoveryMethod2020;

    type Signature = JwsSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::ES256KR;

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
        proof_configuration: ExpandedConfiguration<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }

    fn required_proof_context(&self) -> Option<json_ld::syntax::Context> {
        Some(iri!("https://w3id.org/security/suites/secp256k1recovery-2020/v2").into())
    }
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<EcdsaSecp256k1RecoveryMethod2020>
    for SignatureAlgorithm
{
    type Options = ();

    type Signature = JwsSignature;

    type Protocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::ES256KR;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: <() as Referencable>::Reference<'_>,
        _method: <EcdsaSecp256k1RecoveryMethod2020 as Referencable>::Reference<'_>,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        JwsSignature::sign_detached(bytes, signer, None, ssi_jwk::algorithm::ES256KR).await
    }

    fn verify(
        &self,
        _options: (),
        signature: JwsSignatureRef,
        method: &EcdsaSecp256k1RecoveryMethod2020,
        bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        let (header, _, signature) = signature
            .jws
            .decode()
            .map_err(|_| VerificationError::InvalidSignature)?;
        let signing_bytes = header.encode_signing_bytes(bytes);

        method.verify_bytes(&signing_bytes, &signature, DigestFunction::Sha256)
    }
}
