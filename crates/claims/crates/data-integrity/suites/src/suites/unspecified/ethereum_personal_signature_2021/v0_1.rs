use crate::impl_rdf_input_urdna2015;

use super::{Signature, VerificationMethod, EPSIG_CONTEXT};
use ssi_claims_core::{ProofValidationError, ProofValidity, SignatureError};
use ssi_core::Referencable;
use ssi_data_integrity_core::{suite::HashError, CryptographicSuite, ExpandedConfiguration};
use ssi_rdf::IntoNQuads;
use ssi_verification_methods::{protocol::EthereumWallet, MessageSigner};
use static_iref::iri;

pub struct EthereumPersonalSignature2021v0_1;

impl EthereumPersonalSignature2021v0_1 {
    pub const NAME: &'static str = "EthereumPersonalSignature2021";

    pub const IRI: &'static iref::Iri =
        iri!("https://demo.spruceid.com/ld/epsig/EthereumPersonalSignature2021");
}

impl_rdf_input_urdna2015!(EthereumPersonalSignature2021v0_1);

impl CryptographicSuite for EthereumPersonalSignature2021v0_1 {
    type Transformed = String;

    type Hashed = String;

    type VerificationMethod = VerificationMethod;

    type Signature = Signature;

    type SignatureProtocol = EthereumWallet;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::AnyESKeccakK;

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

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: ExpandedConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        let proof_quads = proof_configuration.quads().into_nquads();
        let message = format!("{proof_quads}\n{data}");
        Ok(message)
    }

    fn required_proof_context(&self) -> Option<json_ld::syntax::Context> {
        Some(json_ld::syntax::Context::One(EPSIG_CONTEXT.clone()))
    }

    async fn sign_hash(
        &self,
        _options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as ssi_core::Referencable>::Reference<'_>,
        data: &Self::Hashed,
        signer: impl MessageSigner<Self::MessageSignatureAlgorithm, Self::SignatureProtocol>,
    ) -> Result<Self::Signature, SignatureError> {
        let proof_value_bytes = signer
            .sign(method.algorithm(), EthereumWallet, data.as_bytes())
            .await?;
        match String::from_utf8(proof_value_bytes) {
            Ok(proof_value) => Ok(Signature::new(proof_value)),
            Err(_) => Err(SignatureError::InvalidSignature),
        }
    }

    fn verify_hash(
        &self,
        _options: <Self::Options as Referencable>::Reference<'_>,
        method: <Self::VerificationMethod as Referencable>::Reference<'_>,
        data: &Self::Hashed,
        signature: <Self::Signature as Referencable>::Reference<'_>,
    ) -> Result<ProofValidity, ProofValidationError> {
        let message = EthereumWallet::prepare_message(data.as_bytes());
        let signature_bytes = signature.decode()?;
        Ok(method.verify_bytes(&message, &signature_bytes)?.into())
    }
}
