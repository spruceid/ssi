use crate::impl_rdf_input_urdna2015;

use super::{Signature, SignatureAlgorithm, VerificationMethod, EPSIG_CONTEXT};
use ssi_crypto::protocol::EthereumWallet;
use ssi_data_integrity_core::{suite::HashError, CryptographicSuite, ExpandedConfiguration};
use ssi_rdf::IntoNQuads;
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

    type SignatureAlgorithm = SignatureAlgorithm;

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

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }

    fn required_proof_context(&self) -> Option<json_ld::syntax::Context> {
        Some(json_ld::syntax::Context::One(EPSIG_CONTEXT.clone()))
    }
}
