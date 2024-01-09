use super::{Signature, SignatureAlgorithm, VerificationMethod};
use crate::{
    impl_rdf_input_urdna2015, suite::HashError, CryptographicSuite, ProofConfigurationRef,
};
use ssi_crypto::protocol::EthereumWallet;
use ssi_rdf::IntoNQuads;
use static_iref::iri;

pub struct EthereumPersonalSignature2021v0_1;

impl EthereumPersonalSignature2021v0_1 {
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
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        let proof_quads = proof_configuration.quads(self).into_nquads();
        let message = format!("{proof_quads}\n{data}");
        Ok(message)
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}