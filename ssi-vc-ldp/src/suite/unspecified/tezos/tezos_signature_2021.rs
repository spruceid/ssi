use ssi_crypto::MessageSigner;
use ssi_jwk::{algorithm::AnyBlake2b, JWK};
use ssi_rdf::IntoNQuads;
use ssi_tzkey::EncodeTezosSignedMessageError;
use ssi_verification_methods::{covariance_rule, Referencable, TezosMethod2021};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015,
    suite::{CryptographicSuiteOptions, HashError},
    CryptographicSuite, ProofConfigurationRef,
};

use super::{Signature, SignatureRef, TezosSign, TezosWallet};

/// Tezos signature suite based on URDNA2015.
///
/// # Transformation algorithm
///
/// The input credential RDF graph is normalized into a list of RDF quads using
/// the URDNA2015 canonicalization algorithm.
///
/// # Hashing algorithm
///
/// The proof configuration RDF graph is normalized into into a list of RDF
/// quads using the URDNA2015 canonicalization algorithm. A message is formed
/// by concatenating the `Tezos Signed Message: ` (ending with a space), the
/// credential quads and the configuration quads using the 0xa byte (line feed).
///
/// The output is a bytes string composed of the byte 0x5, followed by the byte
/// 0x1, followed by the 4 bytes encoding the message lenght in big endian,
/// followd by the message.
///
/// [1]: <https://tools.ietf.org/html/rfc8785>
///
/// # Verification method
///
/// The [`TezosMethod2021`] verification method is used.
pub struct TezosSignature2021;

impl TezosSignature2021 {
    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#TezosSignature2021");
}

impl_rdf_input_urdna2015!(TezosSignature2021);

impl CryptographicSuite for TezosSignature2021 {
    type Transformed = String;
    type Hashed = Vec<u8>;

    type VerificationMethod = TezosMethod2021;

    type Signature = Signature;

    type SignatureProtocol = TezosWallet;

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = AnyBlake2b;

    type Options = Options;

    fn iri(&self) -> &iref::Iri {
        Self::IRI
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    fn hash(
        &self,
        data: String,
        proof_configuration: ProofConfigurationRef<Self::VerificationMethod, Self::Options>,
    ) -> Result<Self::Hashed, HashError> {
        let proof_quads = proof_configuration.quads(self).into_nquads();
        let message = format!("\n{proof_quads}\n{data}");
        match ssi_tzkey::encode_tezos_signed_message(&message) {
            Ok(data) => Ok(data),
            Err(EncodeTezosSignedMessageError::Length(_)) => Err(HashError::TooLong),
        }
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<TezosMethod2021> for SignatureAlgorithm {
    type Options = Options;

    type Signature = Signature;

    type Protocol = TezosWallet;

    type MessageSignatureAlgorithm = AnyBlake2b;

    type Sign<'a, S: 'a + MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>> =
        TezosSign<'a, S>;

    fn sign<'a, S: 'a + MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        options: OptionsRef<'a>,
        method: &TezosMethod2021,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        TezosSign::new(
            method.public_key.as_jwk().or(options.public_key_jwk),
            bytes,
            signer,
        )
    }

    fn verify(
        &self,
        options: OptionsRef,
        signature: SignatureRef,
        method: &TezosMethod2021,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        let (algorithm, signature_bytes) = signature.decode()?;
        method.verify_bytes(options.public_key_jwk, bytes, algorithm, &signature_bytes)
    }
}

#[derive(
    Debug,
    Clone,
    serde::Serialize,
    serde::Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct Options {
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    #[ld("sec:publicKeyJwk")]
    pub public_key_jwk: Option<Box<JWK>>,
}

impl Options {
    pub fn new(public_key_jwk: Option<JWK>) -> Self {
        Self {
            public_key_jwk: public_key_jwk.map(Box::new),
        }
    }
}

impl<T> CryptographicSuiteOptions<T> for Options {}

impl Referencable for Options {
    type Reference<'a> = OptionsRef<'a>;

    fn as_reference(&self) -> Self::Reference<'_> {
        OptionsRef {
            public_key_jwk: self.public_key_jwk.as_deref(),
        }
    }

    covariance_rule!();
}

#[derive(Debug, Clone, Copy, serde::Serialize, linked_data::Serialize)]
#[ld(prefix("sec" = "https://w3id.org/security#"))]
pub struct OptionsRef<'a> {
    #[serde(rename = "publicKeyJwk", skip_serializing_if = "Option::is_none")]
    #[ld("sec:publicKeyJwk")]
    pub public_key_jwk: Option<&'a JWK>,
}