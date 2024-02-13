//! EdDSA Cryptosuite v2020 implementation.
//!
//! This is a legacy cryptographic suite for the usage of the EdDSA algorithm
//! and Curve25519. It is recommended to use `edssa-2022` instead.
//!
//! See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
use futures::FutureExt;
use multibase::Base;
use ssi_crypto::{MessageSignatureError, MessageSigner};
use ssi_vc_data_integrity_core::{
    suite::HashError, CryptographicSuite, ExpandedConfiguration, ProofConfigurationRef,
};
use ssi_verification_methods::{Ed25519VerificationKey2020, SignatureError, VerificationError};
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, suites::sha256_hash, MultibaseSignature, MultibaseSignatureRef,
};

/// EdDSA Cryptosuite v2020.
///
/// This is a legacy cryptographic suite for the usage of the EdDSA algorithm
/// and Curve25519. It is recommended to use `edssa-2022` instead.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2020;

impl Ed25519Signature2020 {
    pub const NAME: &'static str = "Ed25519Signature2020";

    pub const IRI: &'static iref::Iri = iri!("https://w3id.org/security#Ed25519Signature2020");
}

impl_rdf_input_urdna2015!(Ed25519Signature2020);

impl CryptographicSuite for Ed25519Signature2020 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = Ed25519VerificationKey2020;

    type Signature = MultibaseSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::EdDSA;

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
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct Signature {
    /// Multibase encoded signature.
    pub proof_value: String,
}

pub struct SignatureAlgorithm;

pub type MessageBuilder =
    fn(Result<Vec<u8>, MessageSignatureError>) -> Result<MultibaseSignature, SignatureError>;

fn build_signature(
    r: Result<Vec<u8>, MessageSignatureError>,
) -> Result<MultibaseSignature, SignatureError> {
    match r {
        Ok(bytes) => Ok(MultibaseSignature {
            proof_value: multibase::encode(Base::Base58Btc, bytes),
        }),
        Err(e) => Err(e.into()),
    }
}

impl ssi_verification_methods::SignatureAlgorithm<Ed25519VerificationKey2020>
    for SignatureAlgorithm
{
    type Options = ();

    type Signature = MultibaseSignature;

    type Protocol = ();

    type MessageSignatureAlgorithm = ssi_jwk::algorithm::EdDSA;

    async fn sign<S: MessageSigner<Self::MessageSignatureAlgorithm, Self::Protocol>>(
        &self,
        _options: <Self::Options as ssi_core::Referencable>::Reference<'_>,
        _method: <Ed25519VerificationKey2020 as ssi_core::Referencable>::Reference<'_>,
        bytes: &[u8],
        signer: S,
    ) -> Result<Self::Signature, SignatureError> {
        signer
            .sign(ssi_jwk::algorithm::EdDSA, (), bytes)
            .map(build_signature)
            .await
    }

    fn verify(
        &self,
        _options: (),
        signature: MultibaseSignatureRef,
        method: &Ed25519VerificationKey2020,
        bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        let signature_bytes = signature.decode()?;
        method.verify_bytes(bytes, &signature_bytes)
    }
}
