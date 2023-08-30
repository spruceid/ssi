//! EdDSA Cryptosuite v2020 implementation.
//!
//! This is a legacy cryptographic suite for the usage of the EdDSA algorithm
//! and Curve25519. It is recommended to use `edssa-2022` instead.
//!
//! See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
use std::future;

use futures::FutureExt;
use multibase::Base;
use ssi_crypto::{MessageSignatureError, MessageSigner};
use ssi_verification_methods::{SignatureError, VerificationError};
use static_iref::iri;

use crate::{impl_rdf_input_urdna2015, verification, CryptographicSuite, ProofConfigurationRef};

use crate::suite::{sha256_hash, HashError, MultibaseSignature, MultibaseSignatureRef};

pub use verification::method::Ed25519VerificationKey2020;

/// EdDSA Cryptosuite v2020.
///
/// This is a legacy cryptographic suite for the usage of the EdDSA algorithm
/// and Curve25519. It is recommended to use `edssa-2022` instead.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
#[derive(Debug, Default, Clone, Copy)]
pub struct Ed25519Signature2020;

impl_rdf_input_urdna2015!(Ed25519Signature2020);

impl CryptographicSuite for Ed25519Signature2020 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = Ed25519VerificationKey2020;

    type Signature = MultibaseSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> &iref::Iri {
        iri!("https://w3id.org/security#Ed25519Signature2020")
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
    type Signature = MultibaseSignature;

    type Protocol = ();

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> =
        futures::future::Map<S::Sign<'a>, MessageBuilder>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        method: &Ed25519VerificationKey2020,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        signer.sign((), bytes).map(build_signature)
    }

    fn verify(
        &self,
        signature: MultibaseSignatureRef,
        method: &Ed25519VerificationKey2020,
        bytes: &[u8],
    ) -> Result<bool, VerificationError> {
        let (_, signature_bytes) = multibase::decode(signature.proof_value)
            .map_err(|_| VerificationError::InvalidSignature)?;
        method.verify_bytes(bytes, &signature_bytes)
    }
}
