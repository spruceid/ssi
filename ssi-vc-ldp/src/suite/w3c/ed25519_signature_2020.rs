//! EdDSA Cryptosuite v2020 implementation.
//!
//! This is a legacy cryptographic suite for the usage of the EdDSA algorithm
//! and Curve25519. It is recommended to use `edssa-2022` instead.
//!
//! See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, verification, CryptographicSuite, ProofConfiguration
};

use crate::suite::{sha256_hash, HashError};

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

    type Signature = Signature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> iref::Iri {
        iri!("https://w3id.org/security#Ed25519Signature2020")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        None
    }

    /// Hashing algorithm.
    fn hash(
        &self,
        data: String,
        proof_configuration: &ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }

    fn setup_signature_algorithm(&self) -> Self::SignatureAlgorithm {
        SignatureAlgorithm
    }
}

pub struct Signature {
    /// Multibase encoded signature.
    pub proof_value: String
}

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<Ed25519VerificationKey2020> for SignatureAlgorithm {
    type Signature = Signature;

    type Protocol = ();

    fn sign<S: ssi_crypto::MessageSigner<Self::Protocol>>(
            &self,
            method: &Ed25519VerificationKey2020,
            bytes: &[u8],
            signer: &S
        ) -> Result<Self::Signature, ssi_verification_methods::SignatureError> {
        todo!()
    }

    fn verify(&self,
            signature: &Self::Signature,
            method: &Ed25519VerificationKey2020,
            bytes: &[u8]
        ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}