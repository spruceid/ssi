//! EdDSA Cryptosuite v2022 implementation.
//!
//! This is the successor of the EdDSA Cryptosuite v2020.
//!
//! See: <https://w3c.github.io/vc-di-eddsa/>
use std::future;

use ssi_crypto::MessageSigner;
use ssi_verification_methods::SignatureError;
use static_iref::iri;

use crate::{impl_rdf_input_urdna2015, verification, CryptographicSuite, ProofConfigurationRef};

use crate::suite::{sha256_hash, HashError, MultibaseSignature, MultibaseSignatureRef};

pub use verification::method::Multikey;

/// EdDSA Cryptosuite v2020.
///
/// This is a legacy cryptographic suite for the usage of the EdDSA algorithm
/// and Curve25519. It is recommended to use `edssa-2022` instead.
///
/// See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
#[derive(Debug, Default, Clone, Copy)]
pub struct EdDsa2022;

impl_rdf_input_urdna2015!(EdDsa2022);

impl CryptographicSuite for EdDsa2022 {
    type Transformed = String;
    type Hashed = [u8; 64];

    type VerificationMethod = Multikey;

    type Signature = MultibaseSignature;

    type SignatureProtocol = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    type Options = ();

    fn iri(&self) -> &iref::Iri {
        iri!("https://w3id.org/security#DataIntegrityProof")
    }

    fn cryptographic_suite(&self) -> Option<&str> {
        Some("eddsa-2022")
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

pub struct SignatureAlgorithm;

impl ssi_verification_methods::SignatureAlgorithm<Multikey> for SignatureAlgorithm {
    type Options = ();

    type Signature = MultibaseSignature;

    type Protocol = ();

    type Sign<'a, S: 'a + MessageSigner<Self::Protocol>> =
        future::Ready<Result<Self::Signature, SignatureError>>;

    fn sign<'a, S: 'a + MessageSigner<Self::Protocol>>(
        &self,
        options: (),
        method: &Multikey,
        bytes: &'a [u8],
        signer: S,
    ) -> Self::Sign<'a, S> {
        todo!()
    }

    fn verify(
        &self,
        options: (),
        signature: MultibaseSignatureRef,
        method: &Multikey,
        bytes: &[u8],
    ) -> Result<bool, ssi_verification_methods::VerificationError> {
        todo!()
    }
}
