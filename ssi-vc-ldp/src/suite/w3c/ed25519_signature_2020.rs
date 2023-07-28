//! EdDSA Cryptosuite v2020 implementation.
//!
//! This is a legacy cryptographic suite for the usage of the EdDSA algorithm
//! and Curve25519. It is recommended to use `edssa-2022` instead.
//!
//! See: <https://w3c.github.io/vc-di-eddsa/#the-ed25519signature2020-suite>
use static_iref::iri;

use crate::{
    impl_rdf_input_urdna2015, verification, CryptographicSuite, ProofConfiguration, ProofOptions,
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

#[async_trait::async_trait]
impl CryptographicSuite for Ed25519Signature2020 {
    type TransformationParameters = ();
    type Transformed = String;

    type HashParameters = ProofConfiguration<Self::VerificationMethod>;
    type Hashed = [u8; 64];

    type ProofParameters = ProofOptions<Self::VerificationMethod>;

    type SigningParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationParameters = ProofOptions<Self::VerificationMethod>;

    type VerificationMethod = verification::MethodReferenceOrOwned<Ed25519VerificationKey2020>;

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
        proof_configuration: ProofConfiguration<Self::VerificationMethod>,
    ) -> Result<Self::Hashed, HashError> {
        Ok(sha256_hash(data.as_bytes(), self, proof_configuration))
    }
}
