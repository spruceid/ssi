use ssi_data_integrity_core::{
    CryptosuiteStr, StandardCryptographicSuite, Type, TypeRef, UnsupportedProofSuite,
};

mod configuration;
pub use configuration::*;

mod transformation;
use ssi_verification_methods::Multikey;
pub use transformation::*;

mod hashing;
pub use hashing::*;

mod signature;
pub use signature::*;

mod verification;

/// The `ecdsa-sd-2023` cryptographic suite.
///
/// See: <https://www.w3.org/TR/vc-di-ecdsa/#ecdsa-sd-2023>
#[derive(Debug, Clone, Copy)]
pub struct EcdsaSd2023;

impl StandardCryptographicSuite for EcdsaSd2023 {
    type Configuration = ConfigurationAlgorithm;

    type Transformation = TransformationAlgorithm;

    type Hashing = HashingAlgorithm;

    type VerificationMethod = Multikey;

    type ProofOptions = ();

    type SignatureAlgorithm = SignatureAlgorithm;

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof(CryptosuiteStr::new("ecdsa-sd-2023").unwrap())
    }
}

impl TryFrom<Type> for EcdsaSd2023 {
    type Error = UnsupportedProofSuite;

    fn try_from(value: Type) -> Result<Self, Self::Error> {
        match value {
            Type::DataIntegrityProof(c) if c == "ecdsa-sd-2023" => Ok(Self),
            ty => Err(UnsupportedProofSuite::Compact(ty)),
        }
    }
}
