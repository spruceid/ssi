//! Data Integrity BBS Cryptosuite 2023 (v1.0) implementation.
//!
//! See: <https://www.w3.org/TR/vc-di-bbs/#bbs-2023>
use ssi_data_integrity_core::{
    suite::{ConfigurationAlgorithm, ConfigurationError, InputProofOptions},
    CryptosuiteStr, ProofConfiguration, StandardCryptographicSuite, Type, TypeRef,
    UnsupportedProofSuite,
};
use ssi_di_sd_primitives::JsonPointerBuf;
use ssi_verification_methods::Multikey;

pub(crate) mod transformation;
pub use transformation::{Bbs2023Transformation, Bbs2023TransformationOptions, Transformed};

mod hashing;
pub use hashing::{Bbs2023Hashing, HashData};

mod signature;
pub use signature::*;

mod derive;
pub use derive::*;

mod verification;

#[cfg(test)]
mod tests;

/// The `bbs-2023` cryptographic suite.
#[derive(Debug, Clone, Copy)]
pub struct Bbs2023;

impl StandardCryptographicSuite for Bbs2023 {
    type Configuration = Bbs2023Configuration;

    type Transformation = Bbs2023Transformation;

    type Hashing = Bbs2023Hashing;

    type VerificationMethod = Multikey;

    type ProofOptions = ();

    type SignatureAlgorithm = Bbs2023SignatureAlgorithm;

    fn type_(&self) -> TypeRef {
        TypeRef::DataIntegrityProof(CryptosuiteStr::new("bbs-2023").unwrap())
    }
}

impl TryFrom<Type> for Bbs2023 {
    type Error = UnsupportedProofSuite;

    fn try_from(value: Type) -> Result<Self, Self::Error> {
        match value {
            Type::DataIntegrityProof(c) if c == "bbs-2023" => Ok(Self),
            ty => Err(UnsupportedProofSuite::Compact(ty)),
        }
    }
}

#[derive(Clone)]
pub struct Bbs2023SignatureOptions {
    pub mandatory_pointers: Vec<JsonPointerBuf>,

    pub feature_option: FeatureOption,

    pub commitment_with_proof: Option<Vec<u8>>,

    pub hmac_key: Option<HmacKey>,
}

#[derive(Debug, Default, Clone, Copy)]
pub enum FeatureOption {
    #[default]
    Baseline,
    AnonymousHolderBinding,
    PseudonymIssuerPid,
    PseudonymHiddenPid,
}

pub type HmacKey = [u8; 32];

/// Base Proof Configuration.
///
/// See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-configuration-bbs-2023>
pub struct Bbs2023Configuration;

impl ConfigurationAlgorithm<Bbs2023> for Bbs2023Configuration {
    /// Input type for the verification method.
    type InputVerificationMethod = Multikey;

    /// Input suite-specific proof options.
    type InputSuiteOptions = ();

    /// Input signature options.
    type InputSignatureOptions = Bbs2023SignatureOptions;

    type InputVerificationOptions = ();

    /// Document transformation options.
    type TransformationOptions = Bbs2023TransformationOptions;

    fn configure_signature(
        type_: &Bbs2023,
        options: InputProofOptions<Bbs2023>,
        signature_options: Bbs2023SignatureOptions,
    ) -> Result<(ProofConfiguration<Bbs2023>, Bbs2023TransformationOptions), ConfigurationError>
    {
        let proof_configuration = options.into_configuration(*type_)?;
        Ok((
            proof_configuration,
            Bbs2023TransformationOptions::BaseSignature(signature_options),
        ))
    }

    fn configure_verification(
        _suite: &Bbs2023,
        _verification_options: &ssi_data_integrity_core::suite::InputVerificationOptions<Bbs2023>,
    ) -> Result<Self::TransformationOptions, ConfigurationError> {
        Ok(Bbs2023TransformationOptions::DerivedVerification)
    }
}
