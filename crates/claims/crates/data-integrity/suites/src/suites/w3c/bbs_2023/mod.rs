//! Data Integrity BBS Cryptosuite 2023 (v1.0) implementation.
//!
//! See: <https://www.w3.org/TR/vc-di-bbs/#bbs-2023>
use ssi_claims_core::DefaultEnvironment;
use ssi_data_integrity_core::{
    suite::{ConfigurationAlgorithm, ConfigurationError, InputProofOptions},
    CryptosuiteStr, ProofConfiguration, StandardCryptographicSuite, Type, TypeRef,
    UnsupportedProofSuite,
};
use ssi_di_sd_primitives::JsonPointerBuf;
use ssi_json_ld::JsonLdEnvironment;
use ssi_verification_methods::Multikey;

pub(crate) mod transformation;
pub use transformation::{Bbs2023Transformation, Transformed};

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

impl DefaultEnvironment for Bbs2023 {
    type Environment = JsonLdEnvironment;
}

#[derive(Clone)]
pub struct Bbs2023InputOptions {
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
    type InputProofOptions = ();

    /// Input signature options.
    type InputSignatureOptions = Bbs2023InputOptions;

    /// Document transformation options.
    type TransformationOptions = Bbs2023InputOptions;

    fn configure(
        type_: &Bbs2023,
        options: InputProofOptions<Bbs2023>,
        signature_options: Bbs2023InputOptions,
    ) -> Result<(ProofConfiguration<Bbs2023>, Bbs2023InputOptions), ConfigurationError> {
        let proof_configuration = options.into_configuration(*type_)?;
        Ok((proof_configuration, signature_options))
    }
}
