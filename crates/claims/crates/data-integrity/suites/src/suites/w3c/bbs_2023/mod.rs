//! Data Integrity BBS Cryptosuite 2023 (v1.0) implementation.
//!
//! See: <https://www.w3.org/TR/vc-di-bbs/#bbs-2023>
use serde::Serialize;
use ssi_bbs::BBSplusPublicKey;
use ssi_data_integrity_core::{
    suite::{ConfigurationAlgorithm, ConfigurationError, InputProofOptions},
    ProofConfiguration, StandardCryptographicSuite, TypeRef,
};
use ssi_di_sd_primitives::JsonPointerBuf;
use ssi_security::MultibaseBuf;
use ssi_verification_methods::Multikey;

pub(crate) mod transformation;
pub use transformation::{Bbs2023Transformation, Transformed};

mod hashing;
pub use hashing::{Bbs2023Hashing, HashData};

mod signature;
pub use signature::Bbs2023SignatureAlgorithm;

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
        TypeRef::DataIntegrityProof("bbs-2023")
    }
}

pub struct Bbs2023InputOptions {
    pub mandatory_pointers: Vec<JsonPointerBuf>,

    pub feature_option: FeatureOption,

    pub commitment_with_proof: Option<Vec<u8>>,
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
        let proof_configuration = options.into_configuration(type_.clone())?;
        Ok((proof_configuration, signature_options))
    }
}

#[derive(Serialize)]
pub struct Bbs2023Signature {
    pub proof_value: MultibaseBuf,
}

impl Bbs2023Signature {
    pub fn encode(
        signature_bytes: &[u8],
        bbs_header: [u8; 64],
        public_key: &BBSplusPublicKey,
        hmac_key: [u8; 32],
        mandatory_pointers: &[JsonPointerBuf],
        description: Bbs2023SignatureDescription,
    ) -> Self {
        let mut components = vec![
            serde_cbor::Value::Bytes(signature_bytes.to_vec()),
            serde_cbor::Value::Bytes(bbs_header.to_vec()),
            serde_cbor::Value::Bytes(public_key.to_bytes().to_vec()),
            serde_cbor::Value::Bytes(hmac_key.to_vec()),
            serde_cbor::Value::Array(
                mandatory_pointers
                    .iter()
                    .map(|p| p.as_str().to_owned().into())
                    .collect(),
            ),
        ];

        let tag = match description {
            Bbs2023SignatureDescription::Baseline => 0x02,
            Bbs2023SignatureDescription::AnonymousHolderBinding { signer_blind } => {
                components.push(match signer_blind {
                    Some(signer_blind) => serde_cbor::Value::Bytes(signer_blind.to_vec()),
                    None => serde_cbor::Value::Null,
                });
                0x04
            }
            Bbs2023SignatureDescription::PseudonymIssuerPid { pid } => {
                components.push(serde_cbor::Value::Bytes(pid.to_vec()));
                0x06
            }
            Bbs2023SignatureDescription::PseudonymHiddenPid { signer_blind } => {
                components.push(match signer_blind {
                    Some(signer_blind) => serde_cbor::Value::Bytes(signer_blind.to_vec()),
                    None => serde_cbor::Value::Null,
                });
                0x08
            }
        };

        let mut proof_value = vec![0xd9, 0x5d, tag];
        serde_cbor::to_writer(&mut proof_value, &components).unwrap();

        Self {
            proof_value: MultibaseBuf::encode(multibase::Base::Base64Url, proof_value),
        }
    }
}

impl AsRef<str> for Bbs2023Signature {
    fn as_ref(&self) -> &str {
        self.proof_value.as_str()
    }
}

pub enum Bbs2023SignatureDescription {
    Baseline,
    AnonymousHolderBinding { signer_blind: Option<[u8; 32]> },
    PseudonymIssuerPid { pid: [u8; 32] },
    PseudonymHiddenPid { signer_blind: Option<[u8; 32]> },
}
