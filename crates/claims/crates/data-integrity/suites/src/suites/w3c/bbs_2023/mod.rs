//! Data Integrity BBS Cryptosuite 2023 (v1.0) implementation.
//!
//! See: <https://www.w3.org/TR/vc-di-bbs/#bbs-2023>
use multibase::Base;
use serde::{Deserialize, Serialize};
use ssi_bbs::BBSplusPublicKey;
use ssi_data_integrity_core::{
    suite::{
        standard::TransformationError, ConfigurationAlgorithm, ConfigurationError,
        InputProofOptions,
    },
    Proof, ProofConfiguration, StandardCryptographicSuite, TypeRef,
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

pub enum Bbs2023InputOptions {
    Base(Bbs2023BaseInputOptions),
    Derived(Bbs2023DerivedInputOptions),
}

pub struct Bbs2023BaseInputOptions {
    pub mandatory_pointers: Vec<JsonPointerBuf>,

    pub feature_option: FeatureOption,

    pub commitment_with_proof: Option<Vec<u8>>,

    pub hmac_key: Option<HmacKey>,
}

pub struct Bbs2023DerivedInputOptions {
    pub proof: Proof<Bbs2023>,

    pub selective_pointers: Vec<JsonPointerBuf>,

    pub feature_option: DerivedFeatureOption,

    pub presentation_header: Option<Vec<u8>>,
}

#[derive(Debug, Default, Clone, Copy)]
pub enum FeatureOption {
    #[default]
    Baseline,
    AnonymousHolderBinding,
    PseudonymIssuerPid,
    PseudonymHiddenPid,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "featureOption")]
pub enum DerivedFeatureOption {
    Baseline,
    AnonymousHolderBinding {
        holder_secret: String,
        prover_blind: String,
    },
    PseudonymIssuerPid {
        verifier_id: String,
    },
    PseudonymHiddenPid {
        pid: String,
        prover_blind: String,
        verifier_id: String,
    },
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

pub struct DecodedBaseProof {
    pub signature_bytes: Vec<u8>,
    pub bbs_header: [u8; 64],
    pub public_key: BBSplusPublicKey,
    pub hmac_key: [u8; 32],
    pub mandatory_pointers: Vec<JsonPointerBuf>,
    pub description: Bbs2023SignatureDescription,
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

    /// Parses the components of a bbs-2023 selective disclosure base proof
    /// value.
    ///
    /// See: <https://www.w3.org/TR/vc-di-bbs/#parsebaseproofvalue>
    pub fn decode_base_proof(&self) -> Result<DecodedBaseProof, TransformationError> {
        let (base, decoded_proof_value) = self
            .proof_value
            .decode()
            .map_err(|_| TransformationError::InvalidInput)?;

        if base != Base::Base64Url || decoded_proof_value.len() < 3 {
            return Err(TransformationError::InvalidInput);
        }

        let header = [
            decoded_proof_value[0],
            decoded_proof_value[1],
            decoded_proof_value[2],
        ];

        let mut components =
            serde_cbor::from_slice::<Vec<serde_cbor::Value>>(&decoded_proof_value[3..])
                .map_err(|_| TransformationError::InvalidInput)?
                .into_iter();

        let Some(serde_cbor::Value::Bytes(signature_bytes)) = components.next() else {
            return Err(TransformationError::InvalidInput);
        };

        let Some(serde_cbor::Value::Bytes(bbs_header)) = components.next() else {
            return Err(TransformationError::InvalidInput);
        };

        let bbs_header: [u8; 64] = bbs_header
            .try_into()
            .map_err(|_| TransformationError::InvalidInput)?;

        let Some(serde_cbor::Value::Bytes(public_key)) = components.next() else {
            return Err(TransformationError::InvalidInput);
        };

        let public_key = BBSplusPublicKey::from_bytes(&public_key)
            .map_err(|_| TransformationError::InvalidInput)?;

        let Some(serde_cbor::Value::Bytes(hmac_key)) = components.next() else {
            return Err(TransformationError::InvalidInput);
        };

        let hmac_key: [u8; 32] = hmac_key
            .try_into()
            .map_err(|_| TransformationError::InvalidInput)?;

        let Some(serde_cbor::Value::Array(mandatory_pointers_values)) = components.next() else {
            return Err(TransformationError::InvalidInput);
        };

        let mut mandatory_pointers = Vec::with_capacity(mandatory_pointers_values.len());
        for value in mandatory_pointers_values {
            let serde_cbor::Value::Bytes(bytes) = value else {
                return Err(TransformationError::InvalidInput);
            };

            let pointer =
                JsonPointerBuf::from_bytes(bytes).map_err(|_| TransformationError::InvalidInput)?;

            mandatory_pointers.push(pointer);
        }

        match header {
            [0xd9, 0x5d, 0x02] => {
                // baseline
                Ok(DecodedBaseProof {
                    signature_bytes,
                    bbs_header,
                    public_key,
                    hmac_key,
                    mandatory_pointers,
                    description: Bbs2023SignatureDescription::Baseline,
                })
            }
            [0xd9, 0x5d, 0x04] => {
                // anonymous_holder_binding
                let signer_blind = match components.next() {
                    Some(serde_cbor::Value::Bytes(signer_blind)) => Some(
                        signer_blind
                            .try_into()
                            .map_err(|_| TransformationError::InvalidInput)?,
                    ),
                    Some(serde_cbor::Value::Null) => None,
                    _ => return Err(TransformationError::InvalidInput),
                };

                Ok(DecodedBaseProof {
                    signature_bytes,
                    bbs_header,
                    public_key,
                    hmac_key,
                    mandatory_pointers,
                    description: Bbs2023SignatureDescription::AnonymousHolderBinding {
                        signer_blind,
                    },
                })
            }
            [0xd9, 0x5d, 0x06] => {
                // pseudonym_issuer_pid
                let Some(serde_cbor::Value::Bytes(pid)) = components.next() else {
                    return Err(TransformationError::InvalidInput);
                };

                let pid: [u8; 32] = pid
                    .try_into()
                    .map_err(|_| TransformationError::InvalidInput)?;

                Ok(DecodedBaseProof {
                    signature_bytes,
                    bbs_header,
                    public_key,
                    hmac_key,
                    mandatory_pointers,
                    description: Bbs2023SignatureDescription::PseudonymIssuerPid { pid },
                })
            }
            [0xd9, 0x5d, 0x08] => {
                // pseudonym_hidden_pid
                let signer_blind = match components.next() {
                    Some(serde_cbor::Value::Bytes(signer_blind)) => Some(
                        signer_blind
                            .try_into()
                            .map_err(|_| TransformationError::InvalidInput)?,
                    ),
                    Some(serde_cbor::Value::Null) => None,
                    _ => return Err(TransformationError::InvalidInput),
                };

                Ok(DecodedBaseProof {
                    signature_bytes,
                    bbs_header,
                    public_key,
                    hmac_key,
                    mandatory_pointers,
                    description: Bbs2023SignatureDescription::AnonymousHolderBinding {
                        signer_blind,
                    },
                })
            }
            _ => return Err(TransformationError::InvalidInput),
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
