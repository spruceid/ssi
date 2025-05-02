use multibase::Base;
use ssi_bbs::{BBSplusPublicKey, Bbs};
use ssi_claims_core::SignatureError;
use ssi_crypto::algorithm::{BbsInstance, BbsParameters};
use ssi_di_sd_primitives::JsonPointerBuf;
use ssi_rdf::IntoNQuads;
use ssi_security::MultibaseBuf;
use ssi_verification_methods::{multikey::DecodedMultikey, MessageSigner, Multikey};

use crate::bbs_2023::{hashing::BaseHashData, FeatureOption};

use super::{Bbs2023Signature, Bbs2023SignatureDescription, InvalidBbs2023Signature};

pub async fn generate_base_proof<T>(
    verification_method: &Multikey,
    signer: T,
    hash_data: BaseHashData,
) -> Result<Bbs2023Signature, SignatureError>
where
    T: MessageSigner<Bbs>,
{
    // See: <https://www.w3.org/TR/vc-di-bbs/#base-proof-serialization-bbs-2023>
    let DecodedMultikey::Bls12_381(public_key) = verification_method.public_key.decode()? else {
        return Err(SignatureError::InvalidPublicKey);
    };
    let feature_option = hash_data.transformed_document.options.feature_option;
    let proof_hash = &hash_data.proof_hash;
    let mandatory_pointers = &hash_data.transformed_document.options.mandatory_pointers;
    let mandatory_hash = &hash_data.mandatory_hash;
    let non_mandatory = &hash_data.transformed_document.non_mandatory;
    let hmac_key = hash_data.transformed_document.hmac_key;

    let mut bbs_header = [0; 64];
    bbs_header[..32].copy_from_slice(proof_hash);
    bbs_header[32..].copy_from_slice(mandatory_hash);

    let mut messages: Vec<_> = non_mandatory
        .into_nquads_lines()
        .into_iter()
        .map(String::into_bytes)
        .collect();

    let (bbs_params, description) = match feature_option {
        FeatureOption::Baseline => (
            BbsParameters::Baseline { header: bbs_header },
            Bbs2023SignatureDescription::Baseline,
        ),
        FeatureOption::AnonymousHolderBinding => (
            BbsParameters::Blind {
                header: bbs_header,
                commitment_with_proof: None,
                signer_blind: None,
            },
            Bbs2023SignatureDescription::AnonymousHolderBinding { signer_blind: None },
        ),
        FeatureOption::PseudonymIssuerPid => {
            // See: <https://www.ietf.org/archive/id/draft-vasilis-bbs-per-verifier-linkability-00.html#section-4.1>
            let mut pid = [0u8; 32];
            getrandom::getrandom(&mut pid).map_err(SignatureError::other)?;

            messages.push(pid.to_vec());

            (
                BbsParameters::Baseline { header: bbs_header },
                Bbs2023SignatureDescription::PseudonymIssuerPid { pid },
            )
        }
        FeatureOption::PseudonymHiddenPid => {
            // See: <https://www.ietf.org/archive/id/draft-vasilis-bbs-per-verifier-linkability-00.html#section-4.1>
            let commitment_with_proof = hash_data
                .transformed_document
                .options
                .commitment_with_proof
                .clone()
                .ok_or_else(|| SignatureError::missing_required_option("commitment_with_proof"))?;

            (
                BbsParameters::Blind {
                    header: bbs_header,
                    commitment_with_proof: Some(commitment_with_proof),
                    signer_blind: None,
                },
                Bbs2023SignatureDescription::PseudonymHiddenPid { signer_blind: None },
            )
        }
    };

    let signature = signer
        .sign_multi(BbsInstance(Box::new(bbs_params)), &messages)
        .await?;

    Ok(Bbs2023Signature::encode_base(
        &signature,
        bbs_header,
        public_key,
        hmac_key,
        mandatory_pointers,
        description,
    ))
}

impl Bbs2023Signature {
    pub fn encode_base(
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
    pub fn decode_base(&self) -> Result<DecodedBaseProof, InvalidBbs2023Signature> {
        let (base, decoded_proof_value) = self
            .proof_value
            .decode()
            .map_err(|_| InvalidBbs2023Signature)?;

        if base != Base::Base64Url || decoded_proof_value.len() < 3 {
            return Err(InvalidBbs2023Signature);
        }

        let header = [
            decoded_proof_value[0],
            decoded_proof_value[1],
            decoded_proof_value[2],
        ];

        let mut components =
            serde_cbor::from_slice::<Vec<serde_cbor::Value>>(&decoded_proof_value[3..])
                .map_err(|_| InvalidBbs2023Signature)?
                .into_iter();

        let Some(serde_cbor::Value::Bytes(signature_bytes)) = components.next() else {
            return Err(InvalidBbs2023Signature);
        };

        let Some(serde_cbor::Value::Bytes(bbs_header)) = components.next() else {
            return Err(InvalidBbs2023Signature);
        };

        let bbs_header: [u8; 64] = bbs_header.try_into().map_err(|_| InvalidBbs2023Signature)?;

        let Some(serde_cbor::Value::Bytes(public_key)) = components.next() else {
            return Err(InvalidBbs2023Signature);
        };

        let public_key =
            BBSplusPublicKey::from_bytes(&public_key).map_err(|_| InvalidBbs2023Signature)?;

        let Some(serde_cbor::Value::Bytes(hmac_key)) = components.next() else {
            return Err(InvalidBbs2023Signature);
        };

        let hmac_key: [u8; 32] = hmac_key.try_into().map_err(|_| InvalidBbs2023Signature)?;

        let Some(serde_cbor::Value::Array(mandatory_pointers_values)) = components.next() else {
            return Err(InvalidBbs2023Signature);
        };

        let mut mandatory_pointers = Vec::with_capacity(mandatory_pointers_values.len());

        for value in mandatory_pointers_values {
            let serde_cbor::Value::Text(text) = value else {
                return Err(InvalidBbs2023Signature);
            };

            let pointer = JsonPointerBuf::new(text).map_err(|_| InvalidBbs2023Signature)?;

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
                            .map_err(|_| InvalidBbs2023Signature)?,
                    ),
                    Some(serde_cbor::Value::Null) => None,
                    _ => return Err(InvalidBbs2023Signature),
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
                    return Err(InvalidBbs2023Signature);
                };

                let pid: [u8; 32] = pid.try_into().map_err(|_| InvalidBbs2023Signature)?;

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
                            .map_err(|_| InvalidBbs2023Signature)?,
                    ),
                    Some(serde_cbor::Value::Null) => None,
                    _ => return Err(InvalidBbs2023Signature),
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
            _ => Err(InvalidBbs2023Signature),
        }
    }
}

#[derive(Clone)]
pub struct DecodedBaseProof {
    pub signature_bytes: Vec<u8>,
    pub bbs_header: [u8; 64],
    pub public_key: BBSplusPublicKey,
    pub hmac_key: [u8; 32],
    pub mandatory_pointers: Vec<JsonPointerBuf>,
    pub description: Bbs2023SignatureDescription,
}
