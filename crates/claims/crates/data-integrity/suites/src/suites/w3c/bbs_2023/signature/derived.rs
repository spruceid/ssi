use std::collections::{BTreeMap, HashMap};

use crate::bbs_2023::DerivedFeatureOption;
use multibase::Base;
use rdf_types::BlankIdBuf;
use ssi_security::MultibaseBuf;

use super::{Bbs2023Signature, InvalidBbs2023Signature, UnsupportedBbs2023Signature};

impl Bbs2023Signature {
    pub fn encode_derived(
        bbs_proof: &[u8],
        label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
        mandatory_indexes: &[usize],
        selective_indexes: &[usize],
        presentation_header: Option<&[u8]>,
        feature_option: &DerivedFeatureOption,
    ) -> Result<Self, UnsupportedBbs2023Signature> {
        let comperessed_label_map = compress_label_map(label_map);

        let components = vec![
            serde_cbor::Value::Bytes(bbs_proof.to_vec()),
            serde_cbor::Value::Map(comperessed_label_map),
            serde_cbor::Value::Array(
                mandatory_indexes
                    .iter()
                    .map(|i| serde_cbor::Value::Integer(*i as i128))
                    .collect(),
            ),
            serde_cbor::Value::Array(
                selective_indexes
                    .iter()
                    .map(|i| serde_cbor::Value::Integer(*i as i128))
                    .collect(),
            ),
            match presentation_header {
                Some(presentation_header) => serde_cbor::Value::Bytes(presentation_header.to_vec()),
                None => serde_cbor::Value::Null,
            },
        ];

        let tag = match feature_option {
            DerivedFeatureOption::Baseline => 0x03,
            DerivedFeatureOption::AnonymousHolderBinding { .. } => {
                return Err(UnsupportedBbs2023Signature)
            }
            DerivedFeatureOption::PseudonymIssuerPid { .. } => {
                return Err(UnsupportedBbs2023Signature)
            }
            DerivedFeatureOption::PseudonymHiddenPid { .. } => {
                return Err(UnsupportedBbs2023Signature)
            }
        };

        let mut proof_value = vec![0xd9, 0x5d, tag];
        serde_cbor::to_writer(&mut proof_value, &components).unwrap();

        Ok(Self {
            proof_value: MultibaseBuf::encode(multibase::Base::Base64Url, proof_value),
        })
    }

    pub fn decode_derived(&self) -> Result<DecodedDerivedProof, InvalidBbs2023Signature> {
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

        let Some(serde_cbor::Value::Map(compressed_label_map)) = components.next() else {
            return Err(InvalidBbs2023Signature);
        };

        let label_map = decompress_label_map(&compressed_label_map)?;

        let Some(serde_cbor::Value::Array(mandatory_indexes)) = components.next() else {
            return Err(InvalidBbs2023Signature);
        };

        let mandatory_indexes = decode_indexes(mandatory_indexes)?;

        let Some(serde_cbor::Value::Array(selective_indexes)) = components.next() else {
            return Err(InvalidBbs2023Signature);
        };

        let selective_indexes = decode_indexes(selective_indexes)?;

        let presentation_header = match components.next() {
            Some(serde_cbor::Value::Null) => None,
            Some(serde_cbor::Value::Bytes(presentation_header)) => Some(presentation_header),
            _ => return Err(InvalidBbs2023Signature),
        };

        match header {
            [0xd9, 0x5d, 0x03] => {
                // baseline
                Ok(DecodedDerivedProof {
                    bbs_proof: signature_bytes,
                    label_map,
                    mandatory_indexes,
                    selective_indexes,
                    presentation_header,
                    feature_option: DerivedFeatureOption::Baseline,
                })
            }
            [0xd9, 0x5d, 0x05] => {
                // anonymous_holder_binding
                Err(InvalidBbs2023Signature)
            }
            [0xd9, 0x5d, 0x07] => {
                // pseudonym_issuer_pid
                Err(InvalidBbs2023Signature)
            }
            [0xd9, 0x5d, 0x09] => {
                // pseudonym_hidden_pid
                Err(InvalidBbs2023Signature)
            }
            _ => Err(InvalidBbs2023Signature),
        }
    }
}

pub struct DecodedDerivedProof {
    pub bbs_proof: Vec<u8>,
    pub label_map: HashMap<BlankIdBuf, BlankIdBuf>,
    pub mandatory_indexes: Vec<usize>,
    pub selective_indexes: Vec<usize>,
    pub presentation_header: Option<Vec<u8>>,
    pub feature_option: DerivedFeatureOption,
}

fn compress_label_map(
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
) -> BTreeMap<serde_cbor::Value, serde_cbor::Value> {
    let mut map = BTreeMap::new();

    for (k, v) in label_map {
        let ki: i128 = k.strip_prefix("_:c14n").unwrap().parse().unwrap();
        let vi: i128 = v.strip_prefix("_:b").unwrap().parse().unwrap();
        map.insert(
            serde_cbor::Value::Integer(ki),
            serde_cbor::Value::Integer(vi),
        );
    }

    map
}

fn decompress_label_map(
    compressed_label_map: &BTreeMap<serde_cbor::Value, serde_cbor::Value>,
) -> Result<HashMap<BlankIdBuf, BlankIdBuf>, InvalidBbs2023Signature> {
    let mut map = HashMap::new();

    for (ki, vi) in compressed_label_map {
        let serde_cbor::Value::Integer(ki) = ki else {
            return Err(InvalidBbs2023Signature);
        };

        let serde_cbor::Value::Integer(vi) = vi else {
            return Err(InvalidBbs2023Signature);
        };

        let k = BlankIdBuf::new(format!("_:c14n{ki}")).unwrap();
        let v = BlankIdBuf::new(format!("_:b{vi}")).unwrap();

        map.insert(k, v);
    }

    Ok(map)
}

fn decode_indexes(
    encoded_indexes: Vec<serde_cbor::Value>,
) -> Result<Vec<usize>, InvalidBbs2023Signature> {
    let mut indexes = Vec::with_capacity(encoded_indexes.len());

    for v in encoded_indexes {
        let serde_cbor::Value::Integer(i) = v else {
            return Err(InvalidBbs2023Signature);
        };

        indexes.push(i.try_into().map_err(|_| InvalidBbs2023Signature)?)
    }

    Ok(indexes)
}
