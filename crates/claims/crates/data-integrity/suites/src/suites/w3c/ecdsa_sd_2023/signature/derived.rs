use multibase::Base;
use rdf_types::BlankIdBuf;
use ssi_claims_core::ProofValidationError;
use ssi_multicodec::{MultiEncoded, MultiEncodedBuf};
use ssi_security::MultibaseBuf;
use std::collections::{BTreeMap, HashMap};

use super::Signature;

#[derive(Debug, thiserror::Error)]
#[error("invalid derived signature")]
pub struct InvalidDerivedSignature;

impl From<InvalidDerivedSignature> for ProofValidationError {
    fn from(_value: InvalidDerivedSignature) -> Self {
        Self::InvalidProof
    }
}

impl Signature {
    pub fn encode_derived(
        base_signature: &[u8],
        public_key: &MultiEncoded,
        signatures: &[Vec<u8>],
        label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
        mandatory_indexes: &[usize],
    ) -> Self {
        let components = vec![
            serde_cbor::Value::Bytes(base_signature.to_vec()),
            serde_cbor::Value::Bytes(public_key.as_bytes().to_vec()),
            serde_cbor::Value::Array(signatures.iter().map(|s| s.to_vec().into()).collect()),
            serde_cbor::Value::Map(compress_label_map(label_map)),
            serde_cbor::Value::Array(
                mandatory_indexes
                    .iter()
                    .map(|&i| serde_cbor::Value::Integer(i as i128))
                    .collect(),
            ),
        ];

        let mut proof_value = vec![0xd9, 0x5d, 0x01];
        serde_cbor::to_writer(&mut proof_value, &components).unwrap();

        Self {
            proof_value: MultibaseBuf::encode(Base::Base64Url, proof_value),
        }
    }

    pub fn decode_derived(&self) -> Result<DecodedDerivedProof, InvalidDerivedSignature> {
        let (base, decoded_proof_value) = self
            .proof_value
            .decode()
            .map_err(|_| InvalidDerivedSignature)?;

        if base != Base::Base64Url || decoded_proof_value.len() < 3 {
            return Err(InvalidDerivedSignature);
        }

        let header = [
            decoded_proof_value[0],
            decoded_proof_value[1],
            decoded_proof_value[2],
        ];

        if header != [0xd9, 0x5d, 0x01] {
            return Err(InvalidDerivedSignature);
        }

        let mut components =
            serde_cbor::from_slice::<Vec<serde_cbor::Value>>(&decoded_proof_value[3..])
                .map_err(|_| InvalidDerivedSignature)?
                .into_iter();

        let Some(serde_cbor::Value::Bytes(signature_bytes)) = components.next() else {
            return Err(InvalidDerivedSignature);
        };

        let Some(serde_cbor::Value::Bytes(public_key_bytes)) = components.next() else {
            return Err(InvalidDerivedSignature);
        };

        let public_key =
            MultiEncodedBuf::new(public_key_bytes).map_err(|_| InvalidDerivedSignature)?;

        let Some(serde_cbor::Value::Array(signatures_values)) = components.next() else {
            return Err(InvalidDerivedSignature);
        };

        let mut signatures = Vec::with_capacity(signatures_values.len());
        for value in signatures_values {
            let serde_cbor::Value::Bytes(signature) = value else {
                return Err(InvalidDerivedSignature);
            };

            signatures.push(signature)
        }

        let Some(serde_cbor::Value::Map(compressed_label_map)) = components.next() else {
            return Err(InvalidDerivedSignature);
        };

        let label_map = decompress_label_map(&compressed_label_map)?;

        let Some(serde_cbor::Value::Array(mandatory_indexes)) = components.next() else {
            return Err(InvalidDerivedSignature);
        };

        let mandatory_indexes = decode_indexes(mandatory_indexes)?;

        Ok(DecodedDerivedProof {
            base_signature: signature_bytes,
            public_key,
            signatures,
            label_map,
            mandatory_indexes,
        })
    }
}

pub struct DecodedDerivedProof {
    pub base_signature: Vec<u8>,
    pub public_key: MultiEncodedBuf,
    pub signatures: Vec<Vec<u8>>,
    pub label_map: HashMap<BlankIdBuf, BlankIdBuf>,
    pub mandatory_indexes: Vec<usize>,
}

fn compress_label_map(
    label_map: &HashMap<BlankIdBuf, BlankIdBuf>,
) -> BTreeMap<serde_cbor::Value, serde_cbor::Value> {
    let mut map = BTreeMap::new();

    for (k, v) in label_map {
        let ki = k.strip_prefix("_:c14n").unwrap().parse().unwrap();
        let vb = Base::Base64Url
            .decode(v.strip_prefix("_:u").unwrap())
            .unwrap();
        map.insert(serde_cbor::Value::Integer(ki), serde_cbor::Value::Bytes(vb));
    }

    map
}

fn decompress_label_map(
    compressed_label_map: &BTreeMap<serde_cbor::Value, serde_cbor::Value>,
) -> Result<HashMap<BlankIdBuf, BlankIdBuf>, InvalidDerivedSignature> {
    let mut map = HashMap::new();

    for (ki, vb) in compressed_label_map {
        let serde_cbor::Value::Integer(ki) = ki else {
            return Err(InvalidDerivedSignature);
        };

        let serde_cbor::Value::Bytes(vb) = vb else {
            return Err(InvalidDerivedSignature);
        };

        let k = BlankIdBuf::new(format!("_:c14n{ki}")).unwrap();
        let v = BlankIdBuf::new(format!("_:u{}", Base::Base64Url.encode(vb))).unwrap();

        map.insert(k, v);
    }

    Ok(map)
}

fn decode_indexes(
    encoded_indexes: Vec<serde_cbor::Value>,
) -> Result<Vec<usize>, InvalidDerivedSignature> {
    let mut indexes = Vec::with_capacity(encoded_indexes.len());

    for v in encoded_indexes {
        let serde_cbor::Value::Integer(i) = v else {
            return Err(InvalidDerivedSignature);
        };

        indexes.push(i.try_into().map_err(|_| InvalidDerivedSignature)?)
    }

    Ok(indexes)
}
