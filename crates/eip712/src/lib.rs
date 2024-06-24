use keccak_hash::keccak;
use serde::{Deserialize, Serialize};

mod encode;
mod hashing;
mod ty;
mod value;

pub use hashing::TypedDataHashError;
pub use ty::*;
pub use value::*;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TypedData {
    pub types: Types,
    pub primary_type: StructName,
    pub domain: Value,
    pub message: Value,
}

impl TypedData {
    /// Encode a typed data message for hashing and signing.
    /// [Reference](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#specification)
    pub fn hash(&self) -> Result<[u8; 32], TypedDataHashError> {
        let bytes = self.encode()?;
        Ok(keccak(bytes).to_fixed_bytes())
    }

    pub fn encode(&self) -> Result<[u8; 66], TypedDataHashError> {
        let message_hash = self.message.hash(&self.primary_type, &self.types)?;
        let domain_separator = self
            .domain
            .hash(&StructName::from("EIP712Domain"), &self.types)?;

        let mut result = [0; 66];
        result[0] = 0x19;
        result[1] = 0x01;
        result[2..34].copy_from_slice(&domain_separator);
        result[34..].copy_from_slice(&message_hash);

        Ok(result)
    }
}

pub(crate) fn bytes_from_hex(s: &str) -> Option<Vec<u8>> {
    s.strip_prefix("0x")
        .and_then(|hex_str| hex::decode(hex_str).ok())
}
