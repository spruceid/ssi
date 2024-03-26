use keccak_hash::keccak;

use crate::{StructName, TypeDefinition, TypeRef, Types, Value, ValueKind};

#[derive(Debug, thiserror::Error)]
pub enum TypedDataHashError {
    #[error("Missing referenced type: {0}")]
    MissingReferencedType(String),
    #[error("Missing struct member: {0}")]
    MissingStructMember(String),
    #[error("Expected string")]
    ExpectedString,
    #[error("Expected bytes")]
    ExpectedBytes,
    #[error("Expected boolean")]
    ExpectedBoolean,
    #[error("Expected `{0}` array, found {1}")]
    ExpectedArray(String, ValueKind),
    #[error("Expected `{0}` struct, found {1}")]
    ExpectedObject(String, ValueKind),
    #[error("Expected integer")]
    ExpectedInteger,
    #[error("Expected address length 20 but found {0}")]
    ExpectedAddressLength(usize),
    #[error("Expected bytes length {0} but found {1}")]
    ExpectedBytesLength(usize, usize),
    #[error("Expected array length {0} but found {1}")]
    ExpectedArrayLength(usize, usize),
    #[error("Expected integer max length 32 bytes but found {0}")]
    IntegerTooLong(usize),
    #[error("Type not byte-aligned: {0} {1}")]
    TypeNotByteAligned(&'static str, usize),
    #[error("Expected bytes length between 1 and 32: {0}")]
    BytesLength(usize),
    #[error("Expected integer length between 8 and 256: {0}")]
    IntegerLength(usize),
    #[error("Expected string to be hex bytes")]
    ExpectedHex,
    #[error("Untyped properties: {0:?}")]
    UntypedProperties(Vec<String>),
}

impl Value {
    /// Hash the value.
    ///
    /// See: <https://eips.ethereum.org/EIPS/eip-712#definition-of-hashstruct>
    #[allow(clippy::ptr_arg)]
    pub fn hash(
        &self,
        struct_name: &StructName,
        types: &Types,
    ) -> Result<[u8; 32], TypedDataHashError> {
        let encoded_data = self
            .encode(&TypeRef::Struct(struct_name.clone()), types)?
            .to_vec();
        Ok(keccak(encoded_data).to_fixed_bytes())
    }
}

impl TypeDefinition {
    /// Encodes and hash this type.
    #[allow(clippy::ptr_arg)]
    pub fn hash(
        &self,
        struct_name: &StructName,
        types: &Types,
    ) -> Result<[u8; 32], TypedDataHashError> {
        let encoded_type = self.encode(struct_name, types)?.to_vec();
        let type_hash = keccak(encoded_type).to_fixed_bytes();
        Ok(type_hash)
    }
}
