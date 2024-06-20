use std::collections::HashMap;

use keccak_hash::keccak;

use crate::{
    bytes_from_hex, hashing::TypedDataHashError, StructName, TypeDefinition, TypeRef, Types, Value,
};

static EMPTY_32: [u8; 32] = [0; 32];

impl Value {
    pub fn as_bytes(&self) -> Result<Option<Vec<u8>>, TypedDataHashError> {
        let bytes = match self {
            Value::Bytes(bytes) => bytes.to_vec(),
            Value::Integer(int) => int.to_be_bytes().to_vec(),
            Value::String(string) => {
                bytes_from_hex(string).ok_or(TypedDataHashError::ExpectedHex)?
            }
            _ => {
                return Err(TypedDataHashError::ExpectedBytes);
            }
        };
        Ok(Some(bytes))
    }

    /// Encode the value into a byte string according to the [EIP-712
    /// `encodeData` function][1].
    ///
    /// Note: this implementation follows eth-sig-util
    /// which [diverges from EIP-712 when encoding arrays][2].
    ///
    /// [1]: <https://eips.ethereum.org/EIPS/eip-712#definition-of-encodedata>
    /// [2]: <https://github.com/MetaMask/eth-sig-util/issues/106>
    pub fn encode(&self, type_: &TypeRef, types: &Types) -> Result<Vec<u8>, TypedDataHashError> {
        let bytes = match type_ {
            TypeRef::Bytes => {
                let bytes_opt;
                let bytes = match self {
                    Value::Bytes(bytes) => Some(bytes),
                    Value::String(string) => {
                        bytes_opt = bytes_from_hex(string);
                        bytes_opt.as_ref()
                    }
                    _ => None,
                }
                .ok_or(TypedDataHashError::ExpectedBytes)?;
                keccak(bytes).to_fixed_bytes().to_vec()
            }
            TypeRef::String => {
                let string = match self {
                    Value::String(string) => string,
                    _ => {
                        return Err(TypedDataHashError::ExpectedString);
                    }
                };
                keccak(string.as_bytes()).to_fixed_bytes().to_vec()
            }
            TypeRef::BytesN(n) => {
                let n = *n;
                if !(1..=32).contains(&n) {
                    return Err(TypedDataHashError::BytesLength(n));
                }
                let mut bytes = match self {
                    Value::Bytes(bytes) => Some(bytes.to_vec()),
                    Value::String(string) => bytes_from_hex(string),
                    _ => None,
                }
                .ok_or(TypedDataHashError::ExpectedBytes)?;
                let len = bytes.len();
                if len != n {
                    return Err(TypedDataHashError::ExpectedBytesLength(n, len));
                }
                if len < 32 {
                    bytes.resize(32, 0);
                }
                bytes
            }
            TypeRef::UintN(n) => {
                let n = *n;
                if n % 8 != 0 {
                    return Err(TypedDataHashError::TypeNotByteAligned("uint", n));
                }
                if !(8..=256).contains(&n) {
                    return Err(TypedDataHashError::IntegerLength(n));
                }
                let int = self
                    .as_bytes()?
                    .ok_or(TypedDataHashError::ExpectedInteger)?;
                let len = int.len();
                if len > 32 {
                    return Err(TypedDataHashError::IntegerTooLong(len));
                }
                if len == 32 {
                    return Ok(int);
                }
                // Left-pad to 256 bits
                [EMPTY_32[0..(32 - len)].to_vec(), int].concat()
            }
            TypeRef::IntN(n) => {
                let n = *n;
                if n % 8 != 0 {
                    return Err(TypedDataHashError::TypeNotByteAligned("int", n));
                }
                if !(8..=256).contains(&n) {
                    return Err(TypedDataHashError::IntegerLength(n));
                }
                let int = self
                    .as_bytes()?
                    .ok_or(TypedDataHashError::ExpectedInteger)?;
                let len = int.len();
                if len > 32 {
                    return Err(TypedDataHashError::IntegerTooLong(len));
                }
                if len == 32 {
                    return Ok(int);
                }
                // Left-pad to 256 bits, with sign extension.
                let negative = int[0] & 0x80 == 0x80;
                static PADDING_POS: [u8; 32] = [0; 32];
                static PADDING_NEG: [u8; 32] = [0xff; 32];
                let padding = if negative { PADDING_NEG } else { PADDING_POS };
                [padding[0..(32 - len)].to_vec(), int].concat()
            }
            TypeRef::Bool => {
                let b = self.as_bool().ok_or(TypedDataHashError::ExpectedBoolean)?;
                let mut bytes: [u8; 32] = [0; 32];
                if b {
                    bytes[31] = 1;
                }
                bytes.to_vec()
            }
            TypeRef::Address => {
                let bytes = self.as_bytes()?.ok_or(TypedDataHashError::ExpectedBytes)?;
                if bytes.len() != 20 {
                    return Err(TypedDataHashError::ExpectedAddressLength(bytes.len()));
                }
                static PADDING: [u8; 12] = [0; 12];
                [PADDING.to_vec(), bytes].concat()
            }
            TypeRef::Array(member_type) => {
                // Note: this implementation follows eth-sig-util
                // which diverges from EIP-712 when encoding arrays.
                // Ref: https://github.com/MetaMask/eth-sig-util/issues/106
                let array = match self {
                    Value::Array(array) => array,
                    _ => {
                        return Err(TypedDataHashError::ExpectedArray(
                            member_type.to_string(),
                            self.kind(),
                        ));
                    }
                };
                let mut enc = Vec::with_capacity(32 * array.len());
                for member in array {
                    let mut member_enc = encode_field(member, member_type, types)?;
                    enc.append(&mut member_enc);
                }
                enc
            }
            TypeRef::ArrayN(member_type, n) => {
                let array = match self {
                    Value::Array(array) => array,
                    _ => {
                        return Err(TypedDataHashError::ExpectedArray(
                            member_type.to_string(),
                            self.kind(),
                        ));
                    }
                };
                let n = *n;
                let len = array.len();
                if len != n {
                    return Err(TypedDataHashError::ExpectedArrayLength(n, len));
                }
                let mut enc = Vec::with_capacity(32 * n);
                for member in array {
                    let mut member_enc = encode_field(member, member_type, types)?;
                    enc.append(&mut member_enc);
                }
                enc
            }
            TypeRef::Struct(struct_name) => {
                let struct_type = types.get(struct_name).ok_or_else(|| {
                    TypedDataHashError::MissingReferencedType(struct_name.to_string())
                })?;
                let hash_map = match self {
                    Value::Struct(hash_map) => hash_map,
                    _ => {
                        return Err(TypedDataHashError::ExpectedObject(
                            struct_name.to_string(),
                            self.kind(),
                        ));
                    }
                };
                let mut enc = Vec::with_capacity(32 * (struct_type.member_variables().len() + 1));
                let type_hash = struct_type.hash(struct_name, types)?;
                enc.append(&mut type_hash.to_vec());
                let mut keys: std::collections::HashSet<String> =
                    hash_map.keys().map(|k| k.to_owned()).collect();
                for member in struct_type.member_variables() {
                    let mut member_enc = match hash_map.get(&member.name) {
                        Some(value) => encode_field(value, &member.type_, types)?,
                        // Allow missing member structs
                        None => EMPTY_32.to_vec(),
                    };
                    keys.remove(&member.name);
                    enc.append(&mut member_enc);
                }
                if !keys.is_empty() {
                    // A key was remaining in the data that does not have a type in the struct.
                    let names: Vec<String> = keys.into_iter().collect();
                    return Err(TypedDataHashError::UntypedProperties(names));
                }
                enc
            }
        };
        Ok(bytes)
    }
}

fn encode_field(
    data: &Value,
    type_: &TypeRef,
    types: &Types,
) -> Result<Vec<u8>, TypedDataHashError> {
    let is_struct_or_array = matches!(
        type_,
        TypeRef::Struct(_) | TypeRef::Array(_) | TypeRef::ArrayN(_, _)
    );
    let encoded = data.encode(type_, types)?;
    if is_struct_or_array {
        let hash = keccak(&encoded).to_fixed_bytes().to_vec();
        Ok(hash)
    } else {
        Ok(encoded)
    }
}

impl TypeDefinition {
    /// Encode the type into a byte string using the [EIP-712 `encodeType`
    /// function][1].
    ///
    /// [1]: <https://eips.ethereum.org/EIPS/eip-712#definition-of-encodetype>
    #[allow(clippy::ptr_arg)]
    pub fn encode(
        &self,
        struct_name: &StructName,
        types: &Types,
    ) -> Result<Vec<u8>, TypedDataHashError> {
        let mut string = String::new();
        encode_type_single(struct_name, self, &mut string);
        let mut referenced_types = HashMap::new();
        gather_referenced_struct_types(self, types, &mut referenced_types)?;
        let mut types: Vec<(&String, &TypeDefinition)> = referenced_types.into_iter().collect();
        types.sort_by(|(name1, _), (name2, _)| name1.cmp(name2));
        for (name, type_) in types {
            encode_type_single(name, type_, &mut string);
        }
        Ok(string.into_bytes())
    }
}

fn gather_referenced_struct_types<'a>(
    type_: &'a TypeDefinition,
    types: &'a Types,
    memo: &mut HashMap<&'a String, &'a TypeDefinition>,
) -> Result<(), TypedDataHashError> {
    for member in type_.member_variables() {
        if let Some(struct_name) = member.type_.as_struct_name() {
            use std::collections::hash_map::Entry;
            let entry = memo.entry(struct_name);
            if let Entry::Vacant(o) = entry {
                let referenced_struct = types.get(struct_name).ok_or_else(|| {
                    TypedDataHashError::MissingReferencedType(struct_name.to_string())
                })?;
                o.insert(referenced_struct);
                gather_referenced_struct_types(referenced_struct, types, memo)?;
            }
        }
    }
    Ok(())
}

#[allow(clippy::ptr_arg)]
fn encode_type_single(type_name: &StructName, type_: &TypeDefinition, string: &mut String) {
    string.push_str(type_name);
    string.push('(');
    let mut first = true;
    for member in type_.member_variables() {
        if first {
            first = false;
        } else {
            string.push(',');
        }
        string.push_str(&String::from(member.type_.clone()));
        string.push(' ');
        string.push_str(&member.name);
    }
    string.push(')');
}
