use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use keccak_hash::keccak;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use thiserror::Error;

use crate::keccak_hash::bytes_to_lowerhex;
use crate::ldp::LinkedDataDocument;
use crate::vc::Proof;

static EMPTY_32: [u8; 32] = [0; 32];

#[derive(Error, Debug)]
pub enum TypedDataParseError {
    #[error("Unexpected null value")]
    UnexpectedNull,
    #[error("Unexpected number: {0:?}")]
    Number(Number),
    #[error("Unable to parse data type size: {0}")]
    SizeParse(#[from] ParseIntError),
}

pub type StructName = String;

/// Structured typed data as described in
/// [Definition of typed structured data 𝕊](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-typed-structured-data-%F0%9D%95%8A)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StructType(Vec<MemberVariable>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberVariable {
    #[serde(rename = "type")]
    pub type_: EIP712Type,
    pub name: String,
}

/// EIP-712 types
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(try_from = "String", into = "String")]
pub enum EIP712Type {
    BytesN(usize),
    UintN(usize),
    IntN(usize),
    Bool,
    Address,
    Bytes,
    String,
    Array(Box<EIP712Type>),
    ArrayN(Box<EIP712Type>, usize),
    Struct(StructName),
}

/// EIP-712 values, JSON-compatible
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "Value", into = "Value")]
pub enum EIP712Value {
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<EIP712Value>),
    Struct(HashMap<StructName, EIP712Value>),
    Bool(bool),
    Integer(i64),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Types {
    #[serde(rename = "EIP712Domain")]
    pub eip712_domain: StructType,
    #[serde(flatten)]
    pub types: HashMap<StructName, StructType>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct TypedData {
    pub types: Types,
    pub primary_type: StructName,
    pub domain: EIP712Value,
    pub message: EIP712Value,
}

#[derive(Error, Debug)]
pub enum TypedDataConstructionError {
    #[error("Unable to convert document to data set: {0}")]
    DocumentToDataset(String),
    #[error("Unable to convert proof to data set: {0}")]
    ProofToDataset(String),
    #[error("Unable to normalize document: {0}")]
    NormalizeDocument(String),
    #[error("Unable to normalize proof: {0}")]
    NormalizeProof(String),
}

#[derive(Error, Debug)]
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
    #[error("Expected array with type '{0}'")]
    ExpectedArray(String),
    #[error("Expected object with type '{0}'")]
    ExpectedObject(String),
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
}

impl EIP712Value {
    fn as_bytes(&self) -> Result<Option<Vec<u8>>, TypedDataHashError> {
        let bytes = match self {
            EIP712Value::Bytes(bytes) => bytes.to_vec(),
            EIP712Value::Integer(int) => int.to_be_bytes().to_vec(),
            EIP712Value::String(string) => {
                bytes_from_hex(&string).ok_or(TypedDataHashError::ExpectedHex)?
            }
            _ => {
                return Err(TypedDataHashError::ExpectedBytes);
            }
        };
        Ok(Some(bytes))
    }

    fn as_bool(&self) -> Option<bool> {
        match self {
            EIP712Value::Bool(b) => Some(*b),
            EIP712Value::String(string) => {
                // JS treats non-empty strings as boolean true.
                // To catch possible mistakes, let's only allow that for
                // a few special cases.
                match &string[..] {
                    "" => Some(false),
                    "true" => Some(true),
                    "1" => Some(true),
                    _ => None,
                }
            }
            EIP712Value::Integer(int) => match int {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            },
            _ => None,
        }
    }
}

impl fmt::Display for EIP712Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EIP712Type::Bytes => write!(f, "bytes"),
            EIP712Type::String => write!(f, "string"),
            EIP712Type::BytesN(n) => write!(f, "bytes{}", n),
            EIP712Type::UintN(n) => write!(f, "uint{}", n),
            EIP712Type::IntN(n) => write!(f, "int{}", n),
            EIP712Type::Bool => write!(f, "bool"),
            EIP712Type::Address => write!(f, "address"),
            EIP712Type::Array(type_) => {
                write!(f, "{}[]", *type_)
            }
            EIP712Type::ArrayN(type_, n) => {
                write!(f, "{}[{}]", *type_, n)
            }
            EIP712Type::Struct(name) => {
                write!(f, "{}", name)
            }
        }
    }
}

impl From<EIP712Type> for String {
    fn from(type_: EIP712Type) -> String {
        match type_ {
            EIP712Type::Struct(name) => name,
            _ => {
                format!("{}", &type_)
            }
        }
    }
}

impl TryFrom<String> for EIP712Type {
    type Error = TypedDataParseError;
    fn try_from(string: String) -> Result<Self, Self::Error> {
        match &string[..] {
            "bytes" => return Ok(EIP712Type::Bytes),
            "string" => return Ok(EIP712Type::String),
            "address" => return Ok(EIP712Type::Address),
            "bool" => return Ok(EIP712Type::Bool),
            _ => {}
        }
        if string.ends_with("]") {
            let mut parts = string.rsplitn(2, "[");
            let amount_str = parts.next().unwrap().split("]").next().unwrap();
            let base = EIP712Type::try_from(parts.next().unwrap().to_string())?;
            if amount_str.len() == 0 {
                return Ok(EIP712Type::Array(Box::new(base)));
            } else {
                return Ok(EIP712Type::ArrayN(
                    Box::new(base),
                    usize::from_str(amount_str)?,
                ));
            }
        } else if string.starts_with("uint") {
            return Ok(EIP712Type::UintN(usize::from_str(&string[4..])?));
        } else if string.starts_with("int") {
            return Ok(EIP712Type::IntN(usize::from_str(&string[3..])?));
        } else if string.starts_with("bytes") {
            return Ok(EIP712Type::BytesN(usize::from_str(&string[5..])?));
        }
        Ok(EIP712Type::Struct(string))
    }
}

impl From<EIP712Value> for Value {
    fn from(value: EIP712Value) -> Value {
        match value {
            EIP712Value::Bool(true) => Value::Bool(true),
            EIP712Value::Bool(false) => Value::Bool(false),
            EIP712Value::Integer(int) => Value::Number(Number::from(int)),
            EIP712Value::Bytes(bytes) => {
                Value::String("0x".to_string() + &bytes_to_lowerhex(&bytes))
            }
            EIP712Value::String(string) => Value::String(string),
            EIP712Value::Array(array) => Value::Array(array.into_iter().map(Value::from).collect()),
            EIP712Value::Struct(hash_map) => Value::Object(
                hash_map
                    .into_iter()
                    .map(|(name, value)| (name, Value::from(value)))
                    .collect(),
            ),
        }
    }
}

impl TryFrom<Value> for EIP712Value {
    type Error = TypedDataParseError;
    fn try_from(value: Value) -> Result<Self, Self::Error> {
        let eip712_value = match value {
            Value::Null => return Err(Self::Error::UnexpectedNull),
            Value::Bool(true) => EIP712Value::Bool(true),
            Value::Bool(false) => EIP712Value::Bool(false),
            Value::String(string) => EIP712Value::String(string),
            Value::Number(number) => {
                if let Some(int) = number.as_i64() {
                    EIP712Value::Integer(int)
                } else {
                    return Err(Self::Error::Number(number));
                }
            }
            Value::Array(array) => EIP712Value::Array(
                array
                    .into_iter()
                    .map(EIP712Value::try_from)
                    .collect::<Result<Vec<Self>, Self::Error>>()?,
            ),
            Value::Object(object) => EIP712Value::Struct(
                object
                    .into_iter()
                    .map(|(name, value)| EIP712Value::try_from(value).map(|v| (name, v)))
                    .collect::<Result<HashMap<StructName, Self>, Self::Error>>()?,
            ),
        };
        Ok(eip712_value)
    }
}

impl Types {
    pub fn get(&self, struct_name: &str) -> Option<&StructType> {
        if struct_name == "EIP712Domain" {
            Some(&self.eip712_domain)
        } else {
            self.types.get(struct_name)
        }
    }
}

/// Hash the result of [`encodeType`]
pub fn hash_type(
    struct_name: &StructName,
    struct_type: &StructType,
    types: &Types,
) -> Result<[u8; 32], TypedDataHashError> {
    let encoded_type = encode_type(struct_name, struct_type, types)?.to_vec();
    let type_hash = keccak(encoded_type).to_fixed_bytes();
    Ok(type_hash)
}

/// [`hashStruct`](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-hashstruct)
pub fn hash_struct(
    data: &EIP712Value,
    struct_name: &StructName,
    types: &Types,
) -> Result<[u8; 32], TypedDataHashError> {
    let encoded_data = encode_data(data, &EIP712Type::Struct(struct_name.clone()), types)?.to_vec();
    Ok(keccak(encoded_data).to_fixed_bytes())
}

/// [`encodeType`](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-encodetype)
pub fn encode_type(
    struct_name: &StructName,
    struct_type: &StructType,
    types: &Types,
) -> Result<Vec<u8>, TypedDataHashError> {
    let mut string = String::new();
    encode_type_single(struct_name, struct_type, &mut string);
    let mut referenced_types = HashMap::new();
    gather_referenced_struct_types(struct_type, types, &mut referenced_types)?;
    let mut types: Vec<(&String, &StructType)> = referenced_types.into_iter().collect();
    types.sort_by(|(name1, _), (name2, _)| name1.cmp(name2));
    for (name, type_) in types {
        encode_type_single(name, type_, &mut string);
    }
    Ok(string.into_bytes())
}

fn encode_type_single(type_name: &StructName, type_: &StructType, string: &mut String) {
    string.push_str(type_name);
    string.push('(');
    let mut first = true;
    for member in &type_.0 {
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

impl EIP712Type {
    /// Return name of struct if this type is a reference to a struct or array of structs
    fn as_struct_name(&self) -> Option<&StructName> {
        match self {
            Self::Struct(name) => Some(name),
            Self::Array(type_box) | Self::ArrayN(type_box, _) => type_box.as_struct_name(),
            _ => None,
        }
    }
}

pub(crate) fn bytes_from_hex(s: &str) -> Option<Vec<u8>> {
    if s.starts_with("0x") {
        hex::decode(&s[2..]).ok()
    } else {
        None
    }
}

fn gather_referenced_struct_types<'a>(
    type_: &'a StructType,
    types: &'a Types,
    memo: &mut HashMap<&'a String, &'a StructType>,
) -> Result<(), TypedDataHashError> {
    for member in &type_.0 {
        if let Some(struct_name) = member.type_.as_struct_name() {
            use std::collections::hash_map::Entry;
            let entry = memo.entry(struct_name);
            if let Entry::Vacant(o) = entry {
                let referenced_struct =
                    types
                        .get(struct_name)
                        .ok_or(TypedDataHashError::MissingReferencedType(
                            struct_name.to_string(),
                        ))?;
                o.insert(referenced_struct);
                gather_referenced_struct_types(referenced_struct, types, memo)?;
            }
        }
    }
    Ok(())
}

fn encode_field(
    data: &EIP712Value,
    type_: &EIP712Type,
    types: &Types,
) -> Result<Vec<u8>, TypedDataHashError> {
    let is_struct_or_array = match type_ {
        EIP712Type::Struct(_) | EIP712Type::Array(_) | EIP712Type::ArrayN(_, _) => true,
        _ => false,
    };
    let encoded = encode_data(&data, type_, types)?;
    if is_struct_or_array {
        let hash = keccak(&encoded).to_fixed_bytes().to_vec();
        return Ok(hash);
    } else {
        return Ok(encoded);
    }
}

/// [`encodeData`](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-encodedata)
pub fn encode_data(
    data: &EIP712Value,
    type_: &EIP712Type,
    types: &Types,
) -> Result<Vec<u8>, TypedDataHashError> {
    let bytes = match type_ {
        EIP712Type::Bytes => {
            let bytes_opt;
            let bytes = match data {
                EIP712Value::Bytes(bytes) => Some(bytes),
                EIP712Value::String(string) => {
                    bytes_opt = bytes_from_hex(&string);
                    bytes_opt.as_ref()
                }
                _ => None,
            }
            .ok_or(TypedDataHashError::ExpectedBytes)?;
            keccak(bytes).to_fixed_bytes().to_vec()
        }
        EIP712Type::String => {
            let string = match data {
                EIP712Value::String(string) => string,
                _ => {
                    return Err(TypedDataHashError::ExpectedString);
                }
            };
            keccak(string.as_bytes()).to_fixed_bytes().to_vec()
        }
        EIP712Type::BytesN(n) => {
            let n = *n;
            if n < 1 || n > 32 {
                return Err(TypedDataHashError::BytesLength(n));
            }
            let mut bytes = match data {
                EIP712Value::Bytes(bytes) => Some(bytes.to_vec()),
                EIP712Value::String(string) => bytes_from_hex(&string),
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
        EIP712Type::UintN(n) => {
            let n = *n;
            if n % 8 != 0 {
                return Err(TypedDataHashError::TypeNotByteAligned("uint", n));
            }
            if n < 8 || n > 256 {
                return Err(TypedDataHashError::IntegerLength(n));
            }
            let int = data
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
            let padded = vec![EMPTY_32[0..(32 - len)].to_vec(), int].concat();
            padded
        }
        EIP712Type::IntN(n) => {
            let n = *n;
            if n % 8 != 0 {
                return Err(TypedDataHashError::TypeNotByteAligned("int", n));
            }
            if n < 8 || n > 256 {
                return Err(TypedDataHashError::IntegerLength(n));
            }
            let int = data
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
            let padded = vec![padding[0..(32 - len)].to_vec(), int].concat();
            padded
        }
        EIP712Type::Bool => {
            let b = data.as_bool().ok_or(TypedDataHashError::ExpectedBoolean)?;
            let mut bytes: [u8; 32] = [0; 32];
            if b {
                bytes[31] = 1;
            }
            bytes.to_vec()
        }
        EIP712Type::Address => {
            let bytes = data.as_bytes()?.ok_or(TypedDataHashError::ExpectedBytes)?;
            if bytes.len() != 20 {
                return Err(TypedDataHashError::ExpectedAddressLength(bytes.len()));
            }
            static PADDING: [u8; 12] = [0; 12];
            let padded = vec![PADDING.to_vec(), bytes].concat();
            padded
        }
        EIP712Type::Array(member_type) => {
            // Note: this implementation follows eth-sig-util
            // which diverges from EIP-712 when encoding arrays.
            // Ref: https://github.com/MetaMask/eth-sig-util/issues/106
            let array = match data {
                EIP712Value::Array(array) => array,
                _ => {
                    return Err(TypedDataHashError::ExpectedArray(member_type.to_string()));
                }
            };
            let mut enc = Vec::with_capacity(32 * array.len());
            for member in array {
                let mut member_enc = encode_field(&member, member_type, types)?;
                enc.append(&mut member_enc);
            }
            enc
        }
        EIP712Type::ArrayN(member_type, n) => {
            let array = match data {
                EIP712Value::Array(array) => array,
                _ => {
                    return Err(TypedDataHashError::ExpectedArray(member_type.to_string()));
                }
            };
            let n = *n;
            let len = array.len();
            if len != n {
                return Err(TypedDataHashError::ExpectedArrayLength(n, len));
            }
            let mut enc = Vec::with_capacity(32 * n);
            for member in array {
                let mut member_enc = encode_field(&member, member_type, types)?;
                enc.append(&mut member_enc);
            }
            enc
        }
        EIP712Type::Struct(struct_name) => {
            let struct_type =
                types
                    .get(struct_name)
                    .ok_or(TypedDataHashError::MissingReferencedType(
                        struct_name.to_string(),
                    ))?;
            let hash_map = match data {
                EIP712Value::Struct(hash_map) => hash_map,
                _ => {
                    return Err(TypedDataHashError::ExpectedObject(struct_name.to_string()));
                }
            };
            let mut enc = Vec::with_capacity(32 * (struct_type.0.len() + 1));
            let type_hash = hash_type(&struct_name, &struct_type, types)?;
            enc.append(&mut type_hash.to_vec());
            for member in &struct_type.0 {
                let mut member_enc = match hash_map.get(&member.name) {
                    Some(value) => encode_field(value, &member.type_, types)?,
                    // Allow missing member structs
                    None => EMPTY_32.to_vec(),
                };
                enc.append(&mut member_enc);
            }
            enc
        }
    };
    Ok(bytes)
}

impl TypedData {
    pub async fn from_document_and_options(
        document: &(dyn LinkedDataDocument + Sync),
        proof: &Proof,
    ) -> Result<Self, TypedDataConstructionError> {
        let doc_dataset = document
            .to_dataset_for_signing(None)
            .await
            .map_err(|e| TypedDataConstructionError::DocumentToDataset(e.to_string()))?;
        let doc_dataset_normalized = crate::urdna2015::normalize(&doc_dataset)
            .map_err(|e| TypedDataConstructionError::NormalizeDocument(e.to_string()))?;
        let sigopts_dataset = proof
            .to_dataset_for_signing(Some(document))
            .await
            .map_err(|e| TypedDataConstructionError::ProofToDataset(e.to_string()))?;
        let sigopts_dataset_normalized = crate::urdna2015::normalize(&sigopts_dataset)
            .map_err(|e| TypedDataConstructionError::NormalizeProof(e.to_string()))?;

        let types = Types {
            eip712_domain: StructType(vec![MemberVariable {
                name: "name".to_string(),
                type_: EIP712Type::String,
            }]),
            types: vec![(
                "LDPSigningRequest".to_string(),
                StructType(vec![
                    MemberVariable {
                        name: "document".to_string(),
                        type_: EIP712Type::Array(Box::new(EIP712Type::Array(Box::new(
                            EIP712Type::String,
                        )))),
                    },
                    MemberVariable {
                        name: "proof".to_string(),
                        type_: EIP712Type::Array(Box::new(EIP712Type::Array(Box::new(
                            EIP712Type::String,
                        )))),
                    },
                ]),
            )]
            .into_iter()
            .collect(),
        };
        use crate::rdf::Statement;
        fn encode_statement(statement: Statement) -> EIP712Value {
            let mut terms = vec![
                EIP712Value::String(String::from(&statement.subject)),
                EIP712Value::String(String::from(&statement.predicate)),
                EIP712Value::String(String::from(&statement.object)),
            ];
            if let Some(graph_label) = statement.graph_label.as_ref() {
                terms.push(EIP712Value::String(String::from(graph_label)));
            }
            EIP712Value::Array(terms)
        }

        let typed_data = Self {
            types,
            primary_type: "LDPSigningRequest".to_string(),
            domain: EIP712Value::Struct(
                vec![(
                    "name".to_string(),
                    EIP712Value::String("Eip712Method2021".to_string()),
                )]
                .into_iter()
                .collect(),
            ),
            message: EIP712Value::Struct(
                vec![
                    (
                        "document".to_string(),
                        EIP712Value::Array(
                            doc_dataset_normalized
                                .statements()
                                .into_iter()
                                .map(encode_statement)
                                .collect(),
                        ),
                    ),
                    (
                        "proof".to_string(),
                        EIP712Value::Array(
                            sigopts_dataset_normalized
                                .statements()
                                .into_iter()
                                .map(encode_statement)
                                .collect(),
                        ),
                    ),
                ]
                .into_iter()
                .collect::<HashMap<StructName, EIP712Value>>(),
            ),
        };
        Ok(typed_data)
    }

    /// Encode a typed data message for hashing and signing.
    /// [Reference](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#specification)
    pub fn hash(&self) -> Result<Vec<u8>, TypedDataHashError> {
        let message_hash = hash_struct(&self.message, &self.primary_type, &self.types)?;
        let domain_separator =
            hash_struct(&self.domain, &StructName::from("EIP712Domain"), &self.types)?;

        let bytes = vec![
            vec![0x19, 0x01],
            domain_separator.to_vec(),
            message_hash.to_vec(),
        ]
        .concat();
        let hash = keccak(bytes).to_fixed_bytes().to_vec();
        Ok(hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_encode_type() {
        let types = Types {
            eip712_domain: StructType(Vec::new()),
            types: vec![
                (
                    "Transaction".to_string(),
                    StructType(vec![
                        MemberVariable {
                            name: "from".to_string(),
                            type_: EIP712Type::Struct("Person".to_string()),
                        },
                        MemberVariable {
                            name: "to".to_string(),
                            type_: EIP712Type::Struct("Person".to_string()),
                        },
                        MemberVariable {
                            name: "tx".to_string(),
                            type_: EIP712Type::Struct("Asset".to_string()),
                        },
                    ]),
                ),
                (
                    "Person".to_string(),
                    StructType(vec![
                        MemberVariable {
                            name: "wallet".to_string(),
                            type_: EIP712Type::Address,
                        },
                        MemberVariable {
                            name: "name".to_string(),
                            type_: EIP712Type::String,
                        },
                    ]),
                ),
                (
                    "Asset".to_string(),
                    StructType(vec![
                        MemberVariable {
                            name: "token".to_string(),
                            type_: EIP712Type::Address,
                        },
                        MemberVariable {
                            name: "amount".to_string(),
                            type_: EIP712Type::UintN(256),
                        },
                    ]),
                ),
            ]
            .into_iter()
            .collect(),
        };
        let type_encoded = encode_type(
            &StructName::from("Transaction"),
            types.get("Transaction").unwrap(),
            &types,
        )
        .unwrap();
        let type_encoded_string = String::from_utf8(type_encoded).unwrap();
        assert_eq!(type_encoded_string, "Transaction(Person from,Person to,Asset tx)Asset(address token,uint256 amount)Person(address wallet,string name)");
    }

    #[test]
    // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#example
    // https://github.com/ethereum/EIPs/blob/master/assets/eip-712/Example.js
    fn hash_typed_data() {
        let _addr = "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826";
        let typed_data: TypedData = serde_json::from_value(json!({
          "types": {
            "EIP712Domain": [
              { "name": "name", "type": "string" },
              { "name": "version", "type": "string" },
              { "name": "chainId", "type": "uint256" },
              { "name": "verifyingContract", "type": "address" }
            ],
            "Person": [
              { "name": "name", "type": "string" },
              { "name": "wallet", "type": "address" }
            ],
            "Mail": [
              { "name": "from", "type": "Person" },
              { "name": "to", "type": "Person" },
              { "name": "contents", "type": "string" }
            ]
          },
          "primaryType": "Mail",
          "domain": {
            "name": "Ether Mail",
            "version": "1",
            "chainId": 1,
            "verifyingContract": "0xCcCCccccCCCCcCCCCCCcCcCccCcCCCcCcccccccC"
          },
          "message": {
            "from": {
              "name": "Cow",
              "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
            },
            "to": {
              "name": "Bob",
              "wallet": "0xbBbBBBBbbBBBbbbBbbBbbbbBBbBbbbbBbBbbBBbB"
            },
            "contents": "Hello, Bob!"
          }
        }))
        .unwrap();

        // Hash Type
        let struct_type = typed_data.types.get("Mail").unwrap();
        let type_encoded = encode_type(&"Mail".to_string(), struct_type, &typed_data.types)
            .unwrap()
            .to_vec();
        let type_hash = keccak(&type_encoded).to_fixed_bytes().to_vec();
        let type_encoded_string = String::from_utf8(type_encoded).unwrap();
        assert_eq!(
            type_encoded_string,
            "Mail(Person from,Person to,string contents)Person(string name,address wallet)"
        );
        assert_eq!(
            bytes_to_lowerhex(&type_hash),
            "0xa0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2"
        );

        // Hash struct
        let data: EIP712Value = serde_json::from_value(json!({
          "name": "Cow",
          "wallet": "0xCD2a3d9F938E13CD947Ec05AbC7FE734Df8DD826"
        }))
        .unwrap();
        let data_encoded = encode_data(
            &data,
            &EIP712Type::Struct("Person".to_string()),
            &typed_data.types,
        )
        .unwrap();
        assert_eq!(
            bytes_to_lowerhex(&data_encoded),
            "0xb9d8c78acf9b987311de6c7b45bb6a9c8e1bf361fa7fd3467a2163f994c795008c1d2bd5348394761719da11ec67eedae9502d137e8940fee8ecd6f641ee1648000000000000000000000000cd2a3d9f938e13cd947ec05abc7fe734df8dd826"
        );

        // Encode message
        let data_encoded = encode_data(
            &typed_data.message,
            &EIP712Type::Struct(typed_data.primary_type.clone()),
            &typed_data.types,
        )
        .unwrap();
        assert_eq!(
            bytes_to_lowerhex(&data_encoded),
            "0xa0cedeb2dc280ba39b857546d74f5549c3a1d7bdc2dd96bf881f76108e23dac2fc71e5fa27ff56c350aa531bc129ebdf613b772b6604664f5d8dbe21b85eb0c8cd54f074a4af31b4411ff6a60c9719dbd559c221c8ac3492d9d872b041d703d1b5aadf3154a261abdd9086fc627b61efca26ae5702701d05cd2305f7c52a2fc8"
        );

        // Hash message
        let data_hashed = hash_struct(
            &typed_data.message,
            &typed_data.primary_type,
            &typed_data.types,
        )
        .unwrap();
        assert_eq!(
            bytes_to_lowerhex(&data_hashed),
            "0xc52c0ee5d84264471806290a3f2c4cecfc5490626bf912d01f240d7a274b371e"
        );

        let hash = typed_data.hash().unwrap();
        let hash_hex = bytes_to_lowerhex(&hash);
        assert_eq!(
            hash_hex,
            "0xbe609aee343fb3c4b28e1df9e632fca64fcfaede20f02e86244efddf30957bd2"
        );

        // Test more types
        let typed_data: TypedData = serde_json::from_value(json!({
            "types": {
                "EIP712Domain": [
                    { "type": "string", "name": "name" }
                ],
                "Message": [
                    { "name": "bytes8", "type": "bytes8" },
                    { "name": "bytes32", "type": "bytes32" },
                    { "name": "uint8", "type": "uint8" },
                    { "name": "uint32", "type": "uint32" },
                    { "name": "uint256", "type": "uint256" },
                    { "name": "int8", "type": "int8" },
                    { "name": "int16", "type": "int16" },
                    { "name": "true", "type": "bool" },
                    { "name": "empty", "type": "Empty[1]" },
                    { "name": "missing", "type": "Empty" },
                    { "name": "bitmatrix", "type": "bool[2][2]" }
                ],
                "Empty": [
                ]
            },
            "primaryType": "Message",
            "domain": {
                "name": "Test"
            },
            "message": {
                "bytes8": "0x0102030405060708",
                "bytes32": "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f10",
                "uint8": "0x03",
                "uint32": 0x01020304,
                "uint256": "0x0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f10",
                "int8": -5,
                "int16": 5,
                "true": true,
                "empty": [{
                }],
                "bitmatrix": [
                    [true, false],
                    [false, true]
                ]
            }
        }
        ))
        .unwrap();
        let hash = typed_data.hash().unwrap();
        assert_eq!(
            bytes_to_lowerhex(&hash),
            "0x3128ae562d7141585a21f9c04e87520857ae9025d5c57293255f25d72f869b2e"
        );
    }
}
