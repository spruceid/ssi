use std::collections::HashMap;
use std::convert::TryFrom;
use std::fmt;
use std::num::ParseIntError;
use std::str::FromStr;

use keccak_hash::keccak;
use rdf_types::QuadRef;
use serde::{Deserialize, Serialize};
use serde_json::{Number, Value};
use thiserror::Error;

use crate::{LinkedDataDocument, Proof};
use ssi_crypto::hashes::keccak::bytes_to_lowerhex;
use ssi_json_ld::{rdf::NQuadsStatement, ContextLoader};

static EMPTY_32: [u8; 32] = [0; 32];

#[derive(Error, Debug)]
pub enum TypedDataParseError {
    #[error("Unexpected null value")]
    UnexpectedNull,
    #[error("Unmatched bracket")]
    UnmatchedBracket,
    #[error("Unexpected number: {0:?}")]
    Number(Number),
    #[error("Unable to parse data type size: {0}")]
    SizeParse(#[from] ParseIntError),
}

pub type StructName = String;

/// Structured typed data as described in
/// [Definition of typed structured data 𝕊](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-typed-structured-data-%F0%9D%95%8A)
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StructType(Vec<MemberVariable>);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemberVariable {
    #[serde(rename = "type")]
    pub type_: EIP712Type,
    pub name: String,
}

/// EIP-712 types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
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
    // Note: implicit EIP712Domain is not standard EIP-712
    #[serde(default = "eip712sig_default_domain")]
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

/// Object containing EIP-712 types, or a URI for such.
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum TypesOrURI {
    URI(String),
    Object(Types),
}

/// Object at eip712 (formerly eip712Domain) property of [Ethereum EIP712 Signature 2021](https://uport-project.github.io/ethereum-eip712-signature-2021-spec/#ethereum-eip712-signature-2021) proof object
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(deny_unknown_fields)]
pub struct ProofInfo {
    // Allow messageSchema for backwards-compatibility since
    // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
    #[serde(rename = "types", alias = "messageSchema")]
    pub types_or_uri: TypesOrURI,
    pub primary_type: StructName,
    pub domain: EIP712Value,
}

#[derive(Error, Debug)]
pub enum TypedDataConstructionError {
    #[error("Unable to convert document to data set: {0}")]
    DocumentToDataset(String),
    #[error("Unable to convert proof to data set: {0}")]
    ProofToDataset(String),
}

#[derive(Error, Debug)]
pub enum TypedDataConstructionJSONError {
    #[error("Not Implemented")]
    NotImplemented,
    #[error("Unable to convert document to JSON: {0}")]
    DocumentToJSON(String),
    #[error("Unable to convert proof object to JSON: {0}")]
    ProofToJSON(String),
    #[error("Expected document to be a JSON object")]
    ExpectedDocumentObject,
    #[error("Expected proof to be a JSON object")]
    ExpectedProofObject,
    #[error("Expected types in proof.eip712")]
    ExpectedTypes,
    #[error("Unable to parse eip712: {0}")]
    ParseInfo(serde_json::Error),
    #[error("Unable to convert document to EIP-712 message: {0}")]
    ConvertMessage(TypedDataParseError),
    #[error("Unable to dereference EIP-712 types: {0}")]
    DereferenceTypes(DereferenceTypesError),
    #[error("Unable to generate EIP-712 types and proof info: {0}")]
    GenerateProofInfo(#[from] ProofGenerationError),
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
    #[error("Untyped properties: {0:?}")]
    UntypedProperties(Vec<String>),
}

#[derive(Error, Debug)]
pub enum DereferenceTypesError {
    #[error("Remote types loading not implemented")]
    RemoteLoadingNotImplemented,
    #[error("Unable to convert types from JSON: {0}")]
    JSON(serde_json::Error),
}

impl EIP712Value {
    fn as_bytes(&self) -> Result<Option<Vec<u8>>, TypedDataHashError> {
        let bytes = match self {
            EIP712Value::Bytes(bytes) => bytes.to_vec(),
            EIP712Value::Integer(int) => int.to_be_bytes().to_vec(),
            EIP712Value::String(string) => {
                bytes_from_hex(string).ok_or(TypedDataHashError::ExpectedHex)?
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

    fn as_struct(&self) -> Option<&HashMap<StructName, EIP712Value>> {
        match self {
            EIP712Value::Struct(map) => Some(map),
            _ => None,
        }
    }
}

impl fmt::Display for EIP712Type {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EIP712Type::Bytes => write!(f, "bytes"),
            EIP712Type::String => write!(f, "string"),
            EIP712Type::BytesN(n) => write!(f, "bytes{n}"),
            EIP712Type::UintN(n) => write!(f, "uint{n}"),
            EIP712Type::IntN(n) => write!(f, "int{n}"),
            EIP712Type::Bool => write!(f, "bool"),
            EIP712Type::Address => write!(f, "address"),
            EIP712Type::Array(type_) => {
                write!(f, "{}[]", *type_)
            }
            EIP712Type::ArrayN(type_, n) => {
                write!(f, "{}[{n}]", *type_)
            }
            EIP712Type::Struct(name) => {
                write!(f, "{name}")
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
        if string.ends_with(']') {
            let mut parts = string.rsplitn(2, '[');
            let amount_str = parts.next().unwrap().split(']').next().unwrap();
            let inner = parts.next().ok_or(TypedDataParseError::UnmatchedBracket)?;
            let base = EIP712Type::try_from(inner.to_string())?;
            if amount_str.is_empty() {
                return Ok(EIP712Type::Array(Box::new(base)));
            } else {
                return Ok(EIP712Type::ArrayN(
                    Box::new(base),
                    usize::from_str(amount_str)?,
                ));
            }
        } else if let Some(suffix) = string.strip_prefix("uint") {
            return Ok(EIP712Type::UintN(usize::from_str(suffix)?));
        } else if let Some(suffix) = string.strip_prefix("int") {
            return Ok(EIP712Type::IntN(usize::from_str(suffix)?));
        } else if let Some(suffix) = string.strip_prefix("bytes") {
            return Ok(EIP712Type::BytesN(usize::from_str(suffix)?));
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

impl TypesOrURI {
    #[allow(clippy::match_single_binding)]
    #[allow(unreachable_code)]
    #[allow(unused_variables)]
    async fn dereference(self) -> Result<Types, DereferenceTypesError> {
        let uri = match self {
            Self::URI(string) => string,
            Self::Object(types) => return Ok(types),
        };
        let value = match &uri[..] {
            #[cfg(test)]
            "https://example.org/types.json" => tests::EXAMPLE_TYPES.clone(),
            _ => return Err(DereferenceTypesError::RemoteLoadingNotImplemented),
        };
        let types: Types = serde_json::from_value(value).map_err(DereferenceTypesError::JSON)?;
        Ok(types)
    }
}

fn property_to_struct_name(property_name: &str) -> StructName {
    // CamelCase
    let mut chars = property_name.chars();
    let first_char = chars.next().unwrap_or_default();
    first_char.to_uppercase().chain(chars).collect()
}

/// Hash the result of [`encodeType`]
#[allow(clippy::ptr_arg)]
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
#[allow(clippy::ptr_arg)]
pub fn hash_struct(
    data: &EIP712Value,
    struct_name: &StructName,
    types: &Types,
) -> Result<[u8; 32], TypedDataHashError> {
    let encoded_data = encode_data(data, &EIP712Type::Struct(struct_name.clone()), types)?.to_vec();
    Ok(keccak(encoded_data).to_fixed_bytes())
}

/// [`encodeType`](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-encodetype)
#[allow(clippy::ptr_arg)]
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

#[allow(clippy::ptr_arg)]
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
    s.strip_prefix("0x")
        .and_then(|hex_str| hex::decode(hex_str).ok())
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

fn encode_field(
    data: &EIP712Value,
    type_: &EIP712Type,
    types: &Types,
) -> Result<Vec<u8>, TypedDataHashError> {
    let is_struct_or_array = matches!(
        type_,
        EIP712Type::Struct(_) | EIP712Type::Array(_) | EIP712Type::ArrayN(_, _)
    );
    let encoded = encode_data(data, type_, types)?;
    if is_struct_or_array {
        let hash = keccak(&encoded).to_fixed_bytes().to_vec();
        Ok(hash)
    } else {
        Ok(encoded)
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
                    bytes_opt = bytes_from_hex(string);
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
            if !(1..=32).contains(&n) {
                return Err(TypedDataHashError::BytesLength(n));
            }
            let mut bytes = match data {
                EIP712Value::Bytes(bytes) => Some(bytes.to_vec()),
                EIP712Value::String(string) => bytes_from_hex(string),
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
            if !(8..=256).contains(&n) {
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
            vec![EMPTY_32[0..(32 - len)].to_vec(), int].concat()
        }
        EIP712Type::IntN(n) => {
            let n = *n;
            if n % 8 != 0 {
                return Err(TypedDataHashError::TypeNotByteAligned("int", n));
            }
            if !(8..=256).contains(&n) {
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
            vec![padding[0..(32 - len)].to_vec(), int].concat()
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
            vec![PADDING.to_vec(), bytes].concat()
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
                let mut member_enc = encode_field(member, member_type, types)?;
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
                let mut member_enc = encode_field(member, member_type, types)?;
                enc.append(&mut member_enc);
            }
            enc
        }
        EIP712Type::Struct(struct_name) => {
            let struct_type = types.get(struct_name).ok_or_else(|| {
                TypedDataHashError::MissingReferencedType(struct_name.to_string())
            })?;
            let hash_map = match data {
                EIP712Value::Struct(hash_map) => hash_map,
                _ => {
                    return Err(TypedDataHashError::ExpectedObject(struct_name.to_string()));
                }
            };
            let mut enc = Vec::with_capacity(32 * (struct_type.0.len() + 1));
            let type_hash = hash_type(struct_name, struct_type, types)?;
            enc.append(&mut type_hash.to_vec());
            let mut keys: std::collections::HashSet<String> =
                hash_map.keys().map(|k| k.to_owned()).collect();
            for member in &struct_type.0 {
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

fn eip712sig_default_domain() -> StructType {
    StructType(vec![MemberVariable {
        name: String::from("name"),
        type_: EIP712Type::String,
    }])
}

impl TypedData {
    pub async fn from_document_and_options(
        document: &(dyn LinkedDataDocument + Sync),
        proof: &Proof,
        context_loader: &mut ContextLoader,
    ) -> Result<Self, TypedDataConstructionError> {
        let doc_dataset = document
            .to_dataset_for_signing(None, context_loader)
            .await
            .map_err(|e| TypedDataConstructionError::DocumentToDataset(e.to_string()))?;
        let doc_dataset_normalized =
            crate::urdna2015::normalize(doc_dataset.quads().map(QuadRef::from));
        let mut doc_statements_normalized: Vec<_> = doc_dataset_normalized.collect();
        #[allow(clippy::redundant_closure)]
        doc_statements_normalized.sort_by_cached_key(|x| NQuadsStatement(x).to_string());
        let sigopts_dataset = proof
            .to_dataset_for_signing(Some(document), context_loader)
            .await
            .map_err(|e| TypedDataConstructionError::ProofToDataset(e.to_string()))?;
        let sigopts_dataset_normalized =
            crate::urdna2015::normalize(sigopts_dataset.quads().map(QuadRef::from));
        let mut sigopts_statements_normalized: Vec<_> = sigopts_dataset_normalized.collect();
        #[allow(clippy::redundant_closure)]
        sigopts_statements_normalized.sort_by_cached_key(|x| NQuadsStatement(x).to_string());

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

        fn encode_statement(rdf_types::Quad(s, p, o, g): rdf_types::Quad) -> EIP712Value {
            use rdf_types::RdfDisplay;

            let mut terms = vec![
                EIP712Value::String(s.rdf_display().to_string()),
                EIP712Value::String(p.rdf_display().to_string()),
                EIP712Value::String(o.rdf_display().to_string()),
            ];
            if let Some(graph_label) = g {
                terms.push(EIP712Value::String(graph_label.rdf_display().to_string()));
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
                            doc_statements_normalized
                                .into_iter()
                                .map(encode_statement)
                                .collect(),
                        ),
                    ),
                    (
                        "proof".to_string(),
                        EIP712Value::Array(
                            sigopts_statements_normalized
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

    /// Convert linked data document and proof to TypedData according to
    /// [EthereumEip712Signature2021](https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/)
    pub async fn from_document_and_options_json(
        document: &(dyn LinkedDataDocument + Sync),
        proof: &Proof,
    ) -> Result<Self, TypedDataConstructionJSONError> {
        let mut doc_value = document
            .to_value()
            .map_err(|e| TypedDataConstructionJSONError::DocumentToJSON(e.to_string()))?;
        let doc_obj = doc_value
            .as_object_mut()
            .ok_or(TypedDataConstructionJSONError::ExpectedDocumentObject)?;
        let mut proof_value = serde_json::to_value(proof)
            .map_err(|e| TypedDataConstructionJSONError::ProofToJSON(e.to_string()))?;
        let proof_obj = proof_value
            .as_object_mut()
            .ok_or(TypedDataConstructionJSONError::ExpectedProofObject)?;
        proof_obj.remove("proofValue");
        let info = proof_obj
            .remove("eip712")
            // Allow eip712Domain for backwards-compatibility since
            // changed in https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/32
            .or_else(|| proof_obj.remove("eip712Domain"));
        doc_obj.insert("proof".to_string(), proof_value);
        let message = EIP712Value::try_from(doc_value)
            .map_err(TypedDataConstructionJSONError::ConvertMessage)?;
        let proof_info: ProofInfo = match info {
            Some(info) => {
                serde_json::from_value(info).map_err(TypedDataConstructionJSONError::ParseInfo)?
            }
            None => generate_proof_info(&message)?,
        };
        let ProofInfo {
            types_or_uri,
            primary_type,
            domain,
        } = proof_info;
        let types = types_or_uri
            .dereference()
            .await
            .map_err(TypedDataConstructionJSONError::DereferenceTypes)?;
        let typed_data = Self {
            types,
            primary_type,
            domain,
            message,
        };
        Ok(typed_data)
    }

    /// Encode a typed data message for hashing and signing.
    /// [Reference](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#specification)
    pub fn hash(&self) -> Result<Vec<u8>, TypedDataHashError> {
        let bytes = self.bytes()?;
        let hash = keccak(bytes).to_fixed_bytes().to_vec();
        Ok(hash)
    }

    pub fn bytes(&self) -> Result<Vec<u8>, TypedDataHashError> {
        let message_hash = hash_struct(&self.message, &self.primary_type, &self.types)?;
        let domain_separator =
            hash_struct(&self.domain, &StructName::from("EIP712Domain"), &self.types)?;

        let bytes = vec![
            vec![0x19, 0x01],
            domain_separator.to_vec(),
            message_hash.to_vec(),
        ]
        .concat();
        Ok(bytes)
    }
}

#[derive(Error, Debug)]
pub enum TypesGenerationError {
    #[error("Expected object")]
    ExpectedObject,
    #[error("Found empty array under property: {0}")]
    EmptyArray(String),
    #[error("Array inconsistency: expected type {0} under property: {1}")]
    ArrayInconsistency(&'static str, String),
    #[error("Array value must be boolean, number or string. Property: {0}")]
    ComplexArrayValue(String),
    #[error("Value must be boolean, number, string, array or struct. Property: {0}")]
    ComplexValue(String),
    #[error("Missing primaryType in recursive output. primaryType: {0}")]
    MissingPrimaryTypeInRecursiveOutput(String),
    #[error("JCS: {0}")]
    JCS(serde_json::Error),
    #[error("Proof type already exists")]
    ProofAlreadyExists,
}

/// Generate EIP-712 types for EthereumEip712Signature2021
///
/// <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#types-generation>
/// from <https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/25>
pub fn generate_types(
    doc: &EIP712Value,
    primary_type: Option<StructName>,
) -> Result<HashMap<StructName, StructType>, TypesGenerationError> {
    // 1
    let mut output = HashMap::default();
    // 2
    // TypedDataField == MemberVariable
    let mut types = StructType::default();
    // 3
    // Using JCS here probably has no effect:
    // https://github.com/davidpdrsn/assert-json-diff
    let doc_jcs = serde_jcs::to_string(doc).map_err(TypesGenerationError::JCS)?;
    let doc: EIP712Value = serde_json::from_str(&doc_jcs).map_err(TypesGenerationError::JCS)?;
    // 4
    let primary_type = primary_type.unwrap_or_else(|| StructName::from("Document"));
    // 5
    let object = doc
        .as_struct()
        .ok_or(TypesGenerationError::ExpectedObject)?;
    let mut props: Vec<(&String, &EIP712Value)> = object.iter().collect();
    // Iterate through object properties in the order JCS would sort them.
    // https://datatracker.ietf.org/doc/html/rfc8785#section-3.2.3
    props.sort_by_cached_key(|(name, _value)| name.encode_utf16().collect::<Vec<u16>>());
    for (property_name, value) in props {
        match value {
            // 6
            EIP712Value::Bool(_) => {
                // 6.1
                types.0.push(MemberVariable {
                    type_: EIP712Type::Bool,
                    name: String::from(property_name),
                });
            }
            EIP712Value::Integer(_) => {
                // 6.2
                types.0.push(MemberVariable {
                    type_: EIP712Type::UintN(256),
                    name: String::from(property_name),
                });
            }
            EIP712Value::String(_) => {
                // 6.3
                types.0.push(MemberVariable {
                    type_: EIP712Type::String,
                    name: String::from(property_name),
                });
            }
            // 7
            EIP712Value::Array(array) => {
                // Ensure values have same primitive type.
                let mut values = array.iter();
                let first_value = values
                    .next()
                    .ok_or_else(|| TypesGenerationError::EmptyArray(property_name.clone()))?;
                match first_value {
                    EIP712Value::Bool(_) => {
                        // 7.1
                        for value in values {
                            if !matches!(value, EIP712Value::Bool(_)) {
                                return Err(TypesGenerationError::ArrayInconsistency(
                                    "boolean",
                                    property_name.clone(),
                                ));
                            }
                        }
                        types.0.push(MemberVariable {
                            type_: EIP712Type::Array(Box::new(EIP712Type::Bool)),
                            name: String::from(property_name),
                        });
                    }
                    EIP712Value::Integer(_) => {
                        // 7.2
                        for value in values {
                            if !matches!(value, EIP712Value::Integer(_)) {
                                return Err(TypesGenerationError::ArrayInconsistency(
                                    "number",
                                    property_name.clone(),
                                ));
                            }
                        }
                        types.0.push(MemberVariable {
                            type_: EIP712Type::Array(Box::new(EIP712Type::UintN(256))),
                            name: String::from(property_name),
                        });
                    }
                    EIP712Value::String(_) => {
                        // 7.3
                        for value in values {
                            if !matches!(value, EIP712Value::String(_)) {
                                return Err(TypesGenerationError::ArrayInconsistency(
                                    "string",
                                    property_name.clone(),
                                ));
                            }
                        }
                        types.0.push(MemberVariable {
                            type_: EIP712Type::Array(Box::new(EIP712Type::String)),
                            name: String::from(property_name),
                        });
                    }
                    _ => {
                        return Err(TypesGenerationError::ComplexArrayValue(
                            property_name.clone(),
                        ));
                    }
                }
            }
            EIP712Value::Struct(object) => {
                // 8
                let mut recursive_output = generate_types(
                    &EIP712Value::Struct(object.clone()),
                    Some(primary_type.clone()),
                )?;
                // 8.1
                let recursive_types = recursive_output.remove(&primary_type).ok_or_else(|| {
                    TypesGenerationError::MissingPrimaryTypeInRecursiveOutput(primary_type.clone())
                })?;
                // 8.2
                let property_type = property_to_struct_name(property_name);
                types.0.push(MemberVariable {
                    name: String::from(property_name),
                    type_: EIP712Type::Struct(property_type.clone()),
                });
                // 8.3
                output.insert(property_type, recursive_types);
                // 8.4
                for (prop, type_) in recursive_output.into_iter() {
                    output.insert(prop, type_);
                }
            }
            _ => {
                return Err(TypesGenerationError::ComplexValue(property_name.clone()));
            }
        }
    }
    // 9
    output.insert(primary_type, types);
    Ok(output)
}

/// Generate types as in [generate_types], but with assumed proof properties.
pub fn generate_types_with_proof(
    doc: &EIP712Value,
    primary_type: Option<StructName>,
) -> Result<HashMap<StructName, StructType>, TypesGenerationError> {
    let mut map = if let EIP712Value::Struct(ref map) = doc {
        map.clone()
    } else {
        return Err(TypesGenerationError::ExpectedObject);
    };
    if map.get("proof").is_some() {
        return Err(TypesGenerationError::ProofAlreadyExists);
    }
    // Put dummy data in proof object so that types for it can be generated.
    // Note: @context is not added.
    map.insert(
        "proof".to_string(),
        EIP712Value::Struct(
            vec![
                (
                    "type".to_string(),
                    EIP712Value::String("ExampleSignatureType".to_string()),
                ),
                (
                    "created".to_string(),
                    EIP712Value::String("2022-02-03T19:18:58Z".to_string()),
                ),
                (
                    "proofPurpose".to_string(),
                    EIP712Value::String("assertionMethod".to_string()),
                ),
                (
                    "verificationMethod".to_string(),
                    EIP712Value::String("did:example:eip712sig".to_string()),
                ),
            ]
            .into_iter()
            .collect(),
        ),
    );
    generate_types(&EIP712Value::Struct(map), primary_type)
}

#[derive(Error, Debug)]
pub enum ProofGenerationError {
    #[error("Unable to generate types: {0}")]
    TypesGeneration(#[from] TypesGenerationError),
}

// Generate eip712Domain proof property, using [generate_types].
pub fn generate_proof_info(doc: &EIP712Value) -> Result<ProofInfo, ProofGenerationError> {
    // Default primaryType to Document for consistency with generate_types.
    let primary_type = StructName::from("Document");
    let types = generate_types(doc, Some(primary_type.clone()))?;
    let domain = EIP712Value::Struct(HashMap::default());
    let eip712_domain = eip712sig_default_domain();
    Ok(ProofInfo {
        types_or_uri: TypesOrURI::Object(Types {
            eip712_domain,
            types,
        }),
        primary_type,
        domain,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lazy_static::lazy_static;
    use serde_json::json;

    #[test]
    fn test_parse_type() {
        let string_type = EIP712Type::try_from(String::from("string")).unwrap();
        assert_eq!(string_type, EIP712Type::String);

        let string_array_type = EIP712Type::try_from(String::from("string[]")).unwrap();
        let string_array_type_expected = EIP712Type::Array(Box::new(EIP712Type::String));
        assert_eq!(string_array_type, string_array_type_expected);

        EIP712Type::try_from(String::from("string]")).unwrap_err();
    }

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

    lazy_static! {
            // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L637-L645
            static ref TEST_BASIC_DOCUMENT: Value = {
                json!({
                    "@context": ["https://schema.org", "https://w3id.org/security/v2"],
                    "@type": "Person",
                    "firstName": "Jane",
                    "lastName": "Does",
                    "jobTitle": "Professor",
                    "telephone": "(425) 123-4567",
                    "email": "jane.doe@example.com"
                })
            };
            // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L646-L660
            static ref TEST_NESTED_DOCUMENT: Value = {
                json!({
                    "@context": ["https://schema.org", "https://w3id.org/security/v2"],
                    "@type": "Person",
                    "data": {
                      "name": {
                        "firstName": "John",
                        "lastName": "Doe"
                      },
                      "job": {
                        "jobTitle": "Professor",
                        "employer": "University of Waterloo"
                      }
                    },
                    "telephone": "(425) 123-4567"
                })
            };

            static ref MOCK_ETHR_DID_RESOLVER: MockEthrDIDResolver =
                MockEthrDIDResolver {
                    doc: serde_json::from_value(json!({
                      "@context": [
                        "https://www.w3.org/ns/did/v1",
                        {
                          "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
                          "blockchainAccountId": "https://w3id.org/security#blockchainAccountId"
                        }
                      ],
                      "id": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443",
                      "verificationMethod": [{
                          "id": "#blockchainAccountId",
                          "type": "EcdsaSecp256k1RecoveryMethod2020",
                          "controller": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443",
                          "blockchainAccountId": "eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443"
                      }],
                      "assertionMethod": [
                          "#blockchainAccountId"
                      ]
                    })).unwrap()
                };

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L917-L966
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/26/files#r798853853
        pub static ref EXAMPLE_TYPES: Value = {
            serde_json::json!({
              "Data": [
                {
                  "name": "job",
                  "type": "Job"
                },
                {
                  "name": "name",
                  "type": "Name"
                }
              ],
              "Job": [
                {
                  "name": "employer",
                  "type": "string"
                },
                {
                  "name": "jobTitle",
                  "type": "string"
                }
              ],
              "Name": [
                {
                  "name": "firstName",
                  "type": "string"
                },
                {
                  "name": "lastName",
                  "type": "string"
                }
              ],
              "Document": [
                {
                  "name": "@context",
                  "type": "string[]"
                },
                {
                  "name": "@type",
                  "type": "string"
                },
                {
                  "name": "data",
                  "type": "Data"
                },
                {
                  "name": "proof",
                  "type": "Proof"
                },
                {
                  "name": "telephone",
                  "type": "string"
                }
              ],
              "Proof": [
                {
                  "name": "created",
                  "type": "string"
                },
                {
                  "name": "proofPurpose",
                  "type": "string"
                },
                {
                  "name": "type",
                  "type": "string"
                },
                {
                  "name": "verificationMethod",
                  "type": "string"
                }
              ]
            })
        };
    }

    #[test]
    fn test_property_sorting() {
        // https://datatracker.ietf.org/doc/html/rfc8785#section-3.2.3
        let object: EIP712Value = serde_json::from_str(
            r#"{
           "\u20ac": "Euro Sign",
           "\r": "Carriage Return",
           "\ufb33": "Hebrew Letter Dalet With Dagesh",
           "1": "One",
           "\ud83d\ude00": "Emoji: Grinning Face",
           "\u0080": "Control",
           "\u00f6": "Latin Small Letter O With Diaeresis"
        }"#,
        )
        .unwrap();
        let mut props: Vec<(&String, &EIP712Value)> = object.as_struct().unwrap().iter().collect();
        props.sort_by_cached_key(|(name, _value)| name.encode_utf16().collect::<Vec<u16>>());
        let expected_values = vec![
            "Carriage Return",
            "One",
            "Control",
            "Latin Small Letter O With Diaeresis",
            "Euro Sign",
            "Emoji: Grinning Face",
            "Hebrew Letter Dalet With Dagesh",
        ];
        let values: Vec<String> = props
            .iter()
            .map(|(_name_, value)| Value::from((*value).clone()).as_str().unwrap().to_string())
            .collect();
        assert_eq!(values, expected_values);
    }

    #[test]
    fn test_types_generation() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/25
        // #example-1
        let doc: EIP712Value = serde_json::from_value(json!({
          "@context": ["https://schema.org", "https://w3id.org/security/v2"],
          "@type": "Person",
          "name": {
            "first": "Jane",
            "last": "Doe",
          },
          "otherData": {
            "jobTitle": "Professor",
            "school": "University of ExampleLand",
          },
          "telephone": "(425) 123-4567",
          "email": "jane.doe@example.com",
        }))
        .unwrap();

        // #example-2
        let expected_types: HashMap<StructName, StructType> = serde_json::from_value(json!({
            "Name": [
              { "name": "first", "type": "string" },
              { "name": "last", "type": "string" },
            ],
            "OtherData": [
              { "name": "jobTitle", "type": "string" },
              { "name": "school", "type": "string" },
            ],
            "Document": [
              { "name": "@context", "type": "string[]" },
              { "name": "@type", "type": "string" },
              { "name": "email", "type": "string" },
              { "name": "name", "type": "Name" },
              { "name": "otherData", "type": "OtherData" },
              { "name": "telephone", "type": "string" },
            ]
        }))
        .unwrap();
        let types = generate_types(&doc, None).unwrap();
        eprintln!("types: {}", serde_json::to_string_pretty(&types).unwrap());
        let types_value = serde_json::to_value(types).unwrap();
        let expected_types_value = serde_json::to_value(expected_types).unwrap();
        assert_eq!(types_value, expected_types_value);

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/26
        let test_basic_document: EIP712Value =
            serde_json::from_value(TEST_BASIC_DOCUMENT.clone()).unwrap();
        let types = generate_types(&test_basic_document, None).unwrap();
        eprintln!("types: {}", serde_json::to_string_pretty(&types).unwrap());
        let types_value = serde_json::to_value(types).unwrap();
        let expected_types_value: Value = json!({
              "Document": [
                {
                  "name": "@context",
                  "type": "string[]"
                },
                {
                  "name": "@type",
                  "type": "string"
                },
                {
                  "name": "email",
                  "type": "string"
                },
                {
                  "name": "firstName",
                  "type": "string"
                },
                {
                  "name": "jobTitle",
                  "type": "string"
                },
                {
                  "name": "lastName",
                  "type": "string"
                },
                {
                  "name": "telephone",
                  "type": "string"
                }
              ]
        });
        assert_eq!(types_value, expected_types_value);
    }

    use async_trait::async_trait;
    use ssi_dids::did_resolve::{
        DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_NOT_FOUND,
    };
    use ssi_dids::Document;

    use crate::{DataSet, LinkedDataProofOptions};
    use ssi_core::uri::URI;
    use ssi_dids::VerificationRelationship as ProofPurpose;

    #[async_std::test]
    async fn eip712sig_keypair() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/4f1a089c109c32e29725254accfc375588736c39/index.html#L480-L483
        let addr = "0xaed7ea8035eec47e657b34ef5d020c7005487443";
        let sk_hex = "0x149195a4059ac8cafe2d56fc612f613b6b18b9265a73143c9f6d7cfbbed76b7e";
        let sk_bytes = bytes_from_hex(sk_hex).unwrap();
        use ssi_jwk::{Base64urlUInt, ECParams, Params, JWK};

        let sk = k256::SecretKey::from_bytes(sk_bytes.as_slice().into()).unwrap();
        let pk = sk.public_key();
        let mut ec_params = ECParams::try_from(&pk).unwrap();
        ec_params.ecc_private_key = Some(Base64urlUInt(sk_bytes.to_vec()));
        let jwk = JWK::from(Params::EC(ec_params));
        let hash = ssi_jwk::eip155::hash_public_key(&jwk).unwrap();
        assert_eq!(hash, addr);
    }

    #[derive(Debug, Clone, Serialize, Deserialize)]
    struct InputOptions {
        #[serde(skip_serializing_if = "Option::is_none")]
        types: Option<HashMap<StructName, StructType>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        domain: Option<EIP712Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        date: Option<chrono::DateTime<chrono::Utc>>,
        #[serde(skip_serializing_if = "Option::is_none")]
        #[serde(rename = "embed")]
        embed: Option<bool>,
        #[serde(rename = "embedAsURI")]
        #[serde(skip_serializing_if = "Option::is_none")]
        embed_as_uri: Option<bool>,
    }
    impl From<InputOptions> for LinkedDataProofOptions {
        fn from(input_options: InputOptions) -> LinkedDataProofOptions {
            LinkedDataProofOptions {
                created: input_options.date,
                verification_method: Some(URI::String(
                    "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443".to_string(),
                )),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                ..Default::default()
            }
        }
    }

    struct ExampleDocument(Value);
    #[async_trait]
    impl LinkedDataDocument for ExampleDocument {
        fn get_contexts(&self) -> Result<Option<String>, crate::error::Error> {
            Ok(None)
        }
        async fn to_dataset_for_signing(
            &self,
            _parent: Option<&(dyn LinkedDataDocument + Sync)>,
            _context_loader: &mut ContextLoader,
        ) -> Result<DataSet, crate::error::Error> {
            todo!();
        }

        fn to_value(&self) -> Result<Value, crate::error::Error> {
            Ok(self.0.clone())
        }
    }

    #[derive(Debug, Clone)]
    pub struct MockEthrDIDResolver {
        doc: Document,
    }
    #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
    #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
    impl DIDResolver for MockEthrDIDResolver {
        async fn resolve(
            &self,
            did: &str,
            _input_metadata: &ResolutionInputMetadata,
        ) -> (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ) {
            let doc: Document = match did {
                "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443" => self.doc.clone(),
                _ => return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None),
            };
            (
                ResolutionMetadata::default(),
                Some(doc),
                Some(DocumentMetadata::default()),
            )
        }
    }

    // 3.6. Test Vectors
    // https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#test-vectors
    // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/26

    /// 3.6.1. Basic Document - Types Generation - No Embedding
    /// #basic-document-types-generation-no-embedding
    #[async_std::test]
    #[ignore] // FIXME
    async fn eip712sig_types_generation_no_embedding() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L673-L679
        let input_options: InputOptions = serde_json::from_value(json!({
          "date": "2021-08-30T13:28:02Z",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
          "domain": {
            "name": "Test"
          }
        }))
        .unwrap();
        let _ldp_options = LinkedDataProofOptions::from(input_options);

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L685-L691
        let proof: Proof = serde_json::from_value(json!({
            "created": "2021-08-30T13:28:02Z",
            "proofPurpose": "assertionMethod",
            "proofValue": "0xbbdf2914c7572185bbc263e066dfb43f3136e4441fddb3fe3ea4541bbf7fd1f00d8e5af3ce4fbb1f2ebd5256f39b22cef7f285189df2976ea0c385c77f0a42791b",
            "type": "EthereumEip712Signature2021",
            "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
        }))
        .unwrap();

        let basic_doc = ExampleDocument(TEST_BASIC_DOCUMENT.clone());
        let resolver = MOCK_ETHR_DID_RESOLVER.clone();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let verification_result = proof
            .verify(&basic_doc, &resolver, &mut context_loader, None, None)
            .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }

    #[async_std::test]
    /// 3.6.2. Nested Document - TypedData Provided - Embedded EIP712 Properties
    /// #nested-document-typeddata-provided-embedded-types
    async fn eip712sig_typeddata_provided_embedded_eip712_properties() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L703-L782
        let input_options: InputOptions = serde_json::from_value(json!({
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
          "types": {
            "Data": [
              {
                "name": "job",
                "type": "Job"
              },
              {
                "name": "name",
                "type": "Name"
              }
            ],
            "Document": [
              {
                "name": "@context",
                "type": "string[]"
              },
              {
                "name": "@type",
                "type": "string"
              },
              {
                "name": "data",
                "type": "Data"
              },
              {
                "name": "telephone",
                "type": "string"
              },
              {
                "name": "proof",
                "type": "Proof"
              }
            ],
            "Job": [
              {
                "name": "employer",
                "type": "string"
              },
              {
                "name": "jobTitle",
                "type": "string"
              }
            ],
            "Proof": [
              {
                "name": "created",
                "type": "string"
              },
              {
                "name": "proofPurpose",
                "type": "string"
              },
              {
                "name": "type",
                "type": "string"
              },
              {
                "name": "verificationMethod",
                "type": "string"
              }
            ],
            "Name": [
              {
                "name": "firstName",
                "type": "string"
              },
              {
                "name": "lastName",
                "type": "string"
              }
            ]
          },
          "domain": {
            "name": "Test"
          },
          "date": "2021-08-30T13:28:02Z",
          "embed": true
        }))
        .unwrap();
        let _ldp_options = LinkedDataProofOptions::from(input_options);

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L788-L872
        let proof: Proof = serde_json::from_value(json!({
          "created": "2021-08-30T13:28:02Z",
          "eip712": {
            "domain": {
              "name": "Test",
            },
            "primaryType": "Document",
            "types": {
              "Data": [
                {
                  "name": "job",
                  "type": "Job",
                },
                {
                  "name": "name",
                  "type": "Name",
                },
              ],
              "Document": [
                {
                  "name": "@context",
                  "type": "string[]",
                },
                {
                  "name": "@type",
                  "type": "string",
                },
                {
                  "name": "data",
                  "type": "Data",
                },
                {
                  "name": "telephone",
                  "type": "string",
                },
                {
                  "name": "proof",
                  "type": "Proof",
                },
              ],
              "Job": [
                {
                  "name": "employer",
                  "type": "string",
                },
                {
                  "name": "jobTitle",
                  "type": "string",
                },
              ],
              "Name": [
                {
                  "name": "firstName",
                  "type": "string",
                },
                {
                  "name": "lastName",
                  "type": "string",
                },
              ],
              "Proof": [
                {
                  "name": "created",
                  "type": "string",
                },
                {
                  "name": "proofPurpose",
                  "type": "string",
                },
                {
                  "name": "type",
                  "type": "string",
                },
                {
                  "name": "verificationMethod",
                  "type": "string",
                },
              ],
            },
          },
          "proofPurpose": "assertionMethod",
          "proofValue": "0xcf5844be1f1a5c1a083565d492ab4bee93bd0e24a4573bd8ff47331ad225b9d11c4831aade8d071f4abb8c9e266aaaf30612c582c2bc8f082b8788448895fa4a1b",
          "type": "EthereumEip712Signature2021",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
        })).unwrap();

        let nested_doc = ExampleDocument(TEST_NESTED_DOCUMENT.clone());
        let resolver = MOCK_ETHR_DID_RESOLVER.clone();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let verification_result = proof
            .verify(&nested_doc, &resolver, &mut context_loader, None, None)
            .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }

    #[async_std::test]
    /// 3.6.3. Nested Document - Types Generation - TypedData Schema as URI
    /// #nested-document-types-generation-typeddata-schema-as-uri
    async fn eip712sig_typeddata_types_generation_typeddata_schema_as_uri() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L885-L892
        let input_options: InputOptions = serde_json::from_value(json!({
          "embedAsURI": true,
          "date": "2021-08-30T13:28:02Z",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
          "domain": {
            "name": "Test"
          }
        }))
        .unwrap();
        let _ldp_options = LinkedDataProofOptions::from(input_options);

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L898-L911
        let proof: Proof = serde_json::from_value(json!({
          "created": "2021-08-30T13:28:02Z",
          "proofPurpose": "assertionMethod",
          "type": "EthereumEip712Signature2021",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
          "proofValue": "0x8327ad5e4b2426eac7626400c75f000c3e04caf2a863b888988e4e85533880183d4b9cc6870183e55dabfa96b9486624f45ef849bb146257d123f297a2dbf3a11c",
          "eip712": {
            "domain": {
              "name": "Test"
            },
            "types": "https://example.org/types.json",
            "primaryType": "Document"
          }
        })).unwrap();

        let nested_doc = ExampleDocument(TEST_NESTED_DOCUMENT.clone());
        let resolver = MOCK_ETHR_DID_RESOLVER.clone();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let verification_result = proof
            .verify(&nested_doc, &resolver, &mut context_loader, None, None)
            .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // Types generation
        let test_nested_document: EIP712Value =
            serde_json::from_value(TEST_NESTED_DOCUMENT.clone()).unwrap();
        let types = generate_types_with_proof(&test_nested_document, None).unwrap();
        eprintln!("types: {}", serde_json::to_string_pretty(&types).unwrap());
        let types_value = serde_json::to_value(types).unwrap();
        assert_eq!(types_value, *EXAMPLE_TYPES);
    }

    #[async_std::test]
    /// 3.6.4. Nested Document - Types Generation - Types Embedded
    /// #nested-document-types-generation-types-embedded
    async fn eip712sig_typeddata_provided_embedded_types() {
        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L983-L990
        let input_options: InputOptions = serde_json::from_value(json!({
          "date": "2021-08-30T13:28:02Z",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
          "domain": {
            "name": "Test"
          },
          "embed": true
        }))
        .unwrap();
        let _ldp_options = LinkedDataProofOptions::from(input_options);

        // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L996-L1080
        let proof: Proof = serde_json::from_value(json!({
          "created": "2021-08-30T13:28:02Z",
          "eip712": {
            "domain": {
              "name": "EthereumEip712Signature2021",
            },
            "primaryType": "Document",
            "types": {
              "Data": [
                {
                  "name": "job",
                  "type": "Job",
                },
                {
                  "name": "name",
                  "type": "Name",
                },
              ],
              "Document": [
                {
                  "name": "@context",
                  "type": "string[]",
                },
                {
                  "name": "@type",
                  "type": "string",
                },
                {
                  "name": "data",
                  "type": "Data",
                },
                {
                  "name": "proof",
                  "type": "Proof",
                },
                {
                  "name": "telephone",
                  "type": "string",
                },
              ],
              "Job": [
                {
                  "name": "employer",
                  "type": "string",
                },
                {
                  "name": "jobTitle",
                  "type": "string",
                },
              ],
              "Name": [
                {
                  "name": "firstName",
                  "type": "string",
                },
                {
                  "name": "lastName",
                  "type": "string",
                },
              ],
              "Proof": [
                {
                  "name": "created",
                  "type": "string",
                },
                {
                  "name": "proofPurpose",
                  "type": "string",
                },
                {
                  "name": "type",
                  "type": "string",
                },
                {
                  "name": "verificationMethod",
                  "type": "string",
                },
              ],
            },
          },
          "proofPurpose": "assertionMethod",
          "proofValue": "0x7d57ace2be9cc3944aac023f66130935e489bbb1c9b469a4a5b4f16e5c298b57291bc80d52c6f873b11f4bf45c97c6e2506419af7506eaac5374e9ed381fcc5b1b",
          "type": "EthereumEip712Signature2021",
          "verificationMethod": "did:pkh:eip155:1:0xAED7EA8035eEc47E657B34eF5D020c7005487443#blockchainAccountId",
        })).unwrap();

        let nested_doc = ExampleDocument(TEST_NESTED_DOCUMENT.clone());
        let resolver = MOCK_ETHR_DID_RESOLVER.clone();
        let mut context_loader = ssi_json_ld::ContextLoader::default();
        let verification_result = proof
            .verify(&nested_doc, &resolver, &mut context_loader, None, None)
            .await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }
}
