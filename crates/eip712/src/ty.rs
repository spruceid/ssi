use std::{collections::BTreeMap, fmt, num::ParseIntError, str::FromStr};

use iref::Uri;
use serde::{Deserialize, Serialize};

use crate::Value;

pub type StructName = String;

/// Errors that can occur while fetching remote EIP712 type definitions.
#[derive(Debug, thiserror::Error)]
pub enum TypesFetchError {
    /// Error for applications that do not support remote types.
    ///
    /// This is the error always returned by the `()` implementation of
    /// `TypesProvider`.
    #[error("remote EIP712 types are not supported")]
    Unsupported,
}

/// Type providing remote EIP712 type definitions from an URI.
///
/// A default implementation is provided for the `()` type that always return
/// `TypesFetchError::Unsupported`.
pub trait TypesLoader {
    /// Fetches the type definitions located behind the given `uri`.
    ///
    /// This is an asynchronous function returning a `Self::Fetch` future that
    /// resolves into ether the EIP712 [`Types`] or an error
    /// of type `TypesFetchError`.
    #[allow(async_fn_in_trait)]
    async fn fetch_types(&self, uri: &Uri) -> Result<Types, TypesFetchError>;
}

/// Simple EIP712 loader implementation that always return
/// `TypesFetchError::Unsupported`.
impl TypesLoader for () {
    async fn fetch_types(&self, _uri: &Uri) -> Result<Types, TypesFetchError> {
        Err(TypesFetchError::Unsupported)
    }
}

impl<'a, T: TypesLoader> TypesLoader for &'a T {
    async fn fetch_types(&self, uri: &Uri) -> Result<Types, TypesFetchError> {
        T::fetch_types(*self, uri).await
    }
}

pub trait Eip712TypesLoaderProvider {
    type Loader: TypesLoader;

    fn eip712_types(&self) -> &Self::Loader;
}

impl<'a, E: Eip712TypesLoaderProvider> Eip712TypesLoaderProvider for &'a E {
    type Loader = E::Loader;

    fn eip712_types(&self) -> &Self::Loader {
        E::eip712_types(*self)
    }
}

/// EIP-712 types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(untagged)]
#[serde(try_from = "String", into = "String")]
pub enum TypeRef {
    BytesN(usize),
    UintN(usize),
    IntN(usize),
    Bool,
    Address,
    Bytes,
    String,
    Array(Box<TypeRef>),
    ArrayN(Box<TypeRef>, usize),
    Struct(StructName),
}

impl TypeRef {
    /// Return name of struct if this type is a reference to a struct or array of structs
    pub fn as_struct_name(&self) -> Option<&StructName> {
        match self {
            Self::Struct(name) => Some(name),
            Self::Array(type_box) | Self::ArrayN(type_box, _) => type_box.as_struct_name(),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum TypeParseError {
    #[error("Unmatched bracket")]
    UnmatchedBracket,
    #[error("Unable to parse data type size: {0}")]
    SizeParse(#[from] ParseIntError),
}

impl FromStr for TypeRef {
    type Err = TypeParseError;

    fn from_str(string: &str) -> Result<Self, Self::Err> {
        match string {
            "bytes" => return Ok(TypeRef::Bytes),
            "string" => return Ok(TypeRef::String),
            "address" => return Ok(TypeRef::Address),
            "bool" => return Ok(TypeRef::Bool),
            _ => {}
        }

        if string.ends_with(']') {
            let mut parts = string.rsplitn(2, '[');
            let amount_str = parts.next().unwrap().split(']').next().unwrap();
            let inner = parts.next().ok_or(TypeParseError::UnmatchedBracket)?;
            let base = inner.parse()?;
            if amount_str.is_empty() {
                return Ok(TypeRef::Array(Box::new(base)));
            } else {
                return Ok(TypeRef::ArrayN(
                    Box::new(base),
                    usize::from_str(amount_str)?,
                ));
            }
        } else if let Some(suffix) = string.strip_prefix("uint") {
            return Ok(TypeRef::UintN(usize::from_str(suffix)?));
        } else if let Some(suffix) = string.strip_prefix("int") {
            return Ok(TypeRef::IntN(usize::from_str(suffix)?));
        } else if let Some(suffix) = string.strip_prefix("bytes") {
            return Ok(TypeRef::BytesN(usize::from_str(suffix)?));
        }

        Ok(TypeRef::Struct(string.to_owned()))
    }
}

impl TryFrom<String> for TypeRef {
    type Error = TypeParseError;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl fmt::Display for TypeRef {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TypeRef::Bytes => write!(f, "bytes"),
            TypeRef::String => write!(f, "string"),
            TypeRef::BytesN(n) => write!(f, "bytes{}", n),
            TypeRef::UintN(n) => write!(f, "uint{}", n),
            TypeRef::IntN(n) => write!(f, "int{}", n),
            TypeRef::Bool => write!(f, "bool"),
            TypeRef::Address => write!(f, "address"),
            TypeRef::Array(type_) => {
                write!(f, "{}[]", *type_)
            }
            TypeRef::ArrayN(type_, n) => {
                write!(f, "{}[{}]", *type_, n)
            }
            TypeRef::Struct(name) => {
                write!(f, "{}", name)
            }
        }
    }
}

impl From<TypeRef> for String {
    fn from(type_: TypeRef) -> String {
        match type_ {
            TypeRef::Struct(name) => name,
            _ => {
                format!("{}", &type_)
            }
        }
    }
}

/// Structured typed data as described in
/// [Definition of typed structured data 𝕊](https://github.com/ethereum/EIPs/blob/master/EIPS/eip-712.md#definition-of-typed-structured-data-%F0%9D%95%8A)
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TypeDefinition(Vec<MemberVariable>);

impl TypeDefinition {
    pub fn new(member_variables: Vec<MemberVariable>) -> Self {
        Self(member_variables)
    }

    pub fn member_variables(&self) -> &[MemberVariable] {
        &self.0
    }

    pub fn push(&mut self, m: MemberVariable) {
        self.0.push(m)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MemberVariable {
    pub name: String,

    #[serde(rename = "type")]
    pub type_: TypeRef,
}

impl MemberVariable {
    pub fn new(name: String, type_: TypeRef) -> Self {
        Self { name, type_ }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Types {
    #[serde(rename = "EIP712Domain")]
    pub eip712_domain: TypeDefinition,

    #[serde(flatten)]
    pub types: BTreeMap<StructName, TypeDefinition>,
}

impl Types {
    pub fn get(&self, struct_name: &str) -> Option<&TypeDefinition> {
        if struct_name == "EIP712Domain" {
            Some(&self.eip712_domain)
        } else {
            self.types.get(struct_name)
        }
    }

    /// Generate EIP-712 types from a value.
    ///
    /// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#types-generation>
    pub fn generate(
        doc: &Value,
        primary_type: StructName,
        domain_type: TypeDefinition,
    ) -> Result<Self, TypesGenerationError> {
        Ok(Self {
            eip712_domain: domain_type,
            types: Self::generate_inner(doc, primary_type)?,
        })
    }

    /// Generate EIP-712 types from a value, without the toplevel `EIP712Domain` type.
    ///
    /// See: <https://w3c-ccg.github.io/ethereum-eip712-signature-2021-spec/#types-generation>
    fn generate_inner(
        doc: &Value,
        primary_type: StructName,
    ) -> Result<BTreeMap<StructName, TypeDefinition>, TypesGenerationError> {
        // 1
        let mut output = BTreeMap::default();
        // 2
        // TypedDataField == MemberVariable
        let mut types = TypeDefinition::default();
        // 4
        // Done already.
        // 3
        // Using JCS here probably has no effect:
        // https://github.com/davidpdrsn/assert-json-diff
        let doc_jcs = serde_jcs::to_string(doc).map_err(TypesGenerationError::JCS)?;
        let doc: Value = serde_json::from_str(&doc_jcs).map_err(TypesGenerationError::JCS)?;
        // 5
        let object = doc
            .as_struct()
            .ok_or(TypesGenerationError::ExpectedObject)?;
        let mut props: Vec<(&String, &Value)> = object.iter().collect();
        // Iterate through object properties in the order JCS would sort them.
        // https://datatracker.ietf.org/doc/html/rfc8785#section-3.2.3
        props.sort_by_cached_key(|(name, _value)| name.encode_utf16().collect::<Vec<u16>>());
        for (property_name, value) in props {
            match value {
                // 6
                Value::Bool(_) => {
                    // 6.1
                    types.push(MemberVariable {
                        type_: TypeRef::Bool,
                        name: String::from(property_name),
                    });
                }
                Value::Integer(_) => {
                    // 6.2
                    types.push(MemberVariable {
                        type_: TypeRef::UintN(256),
                        name: String::from(property_name),
                    });
                }
                Value::String(_) => {
                    // 6.3
                    types.push(MemberVariable {
                        type_: TypeRef::String,
                        name: String::from(property_name),
                    });
                }
                // 7
                Value::Array(array) => {
                    // Ensure values have same primitive type.
                    let mut values = array.iter();
                    let first_value = values
                        .next()
                        .ok_or_else(|| TypesGenerationError::EmptyArray(property_name.clone()))?;
                    match first_value {
                        Value::Bool(_) => {
                            // 7.1
                            for value in values {
                                if !matches!(value, Value::Bool(_)) {
                                    return Err(TypesGenerationError::ArrayInconsistency(
                                        "boolean",
                                        property_name.clone(),
                                    ));
                                }
                            }
                            types.push(MemberVariable {
                                type_: TypeRef::Array(Box::new(TypeRef::Bool)),
                                name: String::from(property_name),
                            });
                        }
                        Value::Integer(_) => {
                            // 7.2
                            for value in values {
                                if !matches!(value, Value::Integer(_)) {
                                    return Err(TypesGenerationError::ArrayInconsistency(
                                        "number",
                                        property_name.clone(),
                                    ));
                                }
                            }
                            types.push(MemberVariable {
                                type_: TypeRef::Array(Box::new(TypeRef::UintN(256))),
                                name: String::from(property_name),
                            });
                        }
                        Value::String(_) => {
                            // 7.3
                            for value in values {
                                if !matches!(value, Value::String(_)) {
                                    return Err(TypesGenerationError::ArrayInconsistency(
                                        "string",
                                        property_name.clone(),
                                    ));
                                }
                            }
                            types.push(MemberVariable {
                                type_: TypeRef::Array(Box::new(TypeRef::String)),
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
                Value::Struct(object) => {
                    // 8
                    let mut recursive_output =
                        Self::generate_inner(&Value::Struct(object.clone()), primary_type.clone())?;
                    // 8.1
                    let recursive_types =
                        recursive_output.remove(&primary_type).ok_or_else(|| {
                            TypesGenerationError::MissingPrimaryTypeInRecursiveOutput(
                                primary_type.clone(),
                            )
                        })?;
                    // 8.2
                    let property_type = property_to_struct_name(property_name);
                    types.push(MemberVariable {
                        name: String::from(property_name),
                        type_: TypeRef::Struct(property_type.clone()),
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
}

#[derive(Debug, thiserror::Error)]
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

fn property_to_struct_name(property_name: &str) -> StructName {
    // CamelCase
    let mut chars = property_name.chars();
    let first_char = chars.next().unwrap_or_default();
    first_char.to_uppercase().chain(chars).collect()
}

#[cfg(test)]
lazy_static::lazy_static! {
    // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/blob/28bd5edecde8395242aea8ba64e9be25f59585d0/index.html#L917-L966
    // https://github.com/w3c-ccg/ethereum-eip712-signature-2021-spec/pull/26/files#r798853853
    pub static ref EXAMPLE_TYPES: serde_json::Value = {
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
