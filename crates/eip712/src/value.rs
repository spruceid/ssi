use core::fmt;
use indexmap::{Equivalent, IndexMap};
use linked_data::{LinkedData, LinkedDataGraph};
use rdf_types::{Interpretation, Vocabulary};
use serde::{Deserialize, Serialize};
use std::hash::Hash;

use crate::StructName;

mod deserialize;
mod serialize;

pub use serialize::{to_struct, to_value, InvalidValue};

/// EIP-712 structure instance.
#[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(transparent)]
pub struct Struct(IndexMap<String, Value>);

impl Struct {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self(IndexMap::with_capacity(cap))
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn get(&self, key: &(impl ?Sized + Hash + Equivalent<String>)) -> Option<&Value> {
        self.0.get(key)
    }

    pub fn get_mut(
        &mut self,
        key: &(impl ?Sized + Hash + Equivalent<String>),
    ) -> Option<&mut Value> {
        self.0.get_mut(key)
    }

    pub fn iter(&self) -> indexmap::map::Iter<String, Value> {
        self.0.iter()
    }

    pub fn keys(&self) -> indexmap::map::Keys<String, Value> {
        self.0.keys()
    }

    pub fn insert(&mut self, name: String, value: Value) -> Option<Value> {
        self.0.insert(name, value)
    }
}

impl IntoIterator for Struct {
    type IntoIter = indexmap::map::IntoIter<String, Value>;
    type Item = (String, Value);

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<'a> IntoIterator for &'a Struct {
    type IntoIter = indexmap::map::Iter<'a, String, Value>;
    type Item = (&'a String, &'a Value);

    fn into_iter(self) -> Self::IntoIter {
        self.0.iter()
    }
}

impl FromIterator<(StructName, Value)> for Struct {
    fn from_iter<T: IntoIterator<Item = (String, Value)>>(iter: T) -> Self {
        Self(IndexMap::from_iter(iter))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ValueKind {
    String,
    Bytes,
    Array,
    Struct,
    Bool,
    Integer,
}

impl ValueKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::String => "string",
            Self::Bytes => "bytes",
            Self::Array => "array",
            Self::Struct => "struct",
            Self::Bool => "bool",
            Self::Integer => "integer",
        }
    }

    pub fn into_str(self) -> &'static str {
        self.as_str()
    }
}

impl fmt::Display for ValueKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

/// EIP-712 values, JSON-compatible
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Value {
    String(String),
    Bytes(Vec<u8>),
    Array(Vec<Value>),
    Struct(Struct),
    Bool(bool),
    Integer(i64),
}

impl Value {
    pub fn kind(&self) -> ValueKind {
        match self {
            Self::String(_) => ValueKind::String,
            Self::Bytes(_) => ValueKind::Bytes,
            Self::Array(_) => ValueKind::Array,
            Self::Struct(_) => ValueKind::Struct,
            Self::Bool(_) => ValueKind::Bool,
            Self::Integer(_) => ValueKind::Integer,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            Value::String(string) => {
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
            Value::Integer(int) => match int {
                0 => Some(false),
                1 => Some(true),
                _ => None,
            },
            _ => None,
        }
    }

    pub fn as_struct(&self) -> Option<&Struct> {
        match self {
            Value::Struct(map) => Some(map),
            _ => None,
        }
    }

    pub fn as_struct_mut(&mut self) -> Option<&mut Struct> {
        match self {
            Value::Struct(map) => Some(map),
            _ => None,
        }
    }
}

impl From<Value> for serde_json::Value {
    fn from(value: Value) -> serde_json::Value {
        match value {
            Value::Bool(true) => serde_json::Value::Bool(true),
            Value::Bool(false) => serde_json::Value::Bool(false),
            Value::Integer(int) => serde_json::Value::Number(serde_json::Number::from(int)),
            Value::Bytes(bytes) => {
                serde_json::Value::String("0x".to_string() + &hex::encode(bytes))
            }
            Value::String(string) => serde_json::Value::String(string),
            Value::Array(array) => {
                serde_json::Value::Array(array.into_iter().map(serde_json::Value::from).collect())
            }
            Value::Struct(hash_map) => serde_json::Value::Object(
                hash_map
                    .into_iter()
                    .map(|(name, value)| (name, serde_json::Value::from(value)))
                    .collect(),
            ),
        }
    }
}

linked_data::json_literal!(Value);

impl<V: Vocabulary, I: Interpretation> LinkedDataGraph<I, V> for Value {
    fn visit_graph<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::GraphVisitor<I, V>,
    {
        visitor.subject(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedData<I, V> for Value {
    fn visit<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::Visitor<I, V>,
    {
        visitor.default_graph(self)?;
        visitor.end()
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromJsonError {
    #[error("Unexpected null value")]
    UnexpectedNull,
    #[error("Unexpected number: {0:?}")]
    Number(serde_json::Number),
}

impl TryFrom<serde_json::Value> for Value {
    type Error = FromJsonError;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        let eip712_value = match value {
            serde_json::Value::Null => return Err(Self::Error::UnexpectedNull),
            serde_json::Value::Bool(true) => Value::Bool(true),
            serde_json::Value::Bool(false) => Value::Bool(false),
            serde_json::Value::String(string) => Value::String(string),
            serde_json::Value::Number(number) => {
                if let Some(int) = number.as_i64() {
                    Value::Integer(int)
                } else {
                    return Err(Self::Error::Number(number));
                }
            }
            serde_json::Value::Array(array) => Value::Array(
                array
                    .into_iter()
                    .map(Value::try_from)
                    .collect::<Result<Vec<Self>, Self::Error>>()?,
            ),
            serde_json::Value::Object(object) => Value::Struct(
                object
                    .into_iter()
                    .map(|(name, value)| Value::try_from(value).map(|v| (name, v)))
                    .collect::<Result<Struct, Self::Error>>()?,
            ),
        };

        Ok(eip712_value)
    }
}
