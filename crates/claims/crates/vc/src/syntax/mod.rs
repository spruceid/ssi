mod context;
mod credential;
mod presentation;
mod types;

use std::collections::BTreeMap;

pub use context::*;
pub use credential::*;
use iref::{Uri, UriBuf};
pub use presentation::*;
use serde::{Deserialize, Serialize};
pub use types::*;

use crate::Identified;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
pub enum IdOr<T> {
    Id(UriBuf),
    NotId(T),
}

impl<T: Identified> IdOr<T> {
    pub fn id(&self) -> &Uri {
        match self {
            Self::Id(id) => id,
            Self::NotId(t) => t.id(),
        }
    }
}

impl<T> From<UriBuf> for IdOr<T> {
    fn from(value: UriBuf) -> Self {
        Self::Id(value)
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IdentifiedObject {
    pub id: UriBuf,

    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MaybeIdentifiedObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct IdentifiedTypedObject {
    pub id: UriBuf,

    #[serde(rename = "type", with = "value_or_array")]
    pub types: Vec<String>,

    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct MaybeIdentifiedTypedObject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    #[serde(rename = "type", with = "value_or_array")]
    pub types: Vec<String>,

    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct TypedObject {
    #[serde(rename = "type", with = "value_or_array")]
    pub types: Vec<String>,

    #[serde(flatten)]
    pub extra_properties: BTreeMap<String, json_syntax::Value>,
}

pub(crate) mod value_or_array {
    use serde::{Deserialize, Serialize};

    pub fn serialize<T: Serialize, S>(value: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match value.split_first() {
            Some((first, [])) => first.serialize(serializer),
            _ => value.serialize(serializer),
        }
    }

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum SingleOrArray<T> {
        Array(Vec<T>),
        Single(T),
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        match SingleOrArray::deserialize(deserializer)? {
            SingleOrArray::Array(v) => Ok(v),
            SingleOrArray::Single(t) => Ok(vec![t]),
        }
    }
}
