mod context;
mod credential;
mod non_empty_object;
mod non_empty_vec;
mod presentation;
mod types;

use std::collections::BTreeMap;

pub use context::*;
pub use credential::*;
use iref::{Uri, UriBuf};
pub use non_empty_object::*;
pub use non_empty_vec::*;
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
    #[serde(
        default,
        deserialize_with = "not_null",
        skip_serializing_if = "Option::is_none"
    )]
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
    #[serde(
        default,
        deserialize_with = "not_null",
        skip_serializing_if = "Option::is_none"
    )]
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
    use ssi_core::OneOrMany;

    pub fn serialize<T: Serialize, S>(value: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match value.split_first() {
            Some((first, [])) => first.serialize(serializer),
            _ => value.serialize(serializer),
        }
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D>(deserializer: D) -> Result<Vec<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        Ok(OneOrMany::deserialize(deserializer)?.into_vec())
    }
}

pub(crate) mod non_empty_value_or_array {
    use serde::{Deserialize, Serialize};
    use ssi_core::OneOrMany;

    use super::NonEmptyVec;

    pub fn serialize<T: Serialize, S>(value: &[T], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        match value.split_first() {
            Some((first, [])) => first.serialize(serializer),
            _ => value.serialize(serializer),
        }
    }

    pub fn deserialize<'de, T: Deserialize<'de>, D>(
        deserializer: D,
    ) -> Result<NonEmptyVec<T>, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        OneOrMany::deserialize(deserializer)?
            .into_vec()
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

/// Deserialize an `Option::Some`, without accepting `None` (null) as a value.
///
/// Combined with `#[serde(default)]` this allows a field to be either present
/// and not `null`, or absent. But this will raise an error if the field is
/// present but `null`.
pub(crate) fn not_null<'de, T: Deserialize<'de>, D>(deserializer: D) -> Result<Option<T>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    T::deserialize(deserializer).map(Some)
}

#[cfg(test)]
mod tests {
    use super::MaybeIdentifiedObject;
    use serde_json::json;

    #[test]
    fn deserialize_id_not_null_1() {
        assert!(serde_json::from_value::<MaybeIdentifiedObject>(json!({
            "id": null
        }))
        .is_err())
    }

    #[test]
    fn deserialize_id_not_null_2() {
        assert!(serde_json::from_value::<MaybeIdentifiedObject>(json!({})).is_ok())
    }

    #[test]
    fn deserialize_id_not_null_3() {
        assert!(serde_json::from_value::<MaybeIdentifiedObject>(json!({
            "id": "http://example.org/#id"
        }))
        .is_ok())
    }
}
