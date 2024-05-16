//! Syntaxes for the VC data model.
mod context;
pub mod json;
mod jwt;

pub use context::*;
pub use json::{JsonCredential, JsonPresentation, SpecializedJsonCredential};
pub use jwt::*;

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
