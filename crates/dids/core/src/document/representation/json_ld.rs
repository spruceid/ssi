use serde::{ser::SerializeSeq, Deserialize, Serialize};
use std::{ops::Deref, str::FromStr};

pub use ssi_json_ld::syntax::{context, ContextEntry};

use crate::Document;

/// DID document represented as a JSON document.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsonLd<D = Document> {
    #[serde(rename = "@context")]
    context: Context,

    #[serde(flatten)]
    document: D,
}

impl<D> JsonLd<D> {
    pub fn new(document: D, options: Options) -> Self {
        Self {
            context: options.context,
            document,
        }
    }

    pub fn document(&self) -> &D {
        &self.document
    }

    pub fn into_document(self) -> D {
        self.document
    }
}

impl<D: Serialize> JsonLd<D> {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self).unwrap()
    }
}

impl JsonLd {
    /// Construct a DID document from JSON bytes.
    pub fn from_bytes(json: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(json)
    }
}

impl FromStr for JsonLd {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl<D> Deref for JsonLd<D> {
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.document
    }
}

#[derive(Debug, Default)]
pub struct Options {
    pub context: Context,
}

pub struct InvalidContextValue;

/// DID JSON-LD context reference.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub enum DIDContext {
    /// Legacy context.
    #[serde(rename = "https://w3id.org/did/v0.11")]
    V0_11,

    /// Default context.
    #[serde(
        rename = "https://www.w3.org/ns/did/v1",
        alias = "https://w3.org/ns/did/v1",
        alias = "https://w3id.org/did/v1"
    )]
    #[default]
    V1,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Context {
    DID(DIDContext),
    Array(ContextArray),
}

impl Context {
    pub fn array(did_context: DIDContext, additional_contexts: Vec<ContextEntry>) -> Self {
        Self::Array(ContextArray(did_context, additional_contexts))
    }
}

impl Default for Context {
    fn default() -> Self {
        Self::DID(DIDContext::default())
    }
}

#[derive(Debug, Clone, Default)]
pub struct ContextArray(DIDContext, Vec<ContextEntry>);

impl Serialize for ContextArray {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(1 + self.1.len()))?;

        seq.serialize_element(&self.0)?;
        for item in &self.1 {
            seq.serialize_element(item)?;
        }

        seq.end()
    }
}

impl<'de> Deserialize<'de> for ContextArray {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = ContextArray;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "a JSON-LD context array")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                match seq.next_element::<DIDContext>()? {
                    Some(did_v1) => {
                        let mut rest = Vec::new();

                        while let Some(item) = seq.next_element()? {
                            rest.push(item)
                        }

                        Ok(ContextArray(did_v1, rest))
                    }
                    None => Err(<A::Error as serde::de::Error>::custom(
                        "expected <https://www.w3.org/ns/did/v1> as first context item",
                    )),
                }
            }
        }

        deserializer.deserialize_seq(Visitor)
    }
}
