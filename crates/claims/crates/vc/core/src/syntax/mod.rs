//! Syntaxes for the VC data model.
pub mod json;
mod jwt;

use std::{borrow::Borrow, marker::PhantomData};

pub use json::{
    JsonCredential, JsonPresentation, JsonVerifiableCredential, JsonVerifiablePresentation,
};
use json_ld::syntax::ContextEntry;
pub use jwt::*;
use serde::{Deserialize, Serialize};

use crate::{RequiredContext, V1};

/// Verifiable Credential context.
///
/// This type represents the value of the `@context` property.
///
/// It is an ordered set where the first item is a URI with the value
/// `https://www.w3.org/2018/credentials/v1`.
#[derive(Debug, Clone, Serialize)]
#[serde(transparent)]
pub struct Context<V = V1>(json_ld::syntax::Context, PhantomData<V>);

impl<V: RequiredContext> Default for Context<V> {
    fn default() -> Self {
        Self(
            json_ld::syntax::Context::One(json_ld::syntax::ContextEntry::IriRef(
                V::CONTEXT_IRI.as_iri_ref().to_owned(),
            )),
            PhantomData,
        )
    }
}

impl<V> AsRef<json_ld::syntax::Context> for Context<V> {
    fn as_ref(&self) -> &json_ld::syntax::Context {
        &self.0
    }
}

impl<V> Borrow<json_ld::syntax::Context> for Context<V> {
    fn borrow(&self) -> &json_ld::syntax::Context {
        &self.0
    }
}

impl<'de, V: RequiredContext> Deserialize<'de> for Context<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<V>(PhantomData<V>);

        impl<'de, V: RequiredContext> serde::de::Visitor<'de> for Visitor<V> {
            type Value = Context<V>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "presentation types")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if V::CONTEXT_IRI == v {
                    Ok(Context::default())
                } else {
                    Err(E::custom(format!("expected `\"{}\"`", V::CONTEXT_IRI)))
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut contexts = Vec::new();

                match seq.next_element()? {
                    Some(ContextEntry::IriRef(i)) if i == V::CONTEXT_IRI => {
                        contexts.push(ContextEntry::IriRef(i));

                        while let Some(t) = seq.next_element()? {
                            contexts.push(t)
                        }

                        Ok(Context(
                            json_ld::syntax::Context::Many(contexts),
                            PhantomData,
                        ))
                    }
                    _ => Err(<A::Error as serde::de::Error>::custom(format!(
                        "missing required `\"{}\"` type",
                        V::CONTEXT_IRI
                    ))),
                }
            }
        }

        deserializer.deserialize_any(Visitor(PhantomData))
    }
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
