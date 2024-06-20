use std::{borrow::Borrow, marker::PhantomData};

use educe::Educe;
use iref::{Iri, IriRef, IriRefBuf};
use json_ld::syntax::ContextEntry;
use serde::{Deserialize, Serialize};

use crate::V1;

/// Verifiable Credential context.
///
/// This type represents the value of the `@context` property.
///
/// It is an ordered set where the first item is a URI with the value
/// `https://www.w3.org/2018/credentials/v1`.
#[derive(Educe, Serialize)] // FIXME serializing a single entry as a string breaks Tezos JCS cryptosuite.
#[educe(Debug, Clone)]
#[serde(transparent, bound = "")]
pub struct Context<V = V1>(json_ld::syntax::Context, PhantomData<V>);

impl<V: RequiredContextSet> Default for Context<V> {
    fn default() -> Self {
        Self(
            json_ld::syntax::Context::Many(
                V::CONTEXT_IRIS
                    .iter()
                    .map(|&i| json_ld::syntax::ContextEntry::IriRef(i.as_iri_ref().to_owned()))
                    .collect(),
            ),
            PhantomData,
        )
    }
}

impl<V> Context<V> {
    pub fn contains_iri(&self, iri: &Iri) -> bool {
        self.contains_iri_ref(iri.as_iri_ref())
    }

    pub fn contains_iri_ref(&self, iri_ref: &IriRef) -> bool {
        match &self.0 {
            json_ld::syntax::Context::One(ContextEntry::IriRef(i)) => i == iri_ref,
            json_ld::syntax::Context::One(_) => false,
            json_ld::syntax::Context::Many(entries) => entries
                .iter()
                .any(|e| matches!(e, ContextEntry::IriRef(i) if i == iri_ref)),
        }
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

impl<'de, V: RequiredContextSet> Deserialize<'de> for Context<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<V>(PhantomData<V>);

        impl<'de, V: RequiredContextSet> serde::de::Visitor<'de> for Visitor<V> {
            type Value = Context<V>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "presentation types")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match IriRefBuf::new(v.to_owned()) {
                    Ok(iri_ref) => {
                        let contexts = vec![ContextEntry::IriRef(iri_ref)];
                        if contexts.len() < V::CONTEXT_IRIS.len() {
                            let required_iri = V::CONTEXT_IRIS[contexts.len()];
                            Err(E::custom(format!(
                                "missing required context `{}`",
                                required_iri
                            )))
                        } else {
                            Ok(Context(
                                json_ld::syntax::Context::Many(contexts),
                                PhantomData,
                            ))
                        }
                    }
                    Err(e) => Err(E::custom(format!("invalid context IRI `{v}`: {e}"))),
                }
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut contexts = Vec::new();

                while let Some(entry) = seq.next_element()? {
                    if contexts.len() < V::CONTEXT_IRIS.len() {
                        let required_iri = V::CONTEXT_IRIS[contexts.len()];

                        match &entry {
                            ContextEntry::IriRef(i) if required_iri.as_iri_ref() == i => {}
                            _ => {
                                return Err(<A::Error as serde::de::Error>::custom(format!(
                                    "missing required context `{}`",
                                    required_iri
                                )))
                            }
                        }
                    }

                    contexts.push(entry)
                }

                if contexts.len() < V::CONTEXT_IRIS.len() {
                    let required_iri = V::CONTEXT_IRIS[contexts.len()];
                    Err(<A::Error as serde::de::Error>::custom(format!(
                        "missing required context `{}`",
                        required_iri
                    )))
                } else {
                    Ok(Context(
                        json_ld::syntax::Context::Many(contexts),
                        PhantomData,
                    ))
                }
            }
        }

        deserializer.deserialize_any(Visitor(PhantomData))
    }
}

pub trait RequiredContext {
    const CONTEXT_IRI: &'static Iri;
}

/// Set of required contexts.
pub trait RequiredContextSet {
    const CONTEXT_IRIS: &'static [&'static Iri];
}

impl<T: RequiredContext> RequiredContextSet for T {
    const CONTEXT_IRIS: &'static [&'static Iri] = &[T::CONTEXT_IRI];
}

macro_rules! required_context_tuple {
    ($($t:ident: $n:tt),*) => {
        impl<$($t : RequiredContext),*> RequiredContextSet for ($($t),*,) {
            const CONTEXT_IRIS: &'static [&'static Iri] = &[
                $($t::CONTEXT_IRI),*
            ];
        }
    };
}

required_context_tuple!(T0: 0);
required_context_tuple!(T0: 0, T1: 1);
required_context_tuple!(T0: 0, T1: 1, T2: 2);
required_context_tuple!(T0: 0, T1: 1, T2: 2, T3: 3);
