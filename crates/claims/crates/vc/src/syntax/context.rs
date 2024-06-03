use std::{borrow::Borrow, marker::PhantomData};

use educe::Educe;
use iref::{Iri, IriRef, IriRefBuf};
use serde::{Deserialize, Serialize};
use ssi_json_ld::syntax::ContextEntry;

/// JSON-LD context.
///
/// This type represents the value of the `@context` property.
///
/// It is an ordered set where the first item is a URI given by the `V` type
/// parameter implementing [`RequiredContext`], followed by a list of more
/// required context given by the type parameter `T`, implementing
/// [`RequiredContextList`].
#[derive(Educe, Serialize)] // FIXME serializing a single entry as a string breaks Tezos JCS cryptosuite.
#[educe(Debug, Clone)]
#[serde(transparent, bound = "")]
pub struct Context<V, T = ()>(ssi_json_ld::syntax::Context, PhantomData<(V, T)>);

impl<V: RequiredContext, T: RequiredContextList> Default for Context<V, T> {
    fn default() -> Self {
        Self(
            ssi_json_ld::syntax::Context::Many(
                std::iter::once(ssi_json_ld::syntax::ContextEntry::IriRef(
                    V::CONTEXT_IRI.as_iri_ref().to_owned(),
                ))
                .chain(
                    T::CONTEXT_IRIS.iter().map(|&i| {
                        ssi_json_ld::syntax::ContextEntry::IriRef(i.as_iri_ref().to_owned())
                    }),
                )
                .collect(),
            ),
            PhantomData,
        )
    }
}

impl<V, T> Context<V, T> {
    pub fn contains_iri(&self, iri: &Iri) -> bool {
        self.contains_iri_ref(iri.as_iri_ref())
    }

    pub fn contains_iri_ref(&self, iri_ref: &IriRef) -> bool {
        match &self.0 {
            ssi_json_ld::syntax::Context::One(ContextEntry::IriRef(i)) => i == iri_ref,
            ssi_json_ld::syntax::Context::One(_) => false,
            ssi_json_ld::syntax::Context::Many(entries) => entries
                .iter()
                .any(|e| matches!(e, ContextEntry::IriRef(i) if i == iri_ref)),
        }
    }
}

impl<V, T> AsRef<ssi_json_ld::syntax::Context> for Context<V, T> {
    fn as_ref(&self) -> &ssi_json_ld::syntax::Context {
        &self.0
    }
}

impl<V, T> Borrow<ssi_json_ld::syntax::Context> for Context<V, T> {
    fn borrow(&self) -> &ssi_json_ld::syntax::Context {
        &self.0
    }
}

impl<'de, V: RequiredContext, T: RequiredContextList> Deserialize<'de> for Context<V, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor<V, E>(PhantomData<(V, E)>);

        impl<'de, V: RequiredContext, T: RequiredContextList> serde::de::Visitor<'de> for Visitor<V, T> {
            type Value = Context<V, T>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "presentation types")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                match IriRefBuf::new(v.to_owned()) {
                    Ok(v) => {
                        if v == V::CONTEXT_IRI {
                            let contexts = vec![ContextEntry::IriRef(v)];

                            for &required in T::CONTEXT_IRIS {
                                if required != V::CONTEXT_IRI {
                                    return Err(E::custom(format!(
                                        "expected required context `{}`",
                                        required
                                    )));
                                }
                            }

                            Ok(Context(
                                ssi_json_ld::syntax::Context::Many(contexts),
                                PhantomData,
                            ))
                        } else {
                            Err(E::custom(format!(
                                "expected required context `{}`",
                                V::CONTEXT_IRI
                            )))
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

                match seq.next_element()? {
                    Some(entry) => match &entry {
                        ContextEntry::IriRef(iri) if iri == V::CONTEXT_IRI => contexts.push(entry),
                        _ => {
                            return Err(<A::Error as serde::de::Error>::custom(format!(
                                "missing required context `{}`",
                                V::CONTEXT_IRI
                            )))
                        }
                    },
                    None => {
                        return Err(<A::Error as serde::de::Error>::custom(format!(
                            "missing required context `{}`",
                            V::CONTEXT_IRI
                        )))
                    }
                }

                while let Some(entry) = seq.next_element()? {
                    let i = contexts.len() - 1;

                    if i < T::CONTEXT_IRIS.len() {
                        let required_iri = T::CONTEXT_IRIS[i];

                        match &entry {
                            ContextEntry::IriRef(iri) if iri == required_iri.as_iri_ref() => {}
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

                if contexts.len() - 1 < T::CONTEXT_IRIS.len() {
                    let required_iri = T::CONTEXT_IRIS[contexts.len() - 1];
                    Err(<A::Error as serde::de::Error>::custom(format!(
                        "missing required context `{}`",
                        required_iri
                    )))
                } else {
                    Ok(Context(
                        ssi_json_ld::syntax::Context::Many(contexts),
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
pub trait RequiredContextList {
    const CONTEXT_IRIS: &'static [&'static Iri];
}

impl RequiredContextList for () {
    const CONTEXT_IRIS: &'static [&'static Iri] = &[];
}

impl<T: RequiredContext> RequiredContextList for T {
    const CONTEXT_IRIS: &'static [&'static Iri] = &[T::CONTEXT_IRI];
}

macro_rules! required_context_tuple {
    ($($t:ident: $n:tt),*) => {
        impl<$($t : RequiredContext),*> RequiredContextList for ($($t),*,) {
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
