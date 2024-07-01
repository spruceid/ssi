use std::{borrow::Borrow, marker::PhantomData};

use educe::Educe;
use iref::{Iri, IriBuf, IriRef};
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
                std::iter::once(ContextEntry::IriRef(V::CONTEXT_IRI.as_iri_ref().to_owned()))
                    .chain(
                        T::CONTEXT_IRIS
                            .iter()
                            .map(|&i| ContextEntry::IriRef(i.as_iri_ref().to_owned())),
                    )
                    .collect(),
            ),
            PhantomData,
        )
    }
}

impl<V, T> Context<V, T> {
    /// Checks if this context contains the given entry.
    pub fn contains(&self, entry: &ContextEntry) -> bool {
        match &self.0 {
            ssi_json_ld::syntax::Context::One(e) => e == entry,
            ssi_json_ld::syntax::Context::Many(entries) => entries.iter().any(|e| e == entry),
        }
    }

    /// Checks if this context contains the given IRI entry.
    pub fn contains_iri(&self, iri: &Iri) -> bool {
        self.contains_iri_ref(iri.as_iri_ref())
    }

    /// Checks if this context contains the given IRI reference entry.
    pub fn contains_iri_ref(&self, iri_ref: &IriRef) -> bool {
        match &self.0 {
            ssi_json_ld::syntax::Context::One(ContextEntry::IriRef(i)) => i == iri_ref,
            ssi_json_ld::syntax::Context::One(_) => false,
            ssi_json_ld::syntax::Context::Many(entries) => entries
                .iter()
                .any(|e| matches!(e, ContextEntry::IriRef(i) if i == iri_ref)),
        }
    }

    /// Returns an iterator over the context entries.
    pub fn iter(&self) -> std::slice::Iter<ContextEntry> {
        self.0.iter()
    }

    /// Inserts the given entry in the context.
    ///
    /// Appends the entry at the end unless it is already present.
    ///
    /// Returns `true` if the entry was not already present.
    /// Returns `false` if the entry was already present in the context, in
    /// which case it is not added a second time.
    pub fn insert(&mut self, entry: ContextEntry) -> bool {
        if self.contains(&entry) {
            false
        } else {
            let mut entries = match std::mem::take(&mut self.0) {
                ssi_json_ld::syntax::Context::One(e) => vec![e],
                ssi_json_ld::syntax::Context::Many(entries) => entries,
            };

            entries.push(entry);
            self.0 = ssi_json_ld::syntax::Context::Many(entries);
            true
        }
    }
}

impl<'a, V, T> IntoIterator for &'a Context<V, T> {
    type Item = &'a ContextEntry;
    type IntoIter = std::slice::Iter<'a, ContextEntry>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<V, T> IntoIterator for Context<V, T> {
    type Item = ContextEntry;
    type IntoIter = ssi_json_ld::syntax::context::IntoIter;

    fn into_iter(self) -> Self::IntoIter {
        self.0.into_iter()
    }
}

impl<V, T> Extend<ContextEntry> for Context<V, T> {
    fn extend<E: IntoIterator<Item = ContextEntry>>(&mut self, iter: E) {
        for entry in iter {
            self.insert(entry);
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

impl<V, T> From<Context<V, T>> for ssi_json_ld::syntax::Context {
    fn from(value: Context<V, T>) -> Self {
        value.0
    }
}

/// Error that can occur while converting an arbitrary JSON-LD context into a
/// VCDM context.
#[derive(Debug, thiserror::Error)]
pub enum InvalidContext {
    #[error("unexpected context entry (expected `{0}`)")]
    UnexpectedContext(IriBuf, ContextEntry),

    #[error("missing required context entry `{0}`")]
    MissingRequiredContext(IriBuf),
}

impl<V: RequiredContext, T: RequiredContextList> TryFrom<ssi_json_ld::syntax::Context>
    for Context<V, T>
{
    type Error = InvalidContext;

    fn try_from(value: ssi_json_ld::syntax::Context) -> Result<Self, Self::Error> {
        let entries = match value {
            ssi_json_ld::syntax::Context::One(entry) => vec![entry],
            ssi_json_ld::syntax::Context::Many(entries) => entries,
        };

        match entries.split_first() {
            Some((ContextEntry::IriRef(iri), rest)) if iri == V::CONTEXT_IRI => {
                let mut expected = T::CONTEXT_IRIS.iter();
                let mut rest = rest.iter();
                loop {
                    match (expected.next(), rest.next()) {
                        (Some(e), Some(ContextEntry::IriRef(f))) if *e == f => (),
                        (Some(e), Some(f)) => {
                            break Err(InvalidContext::UnexpectedContext(
                                (*e).to_owned(),
                                f.clone(),
                            ))
                        }
                        (Some(e), None) => {
                            break Err(InvalidContext::MissingRequiredContext((*e).to_owned()))
                        }
                        _ => {
                            break Ok(Self(
                                ssi_json_ld::syntax::Context::Many(entries),
                                PhantomData,
                            ))
                        }
                    }
                }
            }
            Some((other, _)) => Err(InvalidContext::UnexpectedContext(
                V::CONTEXT_IRI.to_owned(),
                other.clone(),
            )),
            None => Err(InvalidContext::MissingRequiredContext(
                V::CONTEXT_IRI.to_owned(),
            )),
        }
    }
}

impl<'de, V: RequiredContext, T: RequiredContextList> Deserialize<'de> for Context<V, T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let context = ssi_json_ld::syntax::Context::deserialize(deserializer)?;
        context.try_into().map_err(serde::de::Error::custom)
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
