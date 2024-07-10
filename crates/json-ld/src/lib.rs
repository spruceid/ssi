//! Linked-Data types.
use std::{borrow::Cow, hash::Hash};

use json_ld::expansion::Action;
use linked_data::{LinkedData, LinkedDataResource, LinkedDataSubject};

pub use json_ld;
pub use json_ld::*;
use serde::{Deserialize, Serialize};
use ssi_rdf::{
    generator, interpretation::WithGenerator, Interpretation, LdEnvironment, Vocabulary,
    VocabularyMut,
};

mod contexts;
pub use contexts::*;

/// Type that provides a JSON-LD document loader.
pub trait JsonLdLoaderProvider {
    type Loader: json_ld::Loader;

    fn loader(&self) -> &Self::Loader;
}

impl<'a, E: JsonLdLoaderProvider> JsonLdLoaderProvider for &'a E {
    type Loader = E::Loader;

    fn loader(&self) -> &Self::Loader {
        E::loader(*self)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum JsonLdError {
    #[error("expansion error: {0}")]
    Expansion(#[from] json_ld::expansion::Error),

    #[error("interpretation error: {0}")]
    Interpretation(#[from] linked_data::IntoQuadsError),
}

#[repr(transparent)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct CompactJsonLd(pub json_syntax::Value);

impl CompactJsonLd {
    pub fn from_value_ref(value: &json_syntax::Value) -> &Self {
        unsafe { std::mem::transmute(value) }
    }
}

/// JSON-LD-Expandable value.
pub trait Expandable: Sized {
    type Error: std::fmt::Display;

    type Expanded<I: Interpretation, V: Vocabulary>: LinkedData<I, V>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    #[allow(async_fn_in_trait)]
    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    #[allow(async_fn_in_trait)]
    async fn expand(
        &self,
        loader: &impl Loader,
    ) -> Result<Self::Expanded<WithGenerator<generator::Blank>, ()>, Self::Error> {
        let mut ld = LdEnvironment::default();
        self.expand_with(&mut ld, loader).await
    }
}

impl Expandable for CompactJsonLd {
    type Error = JsonLdError;
    type Expanded<I, V> = json_ld::ExpandedDocument<V::Iri, V::BlankId>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: LinkedDataResource<I, V> + LinkedDataSubject<I, V>;

    async fn expand_with<I, V>(
        &self,
        ld: &mut LdEnvironment<V, I>,
        loader: &impl Loader,
    ) -> Result<Self::Expanded<I, V>, Self::Error>
    where
        I: Interpretation,
        V: VocabularyMut,
        V::Iri: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
        V::BlankId: Clone + Eq + Hash + LinkedDataResource<I, V> + LinkedDataSubject<I, V>,
    {
        let expanded = self
            .0
            .expand_full(
                &mut ld.vocabulary,
                Default::default(),
                None,
                loader,
                json_ld::expansion::Options {
                    policy: json_ld::expansion::Policy {
                        invalid: Action::Reject,
                        allow_undefined: false,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                (),
            )
            .await?;

        Ok(expanded)
    }
}

/// Any type representing a JSON-LD object.
pub trait JsonLdObject {
    /// Returns the JSON-LD context attached to `self`.
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        None
    }
}

impl JsonLdObject for CompactJsonLd {
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        json_syntax::from_value(self.0.as_object()?.get("@context").next()?.clone())
            .map(Cow::Owned)
            .ok()
    }
}

pub trait JsonLdNodeObject: JsonLdObject {
    fn json_ld_type(&self) -> JsonLdTypes {
        JsonLdTypes::default()
    }
}

#[derive(Debug)]
pub struct JsonLdTypes<'a> {
    static_: &'static [&'static str],
    non_static: Cow<'a, [String]>,
}

impl<'a> Default for JsonLdTypes<'a> {
    fn default() -> Self {
        Self::new(&[], Cow::Owned(vec![]))
    }
}

impl<'a> JsonLdTypes<'a> {
    pub fn new(static_: &'static [&'static str], non_static: Cow<'a, [String]>) -> Self {
        Self {
            static_,
            non_static,
        }
    }

    pub fn len(&self) -> usize {
        self.static_.len() + self.non_static.len()
    }

    pub fn is_empty(&self) -> bool {
        self.static_.is_empty() && self.non_static.is_empty()
    }

    pub fn reborrow(&self) -> JsonLdTypes {
        JsonLdTypes {
            static_: self.static_,
            non_static: Cow::Borrowed(&self.non_static),
        }
    }
}

impl<'a> From<&'static &'static str> for JsonLdTypes<'a> {
    fn from(value: &'static &'static str) -> Self {
        Self::new(std::slice::from_ref(value), Cow::Owned(vec![]))
    }
}

impl<'a> From<&'a [String]> for JsonLdTypes<'a> {
    fn from(value: &'a [String]) -> Self {
        Self::new(&[], Cow::Borrowed(value))
    }
}

impl<'a> From<Vec<String>> for JsonLdTypes<'a> {
    fn from(value: Vec<String>) -> Self {
        Self::new(&[], Cow::Owned(value))
    }
}

impl<'a> From<Cow<'a, [String]>> for JsonLdTypes<'a> {
    fn from(value: Cow<'a, [String]>) -> Self {
        Self::new(&[], value)
    }
}

impl<'a> serde::Serialize for JsonLdTypes<'a> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        let mut seq = serializer.serialize_seq(Some(self.static_.len() + self.non_static.len()))?;
        for ty in self.static_ {
            seq.serialize_element(ty)?;
        }
        for ty in self.non_static.as_ref() {
            seq.serialize_element(ty)?;
        }
        seq.end()
    }
}

pub struct WithContext<T> {
    pub context: Option<json_ld::syntax::Context>,
    pub value: T,
}

impl<T> WithContext<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> WithContext<U> {
        WithContext {
            context: self.context,
            value: f(self.value),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{CompactJsonLd, ContextLoader, Expandable};

    #[async_std::test]
    async fn accept_defined_type() {
        let input = CompactJsonLd(json_syntax::json!({
            "@context": { "Defined": "http://example.org/#Defined" },
            "@type": ["Defined"]
        }));

        assert!(input.expand(&ContextLoader::default()).await.is_ok());
    }

    #[async_std::test]
    async fn reject_undefined_type() {
        let input = CompactJsonLd(json_syntax::json!({
            "@type": ["Undefined"]
        }));

        assert!(input.expand(&ContextLoader::default()).await.is_err());
    }

    #[async_std::test]
    async fn accept_defined_property() {
        let input = CompactJsonLd(json_syntax::json!({
            "@context": { "defined": "http://example.org/#defined" },
            "defined": "foo"
        }));

        assert!(input.expand(&ContextLoader::default()).await.is_ok());
    }

    #[async_std::test]
    async fn reject_undefined_property() {
        let input = CompactJsonLd(json_syntax::json!({
            "undefined": "foo"
        }));

        assert!(input.expand(&ContextLoader::default()).await.is_err());
    }
}
