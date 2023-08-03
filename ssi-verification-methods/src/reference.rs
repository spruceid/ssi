use core::fmt;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

use iref::{Iri, IriBuf};
use rdf_types::VocabularyMut;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    ExpectedType, LinkedDataVerificationMethod
};

/// Reference to a verification method.
pub struct Reference<M> {
    iri: IriBuf,
    expected_type: Option<ExpectedType>,
    m: PhantomData<M>,
}

impl<M> Reference<M> {
    pub fn new(iri: IriBuf) -> Self {
        Self {
            iri,
            expected_type: None,
            m: PhantomData,
        }
    }

    pub fn iri(&self) -> Iri {
        self.iri.as_iri()
    }

    pub fn into_iri(self) -> IriBuf {
        self.iri
    }

    pub fn as_str(&self) -> &str {
        self.iri.as_str()
    }

    pub fn expected_type(&self) -> Option<&ExpectedType> {
        self.expected_type.as_ref()
    }
}

impl<M> fmt::Debug for Reference<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.iri.fmt(f)
    }
}

impl<M> Clone for Reference<M> {
    fn clone(&self) -> Self {
        Self {
            iri: self.iri.clone(),
            expected_type: self.expected_type.clone(),
            m: PhantomData,
        }
    }
}

impl<M> PartialEq for Reference<M> {
    fn eq(&self, other: &Self) -> bool {
        self.iri == other.iri
    }
}

impl<M> Eq for Reference<M> {}

impl<M> PartialOrd for Reference<M> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.iri.partial_cmp(&other.iri)
    }
}

impl<M> Ord for Reference<M> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.iri.cmp(&other.iri)
    }
}

impl<M> core::hash::Hash for Reference<M> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.iri.hash(state)
    }
}

impl<M> Serialize for Reference<M> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.iri.serialize(serializer)
    }
}

impl<'de, M> Deserialize<'de> for Reference<M> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let iri = IriBuf::deserialize(deserializer)?;
        Ok(Self::new(iri))
    }
}

impl<M> LinkedDataVerificationMethod for Reference<M> {
    fn quads(&self, _quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
        rdf_types::Object::Id(rdf_types::Id::Iri(self.iri.clone()))
    }
}

/// Reference to a verification method.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ReferenceOrOwned<M> {
    Reference(Reference<M>),
    Owned(M),
}

impl<M> From<Reference<M>> for ReferenceOrOwned<M> {
    fn from(value: Reference<M>) -> Self {
        Self::Reference(value)
    }
}

impl<M> From<IriBuf> for ReferenceOrOwned<M> {
    fn from(value: IriBuf) -> Self {
        Self::Reference(Reference::new(value))
    }
}

impl<M: LinkedDataVerificationMethod> LinkedDataVerificationMethod for ReferenceOrOwned<M> {
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
        match self {
            Self::Reference(r) => r.quads(quads),
            Self::Owned(m) => m.quads(quads),
        }
    }
}

impl<V: VocabularyMut, I, M: Clone, T: IntoJsonLdObjectMeta<V, I, M>> IntoJsonLdObjectMeta<V, I, M>
    for ReferenceOrOwned<T>
{
    fn into_json_ld_object_meta(
        self,
        vocabulary: &mut V,
        interpretation: &I,
        meta: M,
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
        match self {
            Self::Reference(r) => Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Node(Box::new(json_ld::Node::with_id(
                        json_ld::syntax::Entry::new(
                            meta.clone(),
                            Meta(
                                json_ld::Id::Valid(json_ld::ValidId::Iri(
                                    vocabulary.insert_owned(r.into_iri()),
                                )),
                                meta.clone(),
                            ),
                        ),
                    ))),
                    None,
                ),
                meta,
            ),
            Self::Owned(m) => m.into_json_ld_object_meta(vocabulary, interpretation, meta),
        }
    }
}

impl<V: VocabularyMut, I, M: Clone, T: AsJsonLdObjectMeta<V, I, M>> AsJsonLdObjectMeta<V, I, M>
    for ReferenceOrOwned<T>
{
    fn as_json_ld_object_meta(
        &self,
        vocabulary: &mut V,
        interpretation: &I,
        meta: M,
    ) -> json_ld::IndexedObject<V::Iri, V::BlankId, M> {
        match self {
            Self::Reference(r) => Meta(
                json_ld::Indexed::new(
                    json_ld::Object::Node(Box::new(json_ld::Node::with_id(
                        json_ld::syntax::Entry::new(
                            meta.clone(),
                            Meta(
                                json_ld::Id::Valid(json_ld::ValidId::Iri(
                                    vocabulary.insert(r.iri()),
                                )),
                                meta.clone(),
                            ),
                        ),
                    ))),
                    None,
                ),
                meta,
            ),
            Self::Owned(m) => m.as_json_ld_object_meta(vocabulary, interpretation, meta),
        }
    }
}
