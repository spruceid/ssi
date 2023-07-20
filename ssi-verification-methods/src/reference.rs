use core::fmt;
use std::marker::PhantomData;

use iref::{Iri, IriBuf};
use rdf_types::VocabularyMut;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::LinkedDataVerificationMethod;

/// Reference to a verification method.
pub struct Reference<M>(IriBuf, PhantomData<M>);

impl<M> Reference<M> {
    pub fn new(iri: IriBuf) -> Self {
        Self(iri, PhantomData)
    }

    pub fn iri(&self) -> Iri {
        self.0.as_iri()
    }

    pub fn into_iri(self) -> IriBuf {
        self.0
    }

    pub fn as_str(&self) -> &str {
        self.0.as_str()
    }
}

impl<M> fmt::Debug for Reference<M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<M> Clone for Reference<M> {
    fn clone(&self) -> Self {
        Self(self.0.clone(), PhantomData)
    }
}

impl<M> PartialEq for Reference<M> {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl<M> Eq for Reference<M> {}

impl<M> PartialOrd for Reference<M> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.0.partial_cmp(&other.0)
    }
}

impl<M> Ord for Reference<M> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.0.cmp(&other.0)
    }
}

impl<M> core::hash::Hash for Reference<M> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.0.hash(state)
    }
}

impl<M: LinkedDataVerificationMethod> LinkedDataVerificationMethod for Reference<M> {
    fn quads(&self, _quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
        rdf_types::Object::Id(rdf_types::Id::Iri(self.0.clone()))
    }
}

/// Reference to a verification method.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
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
