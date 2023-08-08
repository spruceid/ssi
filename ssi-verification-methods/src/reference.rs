use serde::{Deserialize, Serialize};
use iref::{Iri, IriBuf};
use rdf_types::{VocabularyMut, IriVocabulary, interpretation::ReverseIriInterpretation};
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta, FromRdf};

use crate::{
    LinkedDataVerificationMethod, Referencable, VerificationMethod
};

/// Reference to a verification method.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ReferenceOrOwned<M> {
    Reference(IriBuf),
    Owned(M),
}

impl<M> ReferenceOrOwned<M> {
    pub fn borrowed(&self) -> ReferenceOrOwnedRef<M> where M: Referencable {
        match self {
            Self::Reference(r) => ReferenceOrOwnedRef::Reference(r.as_iri()),
            Self::Owned(m) => ReferenceOrOwnedRef::Owned(m.as_reference())
        }
    }

    pub fn try_map<N, E>(self, f: impl FnOnce(M) -> Result<N, E>) -> Result<ReferenceOrOwned<N>, E> {
        match self {
            Self::Reference(r) => Ok(ReferenceOrOwned::Reference(r)),
            Self::Owned(o) => f(o).map(ReferenceOrOwned::Owned)
        }
    }

    pub fn try_cast<N>(self) -> Result<ReferenceOrOwned<N>, M::Error> where M: TryInto<N> {
        self.try_map(M::try_into)
    }
}

impl<M> From<IriBuf> for ReferenceOrOwned<M> {
    fn from(value: IriBuf) -> Self {
        Self::Reference(value)
    }
}

impl<M: LinkedDataVerificationMethod> LinkedDataVerificationMethod for ReferenceOrOwned<M> {
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
        match self {
            Self::Reference(r) => {
                rdf_types::Object::Id(rdf_types::Id::Iri(r.clone()))
            },
            Self::Owned(m) => m.quads(quads),
        }
    }
}

impl<V: IriVocabulary, I, M: FromRdf<V, I>> FromRdf<V, I> for ReferenceOrOwned<M>
where
    I: ReverseIriInterpretation<Iri = V::Iri>
{
    fn from_rdf<G>(
        vocabulary: &V,
        interpretation: &I,
        graph: &G,
        id: &<I as rdf_types::Interpretation>::Resource,
    ) -> Result<Self, treeldr_rust_prelude::FromRdfError>
    where
        G: treeldr_rust_prelude::grdf::Graph<Subject = <I as rdf_types::Interpretation>::Resource, Predicate = <I as rdf_types::Interpretation>::Resource, Object = <I as rdf_types::Interpretation>::Resource>
    {
        match M::from_rdf(vocabulary, interpretation, graph, id) {
            Ok(m) => Ok(Self::Owned(m)),
            Err(treeldr_rust_prelude::FromRdfError::MissingRequiredPropertyValue) => {
                let mut iris = interpretation.iris_of(id);
                match iris.next() {
                    Some(i) => {
                        let iri = vocabulary.iri(i).unwrap();
                        Ok(Self::Reference(iri.to_owned()))
                    }
                    None => Err(treeldr_rust_prelude::FromRdfError::UnexpectedLiteralValue) // TODO better error
                }
            }
            Err(e) => Err(e)
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
                                    vocabulary.insert_owned(r),
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
                                    vocabulary.insert(r.as_iri()),
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

// /// Method reference.
// pub struct Reference {
//     issuer: Option<IriBuf>,
//     key_id: Option<IriBuf>
// }

// /// Method reference reference.
// pub struct ReferenceRef<'a> {
//     issuer: Option<Iri<'a>>,
//     key_id: Option<Iri<'a>>
// }

/// Reference to a verification method.
#[derive(Serialize)]
#[serde(untagged, bound(serialize = "M::Reference<'a>: Serialize"))]
pub enum ReferenceOrOwnedRef<'a, M: 'a + Referencable> {
    Reference(Iri<'a>),
    Owned(M::Reference<'a>),
}

impl<'a, M: Referencable> ReferenceOrOwnedRef<'a, M>
where
    M::Reference<'a>: VerificationMethod
{
    pub fn id(&self) -> Iri {
        match self {
            Self::Reference(r) => *r,
            Self::Owned(m) => m.id()
        }
    }
}

unsafe impl<'a, M: Referencable> Send for ReferenceOrOwnedRef<'a, M>
where
    M::Reference<'a>: Send
{}

impl<'a, M: Referencable> Clone for ReferenceOrOwnedRef<'a, M> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, M: Referencable> Copy for ReferenceOrOwnedRef<'a, M> {}

impl<'a, M: Referencable> ReferenceOrOwnedRef<'a, M> {
    pub fn try_map<N: 'a + Referencable, E>(self, f: impl FnOnce(M::Reference<'a>) -> Result<N::Reference<'a>, E>) -> Result<ReferenceOrOwnedRef<'a, N>, E> {
        match self {
            Self::Reference(r) => Ok(ReferenceOrOwnedRef::Reference(r)),
            Self::Owned(o) => f(o).map(ReferenceOrOwnedRef::Owned)
        }
    }

    pub fn try_cast<N: 'a + Referencable>(
        self
    ) -> Result<ReferenceOrOwnedRef<'a, N>, <M::Reference<'a> as TryInto<N::Reference<'a>>>::Error> where M::Reference<'a>: TryInto<N::Reference<'a>> {
        self.try_map(TryInto::try_into)
    }
}

impl<'a, M: Referencable> LinkedDataVerificationMethod for ReferenceOrOwnedRef<'a, M>
where
    M::Reference<'a>: LinkedDataVerificationMethod
{
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
        match self {
            Self::Reference(r) => {
                rdf_types::Object::Id(rdf_types::Id::Iri(Iri::to_owned(*r)))
            },
            Self::Owned(m) => m.quads(quads),
        }
    }
}