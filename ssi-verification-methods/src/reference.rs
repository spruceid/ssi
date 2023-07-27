use core::fmt;
use std::{borrow::Cow, marker::PhantomData};

use iref::{Iri, IriBuf};
use rdf_types::VocabularyMut;
use treeldr_rust_prelude::{locspan::Meta, AsJsonLdObjectMeta, IntoJsonLdObjectMeta};

use crate::{
    Any, ExpectedType, IntoAnyVerificationMethod, LinkedDataVerificationMethod,
    TryFromVerificationMethod, TryIntoVerificationMethod, VerificationMethod,
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

impl<M: VerificationMethod> Reference<M> {
    pub fn into_any(self) -> Reference<Any> {
        Reference {
            iri: self.iri,
            expected_type: self.expected_type.or_else(M::expected_type),
            m: PhantomData,
        }
    }

    pub fn as_any(&self) -> ReferenceRef<Any> {
        ReferenceRef {
            iri: self.iri.as_iri(),
            expected_type: self
                .expected_type
                .as_ref()
                .map(Cow::Borrowed)
                .or_else(|| M::expected_type().map(Cow::Owned)),
            m: PhantomData,
        }
    }
}

impl<M, N> TryFromVerificationMethod<Reference<N>> for Reference<M> {
    fn try_from_verification_method(
        method: Reference<N>,
    ) -> Result<Self, crate::InvalidVerificationMethod> {
        Ok(Self {
            iri: method.iri,
            expected_type: method.expected_type,
            m: PhantomData,
        })
    }
}

impl<M: VerificationMethod> IntoAnyVerificationMethod for Reference<M> {
    type Output = Reference<Any>;

    fn into_any_verification_method(self) -> Self::Output {
        self.into_any()
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

impl<M: ssi_crypto::VerificationMethod> ssi_crypto::VerificationMethod for Reference<M> {
    type Reference<'a> = ReferenceRef<'a, M> where Self: 'a;

    fn as_reference(&self) -> Self::Reference<'_> {
        ReferenceRef {
            iri: self.iri.as_iri(),
            expected_type: self.expected_type.as_ref().map(Cow::Borrowed),
            m: PhantomData,
        }
    }

    type Signature = M::Signature;
}

impl<M: LinkedDataVerificationMethod> LinkedDataVerificationMethod for Reference<M> {
    fn quads(&self, _quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
        rdf_types::Object::Id(rdf_types::Id::Iri(self.iri.clone()))
    }
}

pub struct ReferenceRef<'a, M> {
    iri: Iri<'a>,
    expected_type: Option<Cow<'a, ExpectedType>>,
    m: PhantomData<M>,
}

impl<'a, M> ReferenceRef<'a, M> {
    pub fn iri(&self) -> Iri {
        self.iri
    }

    pub fn expected_type(&self) -> Option<&ExpectedType> {
        self.expected_type.as_deref()
    }
}

impl<'a, M: VerificationMethod> ReferenceRef<'a, M> {
    pub fn as_any(&self) -> ReferenceRef<'a, Any> {
        ReferenceRef {
            iri: self.iri,
            expected_type: self
                .expected_type
                .clone()
                .or_else(|| M::expected_type().map(Cow::Owned)),
            m: PhantomData,
        }
    }
}

impl<'a, M, N: VerificationMethod> TryFromVerificationMethod<ReferenceRef<'a, N>>
    for ReferenceRef<'a, M>
{
    fn try_from_verification_method(
        method: ReferenceRef<'a, N>,
    ) -> Result<Self, crate::InvalidVerificationMethod> {
        Ok(ReferenceRef {
            iri: method.iri,
            expected_type: method
                .expected_type
                .or_else(|| N::expected_type().map(Cow::Owned)),
            m: PhantomData,
        })
    }
}

impl<'a, M> fmt::Debug for ReferenceRef<'a, M> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.iri.fmt(f)
    }
}

impl<'a, M> Clone for ReferenceRef<'a, M> {
    fn clone(&self) -> Self {
        Self {
            iri: self.iri,
            expected_type: self.expected_type.clone(),
            m: PhantomData,
        }
    }
}

impl<'a, M> PartialEq for ReferenceRef<'a, M> {
    fn eq(&self, other: &Self) -> bool {
        self.iri == other.iri
    }
}

impl<'a, M> Eq for ReferenceRef<'a, M> {}

impl<'a, M> PartialOrd for ReferenceRef<'a, M> {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.iri.partial_cmp(&other.iri)
    }
}

impl<'a, M> Ord for ReferenceRef<'a, M> {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.iri.cmp(&other.iri)
    }
}

impl<'a, M> core::hash::Hash for ReferenceRef<'a, M> {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.iri.hash(state)
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

impl<M: TryFromVerificationMethod<N>, N> TryFromVerificationMethod<ReferenceOrOwned<N>>
    for ReferenceOrOwned<M>
{
    fn try_from_verification_method(
        method: ReferenceOrOwned<N>,
    ) -> Result<Self, crate::InvalidVerificationMethod> {
        match method {
            ReferenceOrOwned::Reference(r) => r.try_into_verification_method().map(Self::Reference),
            ReferenceOrOwned::Owned(m) => m.try_into_verification_method().map(Self::Owned),
        }
    }
}

/// Reference to a verification method.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ReferenceOrOwnedRef<'a, M: 'a + ssi_crypto::VerificationMethod> {
    Reference(ReferenceRef<'a, M>),
    Owned(M::Reference<'a>),
}

impl<'a, M, N> TryFromVerificationMethod<ReferenceOrOwnedRef<'a, N>> for ReferenceOrOwnedRef<'a, M>
where
    M: ssi_crypto::VerificationMethod,
    M::Reference<'a>: TryFromVerificationMethod<N::Reference<'a>>,
    N: VerificationMethod,
{
    fn try_from_verification_method(
        method: ReferenceOrOwnedRef<'a, N>,
    ) -> Result<Self, crate::InvalidVerificationMethod> {
        match method {
            ReferenceOrOwnedRef::Reference(r) => {
                r.try_into_verification_method().map(Self::Reference)
            }
            ReferenceOrOwnedRef::Owned(m) => m.try_into_verification_method().map(Self::Owned),
        }
    }
}

impl<M: VerificationMethod + Into<Any>> IntoAnyVerificationMethod for ReferenceOrOwned<M> {
    type Output = ReferenceOrOwned<Any>;

    fn into_any_verification_method(self) -> Self::Output {
        match self {
            Self::Reference(r) => ReferenceOrOwned::Reference(r.into_any()),
            Self::Owned(m) => ReferenceOrOwned::Owned(m.into()),
        }
    }
}

impl<M: ssi_crypto::VerificationMethod> ssi_crypto::VerificationMethod for ReferenceOrOwned<M> {
    type Reference<'a> = ReferenceOrOwnedRef<'a, M> where Self: 'a;

    fn as_reference(&self) -> ReferenceOrOwnedRef<M> {
        match self {
            Self::Reference(r) => ReferenceOrOwnedRef::Reference(r.as_reference()),
            Self::Owned(m) => ReferenceOrOwnedRef::Owned(m.as_reference()),
        }
    }

    type Signature = M::Signature;
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
