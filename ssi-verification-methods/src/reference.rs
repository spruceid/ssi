use crate::{LinkedDataVerificationMethod, Referencable, VerificationMethodRef};
use iref::{Iri, IriBuf};
use linked_data::LinkedData;
use serde::{Deserialize, Serialize};

/// Reference to a verification method.
#[derive(
    Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize, LinkedData,
)]
#[serde(untagged)]
pub enum ReferenceOrOwned<M> {
    Reference(#[ld(id)] IriBuf),
    Owned(M),
}

impl<M> ReferenceOrOwned<M> {
    pub fn borrowed(&self) -> ReferenceOrOwnedRef<M>
    where
        M: Referencable,
    {
        match self {
            Self::Reference(r) => ReferenceOrOwnedRef::Reference(r.as_iri()),
            Self::Owned(m) => ReferenceOrOwnedRef::Owned(m.as_reference()),
        }
    }

    pub fn try_map<N, E>(
        self,
        f: impl FnOnce(M) -> Result<N, E>,
    ) -> Result<ReferenceOrOwned<N>, E> {
        match self {
            Self::Reference(r) => Ok(ReferenceOrOwned::Reference(r)),
            Self::Owned(o) => f(o).map(ReferenceOrOwned::Owned),
        }
    }

    pub fn try_cast<N>(self) -> Result<ReferenceOrOwned<N>, M::Error>
    where
        M: TryInto<N>,
    {
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
            Self::Reference(r) => rdf_types::Object::Id(rdf_types::Id::Iri(r.clone())),
            Self::Owned(m) => m.quads(quads),
        }
    }
}

/// Reference to a verification method.
#[derive(Serialize, LinkedData)]
#[serde(untagged, bound(serialize = "M::Reference<'a>: Serialize"))]
pub enum ReferenceOrOwnedRef<'a, M: 'a + Referencable> {
    Reference(#[ld(id)] &'a Iri),
    Owned(M::Reference<'a>),
}

impl<'a, M: Referencable> ReferenceOrOwnedRef<'a, M>
where
    M::Reference<'a>: VerificationMethodRef<'a>,
{
    pub fn id(&self) -> &'a Iri {
        match self {
            Self::Reference(r) => *r,
            Self::Owned(m) => m.id(),
        }
    }
}

impl<'a, M: Referencable> Clone for ReferenceOrOwnedRef<'a, M> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a, M: Referencable> Copy for ReferenceOrOwnedRef<'a, M> {}

impl<'a, M: Referencable> ReferenceOrOwnedRef<'a, M> {
    pub fn try_map<N: 'a + Referencable, E>(
        self,
        f: impl FnOnce(M::Reference<'a>) -> Result<N::Reference<'a>, E>,
    ) -> Result<ReferenceOrOwnedRef<'a, N>, E> {
        match self {
            Self::Reference(r) => Ok(ReferenceOrOwnedRef::Reference(r)),
            Self::Owned(o) => f(o).map(ReferenceOrOwnedRef::Owned),
        }
    }

    pub fn try_cast<N: 'a + Referencable>(
        self,
    ) -> Result<ReferenceOrOwnedRef<'a, N>, <M::Reference<'a> as TryInto<N::Reference<'a>>>::Error>
    where
        M::Reference<'a>: TryInto<N::Reference<'a>>,
    {
        self.try_map(TryInto::try_into)
    }
}

impl<'a, M: Referencable> LinkedDataVerificationMethod for ReferenceOrOwnedRef<'a, M>
where
    M::Reference<'a>: LinkedDataVerificationMethod,
{
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
        match self {
            Self::Reference(r) => rdf_types::Object::Id(rdf_types::Id::Iri(Iri::to_owned(*r))),
            Self::Owned(m) => m.quads(quads),
        }
    }
}
