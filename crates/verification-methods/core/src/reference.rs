use crate::{LinkedDataVerificationMethod, VerificationMethod};
use educe::Educe;
use iref::{Iri, IriBuf};
use serde::{Deserialize, Serialize};

/// Reference to a verification method.
#[derive(
    Debug,
    Clone,
    PartialEq,
    Eq,
    PartialOrd,
    Ord,
    Hash,
    Serialize,
    Deserialize,
    linked_data::Serialize,
    linked_data::Deserialize,
)]
#[serde(untagged)]
pub enum ReferenceOrOwned<M> {
    Reference(#[ld(id)] IriBuf),
    Owned(M),
}

impl<M> ReferenceOrOwned<M> {
    pub fn id(&self) -> &Iri
    where
        M: VerificationMethod,
    {
        match self {
            Self::Reference(r) => r,
            Self::Owned(m) => m.id(),
        }
    }

    pub fn borrowed(&self) -> ReferenceOrOwnedRef<M> {
        match self {
            Self::Reference(r) => ReferenceOrOwnedRef::Reference(r.as_iri()),
            Self::Owned(m) => ReferenceOrOwnedRef::Owned(m),
        }
    }

    pub fn map<N>(self, f: impl FnOnce(M) -> N) -> ReferenceOrOwned<N> {
        match self {
            Self::Reference(r) => ReferenceOrOwned::Reference(r),
            Self::Owned(o) => ReferenceOrOwned::Owned(f(o)),
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

impl<'a, M> From<&'a Iri> for ReferenceOrOwned<M> {
    fn from(value: &'a Iri) -> Self {
        Self::Reference(value.to_owned())
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
#[derive(Educe, Debug, Serialize, linked_data::Serialize, linked_data::Deserialize)]
#[educe(Clone, Copy)]
#[serde(untagged)]
pub enum ReferenceOrOwnedRef<'a, M> {
    Reference(#[ld(id)] &'a Iri),
    Owned(&'a M),
}

impl<'a, M: VerificationMethod> ReferenceOrOwnedRef<'a, M> {
    pub fn cloned(&self) -> ReferenceOrOwned<M> {
        match *self {
            Self::Reference(iri) => ReferenceOrOwned::Reference(iri.to_owned()),
            Self::Owned(m) => ReferenceOrOwned::Owned(m.clone()),
        }
    }

    pub fn id(&self) -> &'a Iri {
        match self {
            Self::Reference(r) => r,
            Self::Owned(m) => m.id(),
        }
    }
}

impl<'a, M> ReferenceOrOwnedRef<'a, M> {
    pub fn map<N>(self, f: impl FnOnce(&'a M) -> &'a N) -> ReferenceOrOwnedRef<'a, N> {
        match self {
            Self::Reference(r) => ReferenceOrOwnedRef::Reference(r),
            Self::Owned(o) => ReferenceOrOwnedRef::Owned(f(o)),
        }
    }

    pub fn try_map<N, E>(
        self,
        f: impl FnOnce(&'a M) -> Result<&'a N, E>,
    ) -> Result<ReferenceOrOwnedRef<'a, N>, E> {
        match self {
            Self::Reference(r) => Ok(ReferenceOrOwnedRef::Reference(r)),
            Self::Owned(o) => f(o).map(ReferenceOrOwnedRef::Owned),
        }
    }

    pub fn try_cast<N>(self) -> Result<ReferenceOrOwnedRef<'a, N>, <&'a M as TryInto<&'a N>>::Error>
    where
        &'a M: TryInto<&'a N>,
    {
        self.try_map(TryInto::try_into)
    }
}

impl<'a, M> LinkedDataVerificationMethod for ReferenceOrOwnedRef<'a, M>
where
    &'a M: LinkedDataVerificationMethod,
{
    fn quads(&self, quads: &mut Vec<rdf_types::Quad>) -> rdf_types::Object {
        match self {
            Self::Reference(r) => rdf_types::Object::Id(rdf_types::Id::Iri(Iri::to_owned(*r))),
            Self::Owned(m) => m.quads(quads),
        }
    }
}
