use iref::Uri;

use crate::syntax::{
    IdOr, IdentifiedObject, IdentifiedTypedObject, MaybeIdentifiedObject,
    MaybeIdentifiedTypedObject,
};

/// Object that *may* contain an `id` property.
///
/// See: <https://www.w3.org/TR/vc-data-model-2.0/#identifiers>
pub trait MaybeIdentified {
    fn id(&self) -> Option<&Uri> {
        None
    }
}

impl MaybeIdentified for MaybeIdentifiedObject {
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }
}

impl MaybeIdentified for IdOr<MaybeIdentifiedObject> {
    fn id(&self) -> Option<&Uri> {
        match self {
            Self::Id(id) => Some(id),
            Self::NotId(o) => o.id(),
        }
    }
}

impl MaybeIdentified for MaybeIdentifiedTypedObject {
    fn id(&self) -> Option<&Uri> {
        self.id.as_deref()
    }
}

/// Object that contain an `id` property.
///
/// See: <https://www.w3.org/TR/vc-data-model-2.0/#identifiers>
pub trait Identified {
    fn id(&self) -> &Uri;
}

impl<T: Identified> MaybeIdentified for T {
    fn id(&self) -> Option<&Uri> {
        Some(Identified::id(self))
    }
}

impl Identified for std::convert::Infallible {
    fn id(&self) -> &Uri {
        unreachable!()
    }
}

impl Identified for Uri {
    fn id(&self) -> &Uri {
        self
    }
}

impl Identified for IdentifiedObject {
    fn id(&self) -> &Uri {
        &self.id
    }
}

impl Identified for IdentifiedTypedObject {
    fn id(&self) -> &Uri {
        &self.id
    }
}

impl Identified for IdOr<IdentifiedObject> {
    fn id(&self) -> &Uri {
        match self {
            Self::Id(id) => id,
            Self::NotId(o) => &o.id,
        }
    }
}
