use crate::syntax::{IdentifiedTypedObject, MaybeIdentifiedTypedObject, TypedObject};

pub trait Typed {
    fn types(&self) -> &[String];
}

impl Typed for std::convert::Infallible {
    fn types(&self) -> &[String] {
        unreachable!()
    }
}

impl Typed for IdentifiedTypedObject {
    fn types(&self) -> &[String] {
        &self.types
    }
}

impl Typed for MaybeIdentifiedTypedObject {
    fn types(&self) -> &[String] {
        &self.types
    }
}

impl Typed for TypedObject {
    fn types(&self) -> &[String] {
        &self.types
    }
}
