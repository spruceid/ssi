use iref::Uri;

/// Object that *may* contain an `id` property.
///
/// See: <https://www.w3.org/TR/vc-data-model-2.0/#identifiers>
pub trait MaybeIdentified {
    fn id(&self) -> Option<&Uri> {
        None
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
