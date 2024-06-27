use iref::Uri;

use super::Credential;

pub use crate::v1::PresentationTypes;
use crate::{Identified, MaybeIdentified};

/// Verifiable Presentation.
pub trait Presentation: MaybeIdentified {
    /// Verifiable credential type.
    type Credential: Credential;

    /// Holder.
    type Holder: Identified;

    /// Identifier.
    fn id(&self) -> Option<&Uri> {
        MaybeIdentified::id(self)
    }

    /// Types, without the `VerifiablePresentation` type.
    fn additional_types(&self) -> &[String] {
        &[]
    }

    fn types(&self) -> PresentationTypes {
        PresentationTypes::from_additional_types(self.additional_types())
    }

    fn verifiable_credentials(&self) -> &[Self::Credential] {
        &[]
    }

    fn holders(&self) -> &[Self::Holder] {
        &[]
    }
}
