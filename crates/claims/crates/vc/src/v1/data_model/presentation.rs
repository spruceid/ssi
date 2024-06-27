use iref::Uri;
use ssi_claims_core::VerifiableClaims;

use crate::v1::syntax::VERIFIABLE_PRESENTATION_TYPE;

use super::Credential;

/// Presentation trait.
pub trait Presentation {
    /// Verifiable credential type.
    type Credential: Credential;

    /// Identifier.
    fn id(&self) -> Option<&Uri> {
        None
    }

    /// Types, without the `VerifiablePresentation` type.
    fn additional_types(&self) -> &[String] {
        &[]
    }

    fn types(&self) -> PresentationTypes {
        PresentationTypes {
            base_type: true,
            additional_types: self.additional_types().iter(),
        }
    }

    fn verifiable_credentials(&self) -> &[Self::Credential] {
        &[]
    }

    fn holder(&self) -> Option<&Uri> {
        None
    }
}

pub trait VerifiablePresentation: Presentation + VerifiableClaims {}

impl<T: Presentation + VerifiableClaims> VerifiablePresentation for T {}

pub struct PresentationTypes<'a> {
    base_type: bool,
    additional_types: std::slice::Iter<'a, String>,
}

impl<'a> PresentationTypes<'a> {
    pub fn from_additional_types(additional_types: &'a [String]) -> Self {
        Self {
            base_type: true,
            additional_types: additional_types.iter(),
        }
    }
}

impl<'a> Iterator for PresentationTypes<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.base_type {
            self.base_type = false;
            Some(VERIFIABLE_PRESENTATION_TYPE)
        } else {
            self.additional_types.next().map(String::as_str)
        }
    }
}
