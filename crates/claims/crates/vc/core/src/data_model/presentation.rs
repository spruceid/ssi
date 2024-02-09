use crate::{CredentialOrPresentation, VerifiableCredentialOrPresentation};
use iref::{Uri, UriBuf};

use super::Credential;

pub const VERIFIABLE_PRESENTATION_TYPE: &str = "VerifiablePresentation";

/// Presentation trait.
pub trait Presentation: CredentialOrPresentation {
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

    fn holders(&self) -> &[UriBuf] {
        &[]
    }

    /// Validates the presentation and all its credentials.
    ///
    /// Validation consists in verifying that the claims themselves are
    /// consistent and valid with regard to the verification environment.
    /// For instance, checking that a credential's expiration date is not in the
    /// past, or the issue date not in the future.
    ///
    /// Validation may fail even if the presentation proof is successfully
    /// verified.
    ///
    /// You do not need to call this method yourself when verifying a
    /// presentation. It is automatically called by
    /// [`ssi_claims_core::VerifiableWith::verify_with`].
    fn is_valid(&self) -> bool {
        self.verifiable_credentials()
            .iter()
            .all(Credential::is_valid)
    }
}

pub trait VerifiablePresentation: Presentation + VerifiableCredentialOrPresentation {}

impl<T: Presentation + VerifiableCredentialOrPresentation> VerifiablePresentation for T {}

pub struct PresentationTypes<'a> {
    base_type: bool,
    additional_types: std::slice::Iter<'a, String>,
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
