use iref::{Iri, Uri};
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, InvalidClaims, VerifiableClaims};
use ssi_data_integrity::{CryptographicSuite, DataIntegrity};
use static_iref::iri;
use xsd_types::DateTime;

use crate::{v1::syntax::VERIFIABLE_CREDENTIAL_TYPE, Identified, MaybeIdentified, Typed};

pub const VERIFIABLE_CREDENTIAL: &Iri =
    iri!("https://www.w3.org/2018/credentials#VerifiableCredential");

/// Credential trait.
pub trait Credential {
    /// Credential subject type.
    type Subject;

    /// Issuer type.
    type Issuer: ?Sized + Identified;

    /// Credential status type.
    type Status: Identified + Typed;

    /// Refresh service.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model//#refreshing>
    type RefreshService: Identified + Typed;

    /// Terms of Use type.
    ///
    /// Terms of use can be utilized by an issuer or a holder to communicate the
    /// terms under which a verifiable credential or verifiable presentation was
    /// issued.
    type TermsOfUse: MaybeIdentified + Typed;

    /// Evidence type.
    ///
    /// Can be included by an issuer to provide the verifier with additional
    /// supporting information in a verifiable credential.
    type Evidence: MaybeIdentified + Typed;

    /// Credential Schemas (Zero-Knowledge Proofs).
    ///
    /// See: <https://www.w3.org/TR/vc-data-model//#zero-knowledge-proofs>
    type Schema: Identified + Typed;

    /// Identifier.
    fn id(&self) -> Option<&Uri> {
        None
    }

    /// Types that are **not** `VerifiableCredential`.
    ///
    /// Since the `VerifiableCredential` type is *required*, it is omitted from
    /// the value returned by this function. If you need to iterate over
    /// all the credential types, including `VerifiableCredential`, use the
    /// [`Self::types`] method.
    fn additional_types(&self) -> &[String] {
        &[]
    }

    fn types(&self) -> CredentialTypes {
        CredentialTypes::from_additional_types(self.additional_types())
    }

    /// Credential subject.
    fn credential_subjects(&self) -> &[Self::Subject] {
        &[]
    }

    /// Issuer.
    ///
    /// This property is *required* for the credential to be *verifiable*.
    fn issuer(&self) -> &Self::Issuer;

    /// Issuance date.
    ///
    /// This property is *required* for the credential to be *verifiable*.
    fn issuance_date(&self) -> Option<DateTime>;

    /// Expiration date.
    fn expiration_date(&self) -> Option<DateTime> {
        None
    }

    /// Credential status.
    ///
    /// Used for discovery of information about the current status of a
    /// verifiable credential, such as whether it is suspended or revoked.
    fn credential_status(&self) -> &[Self::Status] {
        &[]
    }

    /// Refresh services.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model//#refreshing>
    fn refresh_services(&self) -> &[Self::RefreshService] {
        &[]
    }

    /// Terms of Use.
    ///
    /// Terms of use can be utilized by an issuer or a holder to communicate the
    /// terms under which a verifiable credential or verifiable presentation was
    /// issued.
    fn terms_of_use(&self) -> &[Self::TermsOfUse] {
        &[]
    }

    /// Evidence.
    ///
    /// Can be included by an issuer to provide the verifier with additional
    /// supporting information in a verifiable credential.
    fn evidence(&self) -> &[Self::Evidence] {
        &[]
    }

    /// Credential Schemas (Zero-Knowledge Proofs).
    ///
    /// See: <https://www.w3.org/TR/vc-data-model//#zero-knowledge-proofs>
    fn credential_schemas(&self) -> &[Self::Schema] {
        &[]
    }

    /// Validates the credential.
    ///
    /// Validation consists in verifying that the claims themselves are
    /// consistent and valid with regard to the verification environment.
    /// For instance, checking that a credential's expiration date is not in the
    /// past, or the issue date not in the future.
    ///
    /// Validation may fail even if the credential proof is successfully
    /// verified.
    fn validate_credential<E>(&self, env: &E) -> ClaimsValidity
    where
        E: DateTimeProvider,
    {
        let now = env.date_time();

        let issuance_date = self
            .issuance_date()
            .ok_or(InvalidClaims::MissingIssuanceDate)?;

        let valid_from = issuance_date.earliest().to_utc();
        if valid_from > now {
            // Credential is issued in the future!
            return Err(InvalidClaims::Premature { now, valid_from });
        }

        if let Some(t) = self.expiration_date() {
            let valid_until = t.latest().to_utc();
            if now >= valid_until {
                // Credential has expired.
                return Err(InvalidClaims::Expired { now, valid_until });
            }
        }

        Ok(())
    }
}

pub trait VerifiableCredential: Credential + VerifiableClaims {}

impl<T: Credential + VerifiableClaims> VerifiableCredential for T {}

impl<T: Credential, S: CryptographicSuite> Credential for DataIntegrity<T, S> {
    type Subject = T::Subject;
    type Issuer = T::Issuer;
    type Status = T::Status;
    type RefreshService = T::RefreshService;
    type TermsOfUse = T::TermsOfUse;
    type Evidence = T::Evidence;
    type Schema = T::Schema;

    fn id(&self) -> Option<&Uri> {
        T::id(&self.claims)
    }

    fn additional_types(&self) -> &[String] {
        T::additional_types(&self.claims)
    }

    fn credential_subjects(&self) -> &[Self::Subject] {
        T::credential_subjects(&self.claims)
    }

    fn issuer(&self) -> &Self::Issuer {
        T::issuer(&self.claims)
    }

    fn issuance_date(&self) -> Option<DateTime> {
        T::issuance_date(&self.claims)
    }

    fn expiration_date(&self) -> Option<DateTime> {
        T::expiration_date(&self.claims)
    }

    fn credential_status(&self) -> &[Self::Status] {
        T::credential_status(&self.claims)
    }

    fn refresh_services(&self) -> &[Self::RefreshService] {
        T::refresh_services(&self.claims)
    }

    fn terms_of_use(&self) -> &[Self::TermsOfUse] {
        T::terms_of_use(&self.claims)
    }

    fn evidence(&self) -> &[Self::Evidence] {
        T::evidence(&self.claims)
    }

    fn credential_schemas(&self) -> &[Self::Schema] {
        T::credential_schemas(&self.claims)
    }
}

pub struct CredentialTypes<'a> {
    base_type: bool,
    additional_types: std::slice::Iter<'a, String>,
}

impl<'a> CredentialTypes<'a> {
    pub fn from_additional_types(additional_types: &'a [String]) -> Self {
        Self {
            base_type: true,
            additional_types: additional_types.iter(),
        }
    }
}

impl<'a> Iterator for CredentialTypes<'a> {
    type Item = &'a str;

    fn next(&mut self) -> Option<Self::Item> {
        if self.base_type {
            self.base_type = false;
            Some(VERIFIABLE_CREDENTIAL_TYPE)
        } else {
            self.additional_types.next().map(String::as_str)
        }
    }
}
