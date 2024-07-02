use iref::Uri;
use ssi_claims_core::{ClaimsValidity, DateTimeProvider, InvalidClaims};
use xsd_types::DateTimeStamp;

use super::{InternationalString, RelatedResource};

pub use crate::v1::CredentialTypes;
use crate::{Identified, MaybeIdentified, Typed};

/// Verifiable Credential.
pub trait Credential: MaybeIdentified {
    /// Description type.
    type Description: InternationalString;

    /// Credential subject type.
    type Subject;

    /// Return type of the [`issuer`](Credential::issuer) method.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#issuer>
    type Issuer: Identified;

    type Status: MaybeIdentified + Typed;

    type Schema: Identified + Typed;

    type RelatedResource: RelatedResource;

    /// Refresh service.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#refreshing>
    type RefreshService: Typed;

    /// Terms of Use type.
    ///
    /// Terms of use can be utilized by an issuer or a holder to communicate the
    /// terms under which a verifiable credential or verifiable presentation was
    /// issued.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#terms-of-use>
    type TermsOfUse: MaybeIdentified + Typed;

    /// Evidence type.
    ///
    /// Can be included by an issuer to provide the verifier with additional
    /// supporting information in a verifiable credential.
    type Evidence: MaybeIdentified + Typed;

    /// Identifier.
    fn id(&self) -> Option<&Uri> {
        MaybeIdentified::id(self)
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

    /// Name of the credential.
    ///
    /// Ideally, the name of a credential is concise, human-readable, and could
    /// enable an individual to quickly differentiate one credential from any
    /// other credentials that they might hold.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions>
    fn name(&self) -> Option<&str> {
        None
    }

    /// Details about the credential.
    ///
    /// Ideally, the description of a credential is no more than a few sentences
    /// in length and conveys enough information about the credential to remind
    /// an individual of its contents without their having to look through the
    /// entirety of the claims.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#names-and-descriptions>
    fn description(&self) -> Option<&Self::Description> {
        None
    }

    /// Credential subject.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#credential-subject>
    fn credential_subjects(&self) -> &[Self::Subject] {
        &[]
    }

    /// Issuer.
    ///
    /// It is *recommended* that the URL be one which, if dereferenced, results
    /// in a controller document, as defined in [VC-DATA-INTEGRITY] or
    /// [VC-JOSE-COSE], about the issuer that can be used to verify the
    /// information expressed in the credential.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#issuer>
    ///
    /// [VC-DATA-INTEGRITY]: <https://www.w3.org/TR/vc-data-integrity/>
    /// [VC-JOSE-COSE]: <https://www.w3.org/TR/vc-jose-cose/>
    fn issuer(&self) -> &Self::Issuer;

    /// Date and time the credential becomes valid.
    ///
    /// Could be a date and time in the future or in the past.
    /// Note that this value represents the earliest point in time at which the
    /// information associated with the
    /// [`credential_subject`](Credential::credential_subjects) property becomes
    /// valid.
    ///
    /// If a [`valid_until`](Credential::valid_until) value also exists, the
    /// [`valid_from`](Credential::valid_from) value *must* express a datetime
    /// that is temporally the same or earlier than the datetime expressed by
    /// the `valid_until` value.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#validity-period>
    fn valid_from(&self) -> Option<DateTimeStamp> {
        None
    }

    /// Date and time the credential ceases to be valid.
    ///
    /// Could be a date and time in the past or in the future.
    /// Note that this value represents the latest point in time at which the
    /// information associated with the
    /// [`credential_subject`](Credential::credential_subjects) property is
    /// valid.
    ///
    /// If a [`valid_from`](Credential::valid_from) value also exists, the
    /// [`valid_until`](Credential::valid_until) value *must* express a datetime
    /// that is temporally the same or later than the datetime expressed by the
    /// `valid_from` value.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#validity-period>
    fn valid_until(&self) -> Option<DateTimeStamp> {
        None
    }

    /// Credential status.
    ///
    /// Helps discover information related to the status of the verifiable
    /// credential, such as whether it is suspended or revoked.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#status>
    fn credential_status(&self) -> &[Self::Status] {
        &[]
    }

    /// Data schemas.
    ///
    /// Data schemas are useful when enforcing a specific structure on a given
    /// collection of data.
    ///
    /// See: <https://www.w3.org/TR/vc-data-model-2.0/#data-schemas>
    fn credential_schemas(&self) -> &[Self::Schema] {
        &[]
    }

    /// Integrity metadata about each resource referenced by the verifiable
    /// credential.
    fn related_resources(&self) -> &[Self::RelatedResource] {
        &[]
    }

    fn refresh_services(&self) -> &[Self::RefreshService] {
        &[]
    }

    fn terms_of_use(&self) -> &[Self::TermsOfUse] {
        &[]
    }

    fn evidence(&self) -> &[Self::Evidence] {
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

        if let Some(valid_from) = self.valid_from().map(Into::into) {
            if valid_from > now {
                // Credential is issued in the future!
                return Err(InvalidClaims::Premature { now, valid_from });
            }
        }

        if let Some(valid_until) = self.valid_until().map(Into::into) {
            if now >= valid_until {
                // Credential has expired.
                return Err(InvalidClaims::Expired { now, valid_until });
            }
        }

        Ok(())
    }
}
