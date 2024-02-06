use iref::Uri;
use chrono::{DateTime, FixedOffset};
use crate::CredentialOrPresentation;

use super::{Issuer, CredentialStatus, RefreshService, TermsOfUse, Evidence, VerifiableCredentialOrPresentation};

pub const VERIFIABLE_CREDENTIAL_TYPE: &str = "VerifiableCredential";

/// Credential trait.
pub trait Credential: CredentialOrPresentation {
	/// Credential subject type.
	type Subject;

	/// Issuer type.
	type Issuer: ?Sized + Issuer;

	/// Credential status type.
	type Status: CredentialStatus;

	/// Refresh service.
	/// 
	/// See: <https://www.w3.org/TR/vc-data-model//#refreshing>
	type RefreshService: RefreshService;

	/// Terms of Use type.
	/// 
	/// Terms of use can be utilized by an issuer or a holder to communicate the
	/// terms under which a verifiable credential or verifiable presentation was
	/// issued.
	type TermsOfUse: TermsOfUse;

	/// Evidence type.
	/// 
	/// Can be included by an issuer to provide the verifier with additional
	/// supporting information in a verifiable credential.
	type Evidence: Evidence;

	/// Credential Schemas (Zero-Knowledge Proofs).
	/// 
	/// See: <https://www.w3.org/TR/vc-data-model//#zero-knowledge-proofs>
	type Schema;

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
		CredentialTypes {
			base_type: true,
			additional_types: self.additional_types().iter()
		}
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
	fn issuance_date(&self) -> DateTime<FixedOffset>;

	/// Expiration date.
	fn expiration_date(&self) -> Option<DateTime<FixedOffset>> {
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

	/// Evidences.
	/// 
	/// Can be included by an issuer to provide the verifier with additional
	/// supporting information in a verifiable credential.
	fn evidences(&self) -> &[Self::Evidence] {
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
	/// 
	/// You do not need to call this method yourself when verifying a
	/// credential. It is automatically called by
	/// [`ssi_claims_core::VerifiableWith::verify_with`].
	fn is_valid(&self) -> bool {
		let now = chrono::Utc::now();
		
		if self.issuance_date() > now {
			// Credential is issued in the future!
			return false
		}

		if let Some(t) = self.expiration_date() {
			if t < now {
				// Credential has expired.
				return false
			}
		}

		true
	}
}

pub trait VerifiableCredential: Credential + VerifiableCredentialOrPresentation {
	// ...
}

pub struct CredentialTypes<'a> {
	base_type: bool,
	additional_types: std::slice::Iter<'a, String>
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