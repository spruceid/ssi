use std::ops::{Deref, DerefMut};

use chrono::{DateTime, FixedOffset};
use iref::{Uri, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ExtractProof, Validate, VerifiableClaims};

use super::{value_or_array, Evidence, Issuer, RefreshService, Schema, Status, TermsOfUse};
use crate::SpecializedJsonCredential;

/// JSON Verifiable Credential.
///
/// The `P` parameter is the proof format type.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(bound(
    serialize = "P: serde::Serialize",
    deserialize = "P: serde::Deserialize<'de>"
))]
pub struct JsonVerifiableCredential<P = json_syntax::Value> {
    #[serde(flatten)]
    credential: SpecializedJsonCredential,

    /// Proofs.
    #[serde(rename = "proof")]
    #[serde(
        with = "value_or_array",
        default,
        skip_serializing_if = "Vec::is_empty"
    )]
    pub proofs: Vec<P>,
}

impl<P> Deref for JsonVerifiableCredential<P> {
    type Target = SpecializedJsonCredential;

    fn deref(&self) -> &Self::Target {
        &self.credential
    }
}

impl<P> DerefMut for JsonVerifiableCredential<P> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.credential
    }
}

impl<P> JsonVerifiableCredential<P> {
    pub fn new(
        id: Option<UriBuf>,
        issuer: Issuer,
        issuance_date: xsd_types::DateTime,
        credential_subjects: Vec<json_syntax::Value>,
        proofs: Vec<P>,
    ) -> Self {
        Self {
            credential: SpecializedJsonCredential::new(
                id,
                issuer,
                issuance_date,
                credential_subjects,
            ),
            proofs,
        }
    }
}

impl<P> Validate for JsonVerifiableCredential<P> {
    fn is_valid(&self) -> bool {
        crate::Credential::is_valid_credential(self)
    }
}

impl<P> crate::Credential for JsonVerifiableCredential<P> {
    type Subject = json_syntax::Value;
    type Issuer = Issuer;
    type Status = Status;
    type RefreshService = RefreshService;
    type TermsOfUse = TermsOfUse;
    type Evidence = Evidence;
    type Schema = Schema;

    fn id(&self) -> Option<&Uri> {
        self.credential.id.as_deref()
    }

    fn additional_types(&self) -> &[String] {
        self.credential.types.additional_types()
    }

    fn credential_subjects(&self) -> &[Self::Subject] {
        &self.credential.credential_subjects
    }

    fn issuer(&self) -> &Self::Issuer {
        &self.credential.issuer
    }

    fn issuance_date(&self) -> DateTime<FixedOffset> {
        self.credential.issuance_date.into()
    }

    fn expiration_date(&self) -> Option<DateTime<FixedOffset>> {
        self.credential.expiration_date.map(Into::into)
    }

    fn credential_status(&self) -> &[Self::Status] {
        &self.credential.credential_status
    }

    fn refresh_services(&self) -> &[Self::RefreshService] {
        &self.credential.refresh_services
    }

    fn terms_of_use(&self) -> &[Self::TermsOfUse] {
        &self.credential.terms_of_use
    }

    fn evidences(&self) -> &[Self::Evidence] {
        &self.credential.evidences
    }

    fn credential_schemas(&self) -> &[Self::Schema] {
        &self.credential.credential_schema
    }
}

impl<P> VerifiableClaims for JsonVerifiableCredential<P> {
    type Proof = Vec<P>;

    fn proof(&self) -> &Vec<P> {
        &self.proofs
    }
}

impl<P> ExtractProof for JsonVerifiableCredential<P> {
    type Proofless = SpecializedJsonCredential;

    fn extract_proof(self) -> (Self::Proofless, Vec<P>) {
        (self.credential, self.proofs)
    }
}
