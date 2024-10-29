//! Status List 2021.
//!
//! See: <https://www.w3.org/community/reports/credentials/CG-FINAL-vc-status-list-2021-20230102/>
use bitvec::prelude::Lsb0;
use bitvec::vec::BitVec;
use iref::UriBuf;
use serde::{Deserialize, Serialize};
use ssi_claims_core::VerificationParameters;
use ssi_data_integrity::AnyDataIntegrity;
use ssi_json_ld::STATUS_LIST_2021_V1_CONTEXT;
use ssi_verification_methods::{AnyMethod, VerificationMethodResolver};
use static_iref::iri;
use std::collections::BTreeMap;

use crate::{
    syntax::RequiredType,
    v1::{
        revocation::{load_resource, Reason},
        RequiredContext, SpecializedJsonCredential,
    },
};

use super::{
    CredentialStatus, EncodedList, List, NewEncodedListError, RevocationListIndex, SetStatusError,
    StatusCheck, StatusCheckError, MIN_BITSTRING_LENGTH,
};

pub struct StatusList2021Context;

impl RequiredContext for StatusList2021Context {
    const CONTEXT_IRI: &'static iref::Iri = iri!("https://w3id.org/vc/status-list/2021/v1");
}

/// Revocation List 2021 Status object, for use in a Verifiable Credential's credentialStatus
/// property.
/// <https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021entry>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StatusList2021Entry {
    /// URL for status information of the verifiable credential - but not the URL of the status
    /// list.
    pub id: UriBuf,

    /// Status purpose
    ///
    /// Defined in <https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021entry>
    /// and <https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021credential>
    ///
    /// It is allowed to be an arbitrary string, although specific values "revocation" and
    /// "suspension" are defined.
    pub status_purpose: String,

    /// Index of this credential's status in the status list credential
    pub status_list_index: RevocationListIndex,

    /// URL to a [StatusList2021Credential]
    pub status_list_credential: UriBuf,
}

/// [Credential subject](https://www.w3.org/TR/vc-data-model/#credential-subject) of a [StatusList2021Credential]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum StatusList2021Subject {
    StatusList2021(StatusList2021),
}

pub struct StatusList2021CredentialType;

impl RequiredType for StatusList2021CredentialType {
    const REQUIRED_TYPE: &'static str = "StatusList2021Credential";
}

/// Verifiable Credential of type RevocationList2020Credential.
///
/// <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential>
pub type StatusList2021Credential = SpecializedJsonCredential<
    StatusList2021Subject,
    StatusList2021Context,
    StatusList2021CredentialType,
>;

/// Credential subject of type StatusList2021, expected to be used in a Verifiable Credential of type [StatusList2021Credential](https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021credential)
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct StatusList2021 {
    pub encoded_list: EncodedList,

    #[serde(flatten)]
    pub more_properties: BTreeMap<String, json_syntax::Value>,
}

/// Error resulting from attempting to construct a [new StatusList2021](StatusList2021::new)
#[derive(Debug, thiserror::Error)]
pub enum NewStatusListError {
    #[error("Unable to encode list")]
    EncodedList(#[source] NewEncodedListError),
}

impl StatusList2021 {
    /// Construct a new empty [StatusList2021]
    pub fn new(len: usize) -> Result<Self, NewStatusListError> {
        Ok(StatusList2021 {
            encoded_list: EncodedList::new(len).map_err(NewStatusListError::EncodedList)?,
            more_properties: BTreeMap::new(),
        })
    }

    /// Set the revocation status for a given index in the list.
    // TODO: dedupe with RevocationList2020::set_status
    pub fn set_status(&mut self, index: usize, revoked: bool) -> Result<(), SetStatusError> {
        let mut list = List::try_from(&self.encoded_list)?;
        let bitstring_len = list.0.len() * 8;
        let mut bitstring = BitVec::<Lsb0, u8>::try_from_vec(list.0)
            .map_err(|_| SetStatusError::ListTooLarge(bitstring_len))?;

        if bitstring_len < MIN_BITSTRING_LENGTH {
            return Err(SetStatusError::ListTooSmall(
                bitstring_len,
                MIN_BITSTRING_LENGTH,
            ));
        }

        if let Some(mut bitref) = bitstring.get_mut(index) {
            *bitref = revoked;
        } else {
            return Err(SetStatusError::OutOfBounds(index, bitstring_len));
        }

        list.0 = bitstring.into_vec();
        self.encoded_list = EncodedList::try_from(&list)?;
        Ok(())
    }
}

impl CredentialStatus for StatusList2021Entry {
    /// Validate a credential's revocation status according to
    /// [Status List 2021][1].
    ///
    /// [1]: https://w3c-ccg.github.io/vc-status-list-2021/#validate-algorithm
    async fn check(
        &self,
        credential: &AnyDataIntegrity<SpecializedJsonCredential>,
        resolver: &impl VerificationMethodResolver<Method = AnyMethod>,
    ) -> Result<StatusCheck, StatusCheckError> {
        use bitvec::prelude::*;

        // Check context.
        if !credential.context.contains_iri(STATUS_LIST_2021_V1_CONTEXT) {
            // TODO: support JSON-LD credentials defining the terms elsewhere.
            return Ok(StatusCheck::Invalid(Reason::MissingRequiredLdContext(
                STATUS_LIST_2021_V1_CONTEXT.to_owned(),
            )));
        }

        if self.id == self.status_list_credential {
            return Ok(StatusCheck::Invalid(Reason::StatusIdMatchesCredentialId(
                self.id.clone(),
            )));
        }

        // Check the status list URL before attempting to load it.
        // Status List 2021 does not specify an expected URL scheme (URI scheme), but
        // examples and test vectors use https.
        if self.status_list_credential.scheme().as_str() != "https" {
            return Ok(StatusCheck::Invalid(Reason::UnsupportedUriScheme(
                self.status_list_credential.scheme().to_owned(),
            )));
        }

        let credential_data = load_resource(&self.status_list_credential).await?;
        let status_list_credential =
            serde_json::from_slice::<AnyDataIntegrity<StatusList2021Credential>>(&credential_data)?;

        if credential.issuer.id() != status_list_credential.issuer.id() {
            return Ok(StatusCheck::Invalid(Reason::IssuerMismatch(
                credential.issuer.id().to_owned(),
                status_list_credential.issuer.id().to_owned(),
            )));
        }

        let params = VerificationParameters::from_resolver(resolver);
        let vc_result = status_list_credential.verify(params).await?;

        if let Err(e) = vc_result {
            return Ok(StatusCheck::Invalid(Reason::CredentialVerification(e)));
        }

        if status_list_credential.id.as_deref() != Some(self.status_list_credential.as_uri()) {
            return Ok(StatusCheck::Invalid(Reason::IdMismatch(
                credential.issuer.id().to_owned(),
                status_list_credential.issuer.id().to_owned(),
            )));
        }

        let revocation_list = match status_list_credential.credential_subjects.as_ref() {
            [StatusList2021Subject::StatusList2021(l)] => l,
            [] => return Ok(StatusCheck::Invalid(Reason::MissingCredentialSubject)),
            _ => return Ok(StatusCheck::Invalid(Reason::TooManyCredentialSubjects)),
        };

        let list = match List::try_from(&revocation_list.encoded_list) {
            Ok(list) => list,
            Err(e) => return Ok(StatusCheck::Invalid(Reason::DecodeListError(e))),
        };

        let credential_index = self.status_list_index.0;
        let bitstring = match BitVec::<Lsb0, u8>::try_from_vec(list.0) {
            Ok(bitstring) => bitstring,
            Err(list) => return Err(StatusCheckError::RevocationListTooLarge(list.len())),
        };

        let revoked = match bitstring.get(credential_index) {
            Some(bitref) => *bitref,
            None => return Ok(StatusCheck::Invalid(Reason::InvalidRevocationListIndex)),
        };

        if revoked {
            return Ok(StatusCheck::Invalid(Reason::Revoked));
        }

        Ok(StatusCheck::Valid)
    }
}
