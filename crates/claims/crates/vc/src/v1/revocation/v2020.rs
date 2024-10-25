//! Revocation List 2020.
//!
//! See: <https://w3c-ccg.github.io/vc-status-rl-2020/>
use bitvec::prelude::Lsb0;
use bitvec::vec::BitVec;
use iref::UriBuf;
use serde::{Deserialize, Serialize};
use ssi_claims_core::VerificationParameters;
use ssi_data_integrity::AnyDataIntegrity;
use ssi_json_ld::REVOCATION_LIST_2020_V1_CONTEXT;
use ssi_verification_methods::{AnyMethod, VerificationMethodResolver};
use static_iref::iri;
use std::collections::BTreeMap;

use crate::{
    syntax::RequiredType,
    v1::{
        revocation::{load_resource, Reason, StatusCheckError},
        RequiredContext, SpecializedJsonCredential,
    },
};

use super::{
    CredentialStatus, EncodedList, List, RevocationListIndex, SetStatusError, StatusCheck,
    MIN_BITSTRING_LENGTH,
};
pub struct RevocationList2020Context;

impl RequiredContext for RevocationList2020Context {
    const CONTEXT_IRI: &'static iref::Iri = iri!("https://w3id.org/vc-revocation-list-2020/v1");
}

/// Credential Status object for use in a Verifiable Credential.
///
/// See: <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020status>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationList2020Status {
    /// URL for status information of the verifiable credential - but not the URL of the revocation
    /// list.
    pub id: UriBuf,

    /// Index of this credential's status in the revocation list credential
    pub revocation_list_index: RevocationListIndex,

    /// URL to a [RevocationList2020Credential]
    pub revocation_list_credential: UriBuf,
}
pub struct RevocationList2020CredentialType;

impl RequiredType for RevocationList2020CredentialType {
    const REQUIRED_TYPE: &'static str = "RevocationList2020Credential";
}

/// Verifiable Credential of type RevocationList2020Credential.
///
/// <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential>
pub type RevocationList2020Credential = SpecializedJsonCredential<
    RevocationList2020Subject,
    RevocationList2020Context,
    RevocationList2020CredentialType,
>;

/// [Credential subject](https://www.w3.org/TR/vc-data-model/#credential-subject) of a [RevocationList2020Credential]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum RevocationList2020Subject {
    RevocationList2020(RevocationList2020),
}

/// Credential subject of type RevocationList2020, expected to be used in a Verifiable Credential of type [RevocationList2020Credential]
/// <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential>
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct RevocationList2020 {
    pub encoded_list: EncodedList,

    #[serde(flatten)]
    pub more_properties: BTreeMap<String, json_syntax::Value>,
}

impl RevocationList2020 {
    /// Set the revocation status for a given index in the list.
    pub fn set_status(&mut self, index: usize, revoked: bool) -> Result<(), SetStatusError> {
        let mut list = super::List::try_from(&self.encoded_list)?;
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

impl CredentialStatus for RevocationList2020Status {
    /// Validate a credential's revocation status according to
    /// [Revocation List 2020][1].
    ///
    /// [1]: https://w3c-ccg.github.io/vc-status-rl-2020/#validate-algorithm
    async fn check(
        &self,
        credential: &AnyDataIntegrity<SpecializedJsonCredential>,
        resolver: &impl VerificationMethodResolver<Method = AnyMethod>,
    ) -> Result<StatusCheck, StatusCheckError> {
        use bitvec::prelude::*;

        // Check context.
        if !credential
            .context
            .contains_iri(REVOCATION_LIST_2020_V1_CONTEXT)
        {
            // TODO: support JSON-LD credentials defining the terms elsewhere.
            return Ok(StatusCheck::Invalid(Reason::MissingRequiredLdContext(
                REVOCATION_LIST_2020_V1_CONTEXT.to_owned(),
            )));
        }

        if self.id == self.revocation_list_credential {
            return Ok(StatusCheck::Invalid(Reason::StatusIdMatchesCredentialId(
                self.id.clone(),
            )));
        }

        // Check the revocation list URL before attempting to load it.
        // Revocation List 2020 does not specify an expected URL scheme (URI scheme), but
        // examples and test vectors use https.
        if self.revocation_list_credential.scheme().as_str() != "https" {
            return Ok(StatusCheck::Invalid(Reason::UnsupportedUriScheme(
                self.revocation_list_credential.scheme().to_owned(),
            )));
        }

        let credential_data = load_resource(&self.revocation_list_credential).await?;
        let revocation_list_credential = serde_json::from_slice::<
            AnyDataIntegrity<RevocationList2020Credential>,
        >(&credential_data)?;

        if credential.issuer.id() != revocation_list_credential.issuer.id() {
            return Ok(StatusCheck::Invalid(Reason::IssuerMismatch(
                credential.issuer.id().to_owned(),
                revocation_list_credential.issuer.id().to_owned(),
            )));
        }

        let params = VerificationParameters::from_resolver(resolver);
        let vc_result = revocation_list_credential.verify(&params).await?;

        if let Err(e) = vc_result {
            return Ok(StatusCheck::Invalid(Reason::CredentialVerification(e)));
        }

        if revocation_list_credential.id.as_deref()
            != Some(self.revocation_list_credential.as_uri())
        {
            return Ok(StatusCheck::Invalid(Reason::IdMismatch(
                credential.issuer.id().to_owned(),
                revocation_list_credential.issuer.id().to_owned(),
            )));
        }

        let revocation_list = match revocation_list_credential.credential_subjects.as_ref() {
            [RevocationList2020Subject::RevocationList2020(l)] => l,
            [] => return Ok(StatusCheck::Invalid(Reason::MissingCredentialSubject)),
            _ => return Ok(StatusCheck::Invalid(Reason::TooManyCredentialSubjects)),
        };

        let list = match List::try_from(&revocation_list.encoded_list) {
            Ok(list) => list,
            Err(e) => return Ok(StatusCheck::Invalid(Reason::DecodeListError(e))),
        };

        let credential_index = self.revocation_list_index.0;
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
