use crate::{Credential, CredentialStatus, Issuer};
use async_trait::async_trait;
use bitvec::prelude::Lsb0;
use bitvec::slice::BitSlice;
use bitvec::vec::BitVec;
use core::convert::TryFrom;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use ssi_core::one_or_many::OneOrMany;
use ssi_core::uri::URI;
use ssi_dids::did_resolve::DIDResolver;
use ssi_json_ld::{
    ContextLoader, CREDENTIALS_STATUS_V1_CONTEXT, REVOCATION_LIST_2020_V1_CONTEXT,
    STATUS_LIST_2021_V1_CONTEXT,
};
use ssi_ldp::{StatusCheckEntry, VerificationResult};
use thiserror::Error;

#[allow(clippy::upper_case_acronyms)]
type URL = String;

/// Minimum length of a revocation list bitstring
/// <https://w3c-ccg.github.io/vc-status-rl-2020/#revocation-bitstring-length>
pub const MIN_BITSTRING_LENGTH: usize = 131072;

/// Maximum size of a revocation list credential loaded using [`load_credential`].
pub const MAX_RESPONSE_LENGTH: usize = 2097152; // 2MB

const EMPTY_RLIST: &str = "H4sIAAAAAAAA_-3AMQEAAADCoPVPbQwfKAAAAAAAAAAAAAAAAAAAAOBthtJUqwBAAAA";

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Credential Status object for use in a Verifiable Credential.
/// <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020status>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationList2020Status {
    /// URL for status information of the verifiable credential - but not the URL of the revocation
    /// list.
    pub id: URI,
    /// Index of this credential's status in the revocation list credential
    pub revocation_list_index: RevocationListIndex,
    /// URL to a [RevocationList2020Credential]
    pub revocation_list_credential: URL,
}

/// Revocation List 2021 Status object, for use in a Verifiable Credential's credentialStatus
/// property.
/// <https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021entry>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StatusList2021Entry {
    /// URL for status information of the verifiable credential - but not the URL of the status
    /// list.
    pub id: URI,
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
    pub status_list_credential: URL,
}

/// Bitstring Status List status object, for use in a Verifiable Credential's
/// credentialStatus property.
/// <https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListEntry {
    /// Optional URL for status information of the verifiable credential - but not the URL of the
    /// status list.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    /// Status purpose.
    pub status_purpose: String,
    /// Index of this credential's status in the status list credential.
    pub status_list_index: RevocationListIndex,
    /// URL to a [BitstringStatusListCredential].
    pub status_list_credential: URL,
    /// Size of the status entry in bits. If omitted, the status size is 1.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<Vec<BitstringStatusMessage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_reference: Option<OneOrMany<URL>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusMessage {
    pub status: String,
    pub message: String,
    #[serde(flatten)]
    pub more_properties: Value,
}

/// Integer identifying a bit position of the revocation status of a verifiable credential in a
/// revocation list, e.g. in a [RevocationList2020].
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct RevocationListIndex(usize);

/// Verifiable Credential of type RevocationList2020Credential.
/// <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RevocationList2020Credential {
    pub id: URI,
    pub issuer: Issuer,
    pub credential_subject: RevocationList2020Subject,
    #[serde(flatten)]
    pub more_properties: Value,
}

/// [Credential subject](https://www.w3.org/TR/vc-data-model/#credential-subject) of a [RevocationList2020Credential]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum RevocationList2020Subject {
    RevocationList2020(RevocationList2020),
}

/// [Credential subject](https://www.w3.org/TR/vc-data-model/#credential-subject) of a [StatusList2021Credential]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum StatusList2021Subject {
    StatusList2021(StatusList2021),
}

/// [Credential subject](https://www.w3.org/TR/vc-data-model-2.0/#credential-subject)
/// of a [BitstringStatusListCredential].
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "type")]
pub enum BitstringStatusListSubject {
    BitstringStatusList(BitstringStatusList),
}

/// Verifiable Credential of type StatusList2021Credential.
/// <https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021credential>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct StatusList2021Credential {
    pub id: URI,
    pub issuer: Issuer,
    pub credential_subject: StatusList2021Subject,
    #[serde(flatten)]
    pub more_properties: Value,
}

/// Verifiable Credential of type BitstringStatusListCredential.
/// <https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistcredential>
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListCredential {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<URI>,
    pub issuer: Issuer,
    pub credential_subject: BitstringStatusListSubject,
    #[serde(flatten)]
    pub more_properties: Value,
}

/// Credential subject of type RevocationList2020, expected to be used in a Verifiable Credential of type [RevocationList2020Credential]
/// <https://w3c-ccg.github.io/vc-status-rl-2020/#revocationlist2020credential>
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct RevocationList2020 {
    pub encoded_list: EncodedList,
    #[serde(flatten)]
    pub more_properties: Value,
}

/// Credential subject of type StatusList2021, expected to be used in a Verifiable Credential of type [StatusList2021Credential](https://w3c-ccg.github.io/vc-status-list-2021/#statuslist2021credential)
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct StatusList2021 {
    pub encoded_list: EncodedList,
    #[serde(flatten)]
    pub more_properties: Value,
}

/// Credential subject of type BitstringStatusList, expected to be used in a Verifiable Credential
/// of type [BitstringStatusListCredential](https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistcredential).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusList {
    pub status_purpose: OneOrMany<String>,
    pub encoded_list: BitstringStatusListEncodedList,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_size: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_message: Option<Vec<BitstringStatusMessage>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status_reference: Option<OneOrMany<URL>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u64>,
    #[serde(flatten)]
    pub more_properties: Value,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EncodedList(pub String);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct BitstringStatusListEncodedList(pub String);

/// A decoded [revocation list][EncodedList].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct List(pub Vec<u8>);

impl TryFrom<String> for RevocationListIndex {
    type Error = std::num::ParseIntError;
    fn try_from(string: String) -> Result<Self, Self::Error> {
        Ok(Self(string.parse()?))
    }
}

impl From<RevocationListIndex> for String {
    fn from(idx: RevocationListIndex) -> String {
        idx.0.to_string()
    }
}

#[derive(Error, Debug)]
pub enum SetStatusError {
    #[error("Encode list: {0}")]
    Encode(#[from] EncodeListError),
    #[error("Decode list: {0}")]
    Decode(#[from] DecodeListError),
    #[error("Out of bounds: bitstring index {0} but length is {1}")]
    OutOfBounds(usize, usize),
    #[error("Revocation list bitstring is too large for BitVec: {0}")]
    ListTooLarge(usize),
    #[error("Revocation list bitstring is too small: {0}. Minimum: {1}")]
    ListTooSmall(usize, usize),
}

impl RevocationList2020 {
    /// Set the revocation status for a given index in the list.
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

/// Error resulting from attempting to construct a [new StatusList2021](StatusList2021::new)
#[derive(Error, Debug)]
pub enum NewStatusListError {
    #[error("Unable to encode list")]
    EncodedList(#[source] NewEncodedListError),
}

impl StatusList2021 {
    /// Construct a new empty [StatusList2021]
    pub fn new(len: usize) -> Result<Self, NewStatusListError> {
        Ok(StatusList2021 {
            encoded_list: EncodedList::new(len).map_err(NewStatusListError::EncodedList)?,
            more_properties: serde_json::Value::Null,
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

impl BitstringStatusList {
    /// Construct a new empty [BitstringStatusList] for the given status purpose.
    pub fn new(len: usize, status_purpose: impl Into<String>) -> Result<Self, NewStatusListError> {
        Ok(BitstringStatusList {
            status_purpose: OneOrMany::One(status_purpose.into()),
            encoded_list: BitstringStatusListEncodedList::new(len)
                .map_err(NewStatusListError::EncodedList)?,
            status_size: None,
            status_message: None,
            status_reference: None,
            ttl: None,
            more_properties: serde_json::Value::Null,
        })
    }

    /// Set the status for a given index in the list.
    pub fn set_status(&mut self, index: usize, status: bool) -> Result<(), SetStatusError> {
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
            *bitref = status;
        } else {
            return Err(SetStatusError::OutOfBounds(index, bitstring_len));
        }
        list.0 = bitstring.into_vec();
        self.encoded_list = BitstringStatusListEncodedList::try_from(&list)?;
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ListIterDecodeError {
    #[error("Unable to reference indexes: {0}")]
    BitSpan(#[from] bitvec::ptr::BitSpanError<u8>),
    #[error("Revocation list bitstring is too small: {0}. Minimum: {1}")]
    ListTooSmall(usize, usize),
}

impl List {
    /// Get an array of indices in the revocation list for credentials that are revoked.
    pub fn iter_revoked_indexes(
        &self,
    ) -> Result<bitvec::slice::IterOnes<Lsb0, u8>, ListIterDecodeError> {
        let bitstring = BitSlice::<Lsb0, u8>::from_slice(&self.0[..])?;
        if bitstring.len() < MIN_BITSTRING_LENGTH {
            return Err(ListIterDecodeError::ListTooSmall(
                bitstring.len(),
                MIN_BITSTRING_LENGTH,
            ));
        }
        Ok(bitstring.iter_ones())
    }
}

#[derive(Error, Debug)]
pub enum DecodeListError {
    #[error("Base64url: {0}")]
    Build(#[from] base64::DecodeError),
    #[error("Decompression: {0}")]
    Decompress(#[from] std::io::Error),
    #[error("Invalid multibase encoding; expected base64url-no-pad prefix 'u'")]
    InvalidMultibasePrefix,
}

#[derive(Error, Debug)]
pub enum EncodeListError {
    #[error("Compression: {0}")]
    Compress(#[from] std::io::Error),
}

impl Default for EncodedList {
    /// Generate a 16KB list of zeros.
    fn default() -> Self {
        Self(EMPTY_RLIST.to_string())
    }
}

impl Default for BitstringStatusListEncodedList {
    /// Generate a 16KB list of zeros as multibase base64url-no-pad.
    fn default() -> Self {
        Self(format!("u{}", EMPTY_RLIST))
    }
}

/// Error resulting from attempting to construct a [new EncodedList](EncodedList::new)
#[derive(Error, Debug)]
pub enum NewEncodedListError {
    #[error("Length is not a multiple of 8: {0}")]
    LengthMultiple8(usize),
    #[error("Unable to encode list")]
    Encode(#[source] EncodeListError),
}

impl EncodedList {
    /// Construct a new empty [EncodedList] of a given bit length.
    ///
    /// Given length must be a multiple of 8.
    pub fn new(bit_len: usize) -> Result<Self, NewEncodedListError> {
        if bit_len % 8 != 0 {
            return Err(NewEncodedListError::LengthMultiple8(bit_len));
        }
        let byte_len = bit_len / 8;
        let vec: Vec<u8> = vec![0; byte_len];
        let list = List(vec);
        EncodedList::try_from(&list).map_err(NewEncodedListError::Encode)
    }
}

impl BitstringStatusListEncodedList {
    /// Construct a new empty [BitstringStatusListEncodedList] of a given bit length.
    ///
    /// Given length must be a multiple of 8.
    pub fn new(bit_len: usize) -> Result<Self, NewEncodedListError> {
        if bit_len % 8 != 0 {
            return Err(NewEncodedListError::LengthMultiple8(bit_len));
        }
        let byte_len = bit_len / 8;
        let vec: Vec<u8> = vec![0; byte_len];
        let list = List(vec);
        BitstringStatusListEncodedList::try_from(&list).map_err(NewEncodedListError::Encode)
    }
}

fn decode_base64url_gzip(string: &str) -> Result<List, DecodeListError> {
    let bytes = base64::decode_config(string, base64::URL_SAFE)?;
    let mut data = Vec::new();
    use flate2::bufread::GzDecoder;
    use std::io::Read;
    GzDecoder::new(bytes.as_slice()).read_to_end(&mut data)?;
    Ok(List(data))
}

fn encode_base64url_gzip(list: &List) -> Result<String, EncodeListError> {
    use flate2::{write::GzEncoder, Compression};
    use std::io::Write;
    let mut e = GzEncoder::new(Vec::new(), Compression::default());
    e.write_all(&list.0)?;
    let bytes = e.finish()?;
    Ok(base64::encode_config(bytes, base64::URL_SAFE_NO_PAD))
}

impl TryFrom<&EncodedList> for List {
    type Error = DecodeListError;
    fn try_from(encoded_list: &EncodedList) -> Result<Self, Self::Error> {
        decode_base64url_gzip(&encoded_list.0)
        // TODO: streaming decode the revocation list, for less memory use for large bitvecs.
    }
}

impl TryFrom<&List> for EncodedList {
    type Error = EncodeListError;
    fn try_from(list: &List) -> Result<Self, Self::Error> {
        Ok(EncodedList(encode_base64url_gzip(list)?))
    }
}

impl TryFrom<&BitstringStatusListEncodedList> for List {
    type Error = DecodeListError;
    fn try_from(encoded_list: &BitstringStatusListEncodedList) -> Result<Self, Self::Error> {
        let string = encoded_list
            .0
            .strip_prefix('u')
            .ok_or(DecodeListError::InvalidMultibasePrefix)?;
        decode_base64url_gzip(string)
    }
}

impl TryFrom<&List> for BitstringStatusListEncodedList {
    type Error = EncodeListError;
    fn try_from(list: &List) -> Result<Self, Self::Error> {
        Ok(BitstringStatusListEncodedList(format!(
            "u{}",
            encode_base64url_gzip(list)?
        )))
    }
}

fn has_bitstring_status_list_context(credential: &Credential) -> bool {
    credential.context.contains_uri(crate::DEFAULT_CONTEXT_V2)
        || credential
            .context
            .contains_uri(CREDENTIALS_STATUS_V1_CONTEXT.into_str())
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl CredentialStatus for RevocationList2020Status {
    /// Validate a credential's revocation status according to [Revocation List 2020](https://w3c-ccg.github.io/vc-status-rl-2020/#validate-algorithm).
    async fn check(
        &self,
        credential: &Credential,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        let mut result = VerificationResult::new();
        // TODO: prefix errors or change return type
        let issuer_id = match &credential.issuer {
            Some(issuer) => issuer.get_id().clone(),
            None => {
                return result.with_error("Credential is missing issuer".to_string());
            }
        };
        if !credential
            .context
            .contains_uri(REVOCATION_LIST_2020_V1_CONTEXT.into_str())
        {
            // TODO: support JSON-LD credentials defining the terms elsewhere.
            return result.with_error(format!(
                "Missing expected context URI {} for credential using RevocationList2020",
                REVOCATION_LIST_2020_V1_CONTEXT
            ));
        }
        if self.id == URI::String(self.revocation_list_credential.clone()) {
            return result.with_error(format!(
                "Expected revocationListCredential to be different from status id: {}",
                self.id
            ));
        }
        // Check the revocation list URL before attempting to load it.
        // Revocation List 2020 does not specify an expected URL scheme (URI scheme), but
        // examples and test vectors use https.
        match self.revocation_list_credential.split_once(':') {
            Some(("https", _)) => (),
            // TODO: an option to allow HTTP?
            // TODO: load from DID URLs?
            Some((_scheme, _)) => return result.with_error(format!("Invalid schema: {}", self.id)),
            _ => return result.with_error(format!("Invalid rsrc: {}", self.id)),
        }
        let revocation_list_credential =
            match load_credential(&self.revocation_list_credential).await {
                Ok(credential) => credential,
                Err(e) => {
                    return result
                        .with_error(format!("Unable to fetch revocation list credential: {}", e));
                }
            };
        let list_issuer_id = match &revocation_list_credential.issuer {
            Some(issuer) => issuer.get_id().clone(),
            None => {
                return result
                    .with_error("Revocation list credential is missing issuer".to_string());
            }
        };
        /* if issuer_id != list_issuer_id {
            return result.with_error(format!(
                "Revocation list issuer mismatch. Credential: {}, Revocation list: {}",
                issuer_id, list_issuer_id
            ));
        } */

        if let Err(e) = revocation_list_credential.validate() {
            return result.with_error(format!("Invalid list credential: {}", e));
        }
        let vc_result = revocation_list_credential
            .verify(None, resolver, context_loader)
            .await;
        for warning in vc_result.warnings {
            result
                .warnings
                .push(format!("Revocation list: {}", warning));
        }
        for error in vc_result.errors {
            result.errors.push(format!("Revocation list: {}", error));
        }
        if !result.errors.is_empty() {
            return result;
        }
        // Note: vc_result.checks is not checked here. It is assumed that default checks passed.

        let revocation_list_credential =
            match RevocationList2020Credential::try_from(revocation_list_credential) {
                Ok(credential) => credential,
                Err(e) => {
                    return result
                        .with_error(format!("Unable to parse revocation list credential: {}", e));
                }
            };
        if revocation_list_credential.id != URI::String(self.revocation_list_credential.to_string())
        {
            return result.with_error(format!(
                "Revocation list credential id mismatch. revocationListCredential: {}, id: {}",
                self.revocation_list_credential, revocation_list_credential.id
            ));
        }
        let RevocationList2020Subject::RevocationList2020(revocation_list) =
            revocation_list_credential.credential_subject;

        let list = match List::try_from(&revocation_list.encoded_list) {
            Ok(list) => list,
            Err(e) => return result.with_error(format!("Unable to decode revocation list: {}", e)),
        };
        let credential_index = self.revocation_list_index.0;
        use bitvec::prelude::*;
        let bitstring = match BitVec::<Lsb0, u8>::try_from_vec(list.0) {
            Ok(bitstring) => bitstring,
            Err(list) => {
                return result.with_error(format!(
                    "Revocation list is too large for bitvec: {}",
                    list.len()
                ))
            }
        };
        let revoked = match bitstring.get(credential_index) {
            Some(bitref) => *bitref,
            None => {
                return result
                    .with_error("Credential index in revocation list is invalid.".to_string());
            }
        };

        // Structured outcome. RevocationList2020 doesn't carry a
        // status_purpose field, so we synthesize "revocation" — that's
        // the only purpose this entry type ever expressed.
        result.status.push(StatusCheckEntry {
            entry_type: "RevocationList2020Status".to_string(),
            status_purpose: "revocation".to_string(),
            is_set: revoked,
            status_list_credential: Some(self.revocation_list_credential.clone()),
            status_list_index: Some(self.revocation_list_index.0.to_string()),
        });

        if revoked {
            return result.with_error("Credential is revoked.".to_string());
        }
        result
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl CredentialStatus for StatusList2021Entry {
    /// Validate a credential's revocation status according to [Status List 2021](https://w3c-ccg.github.io/vc-status-list-2021/#validate-algorithm).
    async fn check(
        &self,
        credential: &Credential,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        let mut result = VerificationResult::new();
        // TODO: prefix errors or change return type
        let issuer_id = match &credential.issuer {
            Some(issuer) => issuer.get_id().clone(),
            None => {
                return result.with_error("Credential is missing issuer".to_string());
            }
        };
        if !credential
            .context
            .contains_uri(STATUS_LIST_2021_V1_CONTEXT.into_str())
        {
            // TODO: support JSON-LD credentials defining the terms elsewhere.
            return result.with_error(format!(
                "Missing expected context URI {} for credential using StatusList2021",
                STATUS_LIST_2021_V1_CONTEXT
            ));
        }
        if self.id == URI::String(self.status_list_credential.clone()) {
            return result.with_error(format!(
                "Expected statusListCredential to be different from status id: {}",
                self.id
            ));
        }
        // Check the status list URL before attempting to load it.
        // Status List 2021 does not specify an expected URL scheme (URI scheme), but
        // examples and test vectors use https.
        match self.status_list_credential.split_once(':') {
            Some(("https", _)) => (),
            Some(("http", _)) => (),
            // TODO: an option to allow HTTP?
            // TODO: load from DID URLs?
            Some((_scheme, _)) => return result.with_error(format!("Invalid schema: {}", self.id)),
            _ => return result.with_error(format!("Invalid rsrc: {}", self.id)),
        }
        let status_list_credential = match load_credential(&self.status_list_credential).await {
            Ok(credential) => credential,
            Err(e) => {
                return result.with_error(format!("Unable to fetch status list credential: {}", e));
            }
        };
        let list_issuer_id = match &status_list_credential.issuer {
            Some(issuer) => issuer.get_id().clone(),
            None => {
                return result.with_error("Status list credential is missing issuer".to_string());
            }
        };
        /* if issuer_id != list_issuer_id {
            return result.with_error(format!(
                "Status list issuer mismatch. Credential: {}, Status list: {}",
                issuer_id, list_issuer_id
            ));
        } */

        if let Err(e) = status_list_credential.validate() {
            return result.with_error(format!("Invalid list credential: {}", e));
        }
        let vc_result = status_list_credential
            .verify(None, resolver, context_loader)
            .await;
        for warning in vc_result.warnings {
            result.warnings.push(format!("Status list: {}", warning));
        }
        if let Some(error) = vc_result.errors.into_iter().next() {
            result.errors.push(format!("Status list: {}", error));
            return result;
        }
        // Note: vc_result.checks is not checked here. It is assumed that default checks passed.

        let status_list_credential =
            match StatusList2021Credential::try_from(status_list_credential) {
                Ok(credential) => credential,
                Err(e) => {
                    return result
                        .with_error(format!("Unable to parse status list credential: {}", e));
                }
            };
        if status_list_credential.id != URI::String(self.status_list_credential.to_string()) {
            return result.with_error(format!(
                "Status list credential id mismatch. statusListCredential: {}, id: {}",
                self.status_list_credential, status_list_credential.id
            ));
        }
        let StatusList2021Subject::StatusList2021(status_list) =
            status_list_credential.credential_subject;

        let list = match List::try_from(&status_list.encoded_list) {
            Ok(list) => list,
            Err(e) => return result.with_error(format!("Unable to decode status list: {}", e)),
        };
        let credential_index = self.status_list_index.0;
        use bitvec::prelude::*;
        let bitstring = match BitVec::<Lsb0, u8>::try_from_vec(list.0) {
            Ok(bitstring) => bitstring,
            Err(list) => {
                return result.with_error(format!(
                    "Revocation list is too large for bitvec: {}",
                    list.len()
                ))
            }
        };
        let revoked = match bitstring.get(credential_index) {
            Some(bitref) => *bitref,
            None => {
                return result
                    .with_error("Credential index in revocation list is invalid.".to_string());
            }
        };

        // Mirror the BitstringStatusListEntry path: emit a structured
        // entry alongside the (possibly empty) error so consumers can
        // distinguish revoked / suspended / active without parsing
        // the human-readable error text.
        result.status.push(StatusCheckEntry {
            entry_type: "StatusList2021Entry".to_string(),
            status_purpose: self.status_purpose.clone(),
            is_set: revoked,
            status_list_credential: Some(self.status_list_credential.clone()),
            status_list_index: Some(self.status_list_index.0.to_string()),
        });

        if revoked {
            return match self.status_purpose.as_str() {
                "revocation" => result.with_error("Credential is revoked.".to_string()),
                "suspension" => result.with_error("Credential is suspended.".to_string()),
                status_purpose => result.with_error(format!(
                    "Credential status is set for purpose: {}",
                    status_purpose
                )),
            };
        }
        result
    }
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl CredentialStatus for BitstringStatusListEntry {
    /// Validate a credential's status according to [Bitstring Status List](https://www.w3.org/TR/vc-bitstring-status-list/#validate-algorithm).
    async fn check(
        &self,
        credential: &Credential,
        resolver: &dyn DIDResolver,
        context_loader: &mut ContextLoader,
    ) -> VerificationResult {
        let mut result = VerificationResult::new();
        let _issuer_id = match &credential.issuer {
            Some(issuer) => issuer.get_id().clone(),
            None => {
                return result.with_error("Credential is missing issuer".to_string());
            }
        };
        if !has_bitstring_status_list_context(credential) {
            // TODO: support JSON-LD credentials defining the terms elsewhere.
            return result.with_error(
                "Missing expected context URI for credential using BitstringStatusList".to_string(),
            );
        }
        if self.id == Some(URI::String(self.status_list_credential.clone())) {
            return result.with_error(format!(
                "Expected statusListCredential to be different from status id: {}",
                self.status_list_credential
            ));
        }
        let status_size = match self.status_size {
            Some(0) => return result.with_error("Invalid statusSize: 0".to_string()),
            Some(status_size) => status_size,
            None => 1,
        };
        if status_size != 1 {
            return result.with_error(format!(
                "Unsupported statusSize: {}. Only statusSize 1 is supported",
                status_size
            ));
        }
        // Check the status list URL before attempting to load it.
        match self.status_list_credential.split_once(':') {
            Some(("https", _)) => (),
            Some(("http", _)) => (),
            // TODO: an option to allow other URL schemes.
            Some((_scheme, _)) => {
                return result
                    .with_error(format!("Invalid schema: {}", self.status_list_credential))
            }
            _ => {
                return result.with_error(format!("Invalid rsrc: {}", self.status_list_credential))
            }
        }
        let status_list_credential = match load_credential(&self.status_list_credential).await {
            Ok(credential) => credential,
            Err(e) => {
                return result.with_error(format!("Unable to fetch status list credential: {}", e));
            }
        };
        let _list_issuer_id = match &status_list_credential.issuer {
            Some(issuer) => issuer.get_id().clone(),
            None => {
                return result.with_error("Status list credential is missing issuer".to_string());
            }
        };

        if let Err(e) = status_list_credential.validate() {
            return result.with_error(format!("Invalid list credential: {}", e));
        }
        let vc_result = status_list_credential
            .verify(None, resolver, context_loader)
            .await;
        for warning in vc_result.warnings {
            result.warnings.push(format!("Status list: {}", warning));
        }
        if let Some(error) = vc_result.errors.into_iter().next() {
            result.errors.push(format!("Status list: {}", error));
            return result;
        }
        // Note: vc_result.checks is not checked here. It is assumed that default checks passed.

        let status_list_credential =
            match BitstringStatusListCredential::try_from(status_list_credential) {
                Ok(credential) => credential,
                Err(e) => {
                    return result
                        .with_error(format!("Unable to parse status list credential: {}", e));
                }
            };
        if let Some(id) = status_list_credential.id {
            if id != URI::String(self.status_list_credential.to_string()) {
                return result.with_error(format!(
                    "Status list credential id mismatch. statusListCredential: {}, id: {}",
                    self.status_list_credential, id
                ));
            }
        }
        let BitstringStatusListSubject::BitstringStatusList(status_list) =
            status_list_credential.credential_subject;
        if !status_list.status_purpose.contains(&self.status_purpose) {
            return result.with_error(format!(
                "Status list purpose mismatch. credentialStatus: {}, statusListCredential: {:?}",
                self.status_purpose, status_list.status_purpose
            ));
        }
        if let Some(0) = status_list.status_size {
            return result.with_error("Invalid status list statusSize: 0".to_string());
        }
        if let Some(status_size) = status_list.status_size {
            if status_size != 1 {
                return result.with_error(format!(
                    "Unsupported status list statusSize: {}. Only statusSize 1 is supported",
                    status_size
                ));
            }
        }

        let list = match List::try_from(&status_list.encoded_list) {
            Ok(list) => list,
            Err(e) => return result.with_error(format!("Unable to decode status list: {}", e)),
        };
        let credential_index = self.status_list_index.0;
        use bitvec::prelude::*;
        let bitstring = match BitVec::<Lsb0, u8>::try_from_vec(list.0) {
            Ok(bitstring) => bitstring,
            Err(list) => {
                return result.with_error(format!(
                    "Status list is too large for bitvec: {}",
                    list.len()
                ))
            }
        };
        if bitstring.len() / status_size < MIN_BITSTRING_LENGTH {
            return result.with_error(format!(
                "Status list bitstring is too small: {}. Minimum entries: {}",
                bitstring.len() / status_size,
                MIN_BITSTRING_LENGTH
            ));
        }
        let status = match bitstring.get(credential_index * status_size) {
            Some(bitref) => *bitref,
            None => {
                return result
                    .with_error("Credential index in status list is invalid.".to_string());
            }
        };

        // Record the structured outcome before deciding whether to
        // attach an error. Downstream consumers can read
        // `result.status` for an unambiguous purpose+is_set result
        // without parsing the human-readable error string.
        result.status.push(StatusCheckEntry {
            entry_type: "BitstringStatusListEntry".to_string(),
            status_purpose: self.status_purpose.clone(),
            is_set: status,
            status_list_credential: Some(self.status_list_credential.clone()),
            status_list_index: Some(self.status_list_index.0.to_string()),
        });

        if status {
            return match self.status_purpose.as_str() {
                "revocation" => result.with_error("Credential is revoked.".to_string()),
                "suspension" => result.with_error("Credential is suspended.".to_string()),
                status_purpose => result.with_error(format!(
                    "Credential status is set for purpose: {}",
                    status_purpose
                )),
            };
        }
        result
    }
}

#[derive(Error, Debug)]
pub enum LoadResourceError {
    #[error("Error building HTTP client: {0}")]
    Build(reqwest::Error),
    #[error("Error sending HTTP request: {0}")]
    Request(reqwest::Error),
    #[error("Parse error: {0}")]
    Response(String),
    #[error("Not found")]
    NotFound,
    #[error("HTTP error: {0}")]
    HTTP(String),
    /// The resource is larger than an expected/allowed maximum size.
    #[error("Resource is too large: {size}, expected maximum: {max}")]
    TooLarge {
        /// The size of the resource so far, in bytes.
        size: usize,
        /// Maximum expected size of the resource, in bytes.
        ///
        /// e.g. [`MAX_RESPONSE_LENGTH`]
        max: usize,
    },
    /// Unable to convert content-length header value.
    #[error("Unable to convert content-length header value")]
    ContentLengthConversion(#[source] std::num::TryFromIntError),
}

async fn load_resource(url: &str) -> Result<Vec<u8>, LoadResourceError> {
    #[cfg(test)]
    match url {
        crate::tests::EXAMPLE_REVOCATION_2020_LIST_URL => {
            return Ok(crate::tests::EXAMPLE_REVOCATION_2020_LIST.to_vec());
        }
        crate::tests::EXAMPLE_STATUS_LIST_2021_URL => {
            return Ok(crate::tests::EXAMPLE_STATUS_LIST_2021.to_vec());
        }
        crate::tests::EXAMPLE_BITSTRING_STATUS_LIST_URL => {
            return Ok(crate::tests::example_bitstring_status_list().await);
        }
        _ => {}
    }
    let mut headers = reqwest::header::HeaderMap::new();
    headers.insert(
        "User-Agent",
        reqwest::header::HeaderValue::from_static(USER_AGENT),
    );
    let client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .map_err(LoadResourceError::Build)?;
    let accept = "application/json".to_string();
    let resp = client
        .get(url)
        .header("Accept", accept)
        .send()
        .await
        .map_err(LoadResourceError::Request)?;
    if let Err(err) = resp.error_for_status_ref() {
        if err.status() == Some(reqwest::StatusCode::NOT_FOUND) {
            return Err(LoadResourceError::NotFound);
        }
        return Err(LoadResourceError::HTTP(err.to_string()));
    }
    #[allow(unused_variables)]
    let content_length_opt = if let Some(content_length) = resp.content_length() {
        let len =
            usize::try_from(content_length).map_err(LoadResourceError::ContentLengthConversion)?;
        if len > MAX_RESPONSE_LENGTH {
            // Fail early if content-length header indicates body is too large.
            return Err(LoadResourceError::TooLarge {
                size: len,
                max: MAX_RESPONSE_LENGTH,
            });
        }
        Some(len)
    } else {
        None
    };
    #[cfg(target_arch = "wasm32")]
    {
        // Reqwest's WASM backend doesn't offer streamed/chunked response reading.
        // So we cannot check the response size while reading the response here.
        // Relevant issue: https://github.com/seanmonstar/reqwest/issues/1234
        // Instead, we hope that the content-length is correct, read the body all at once,
        // and apply the length check afterwards, for consistency.
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| LoadResourceError::Response(e.to_string()))?
            .to_vec();
        if bytes.len() > MAX_RESPONSE_LENGTH {
            return Err(LoadResourceError::TooLarge {
                size: bytes.len(),
                max: MAX_RESPONSE_LENGTH,
            });
        }
        Ok(bytes)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        // For non-WebAssembly, read the response up to the allowed maximimum size.
        let mut bytes = if let Some(len) = content_length_opt {
            Vec::with_capacity(len)
        } else {
            Vec::new()
        };
        let mut resp = resp;
        while let Some(chunk) = resp
            .chunk()
            .await
            .map_err(|e| LoadResourceError::Response(e.to_string()))?
        {
            let len = bytes.len() + chunk.len();
            if len > MAX_RESPONSE_LENGTH {
                return Err(LoadResourceError::TooLarge {
                    size: len,
                    max: MAX_RESPONSE_LENGTH,
                });
            }
            bytes.append(&mut chunk.to_vec());
        }
        Ok(bytes)
    }
}

#[derive(Error, Debug)]
pub enum LoadCredentialError {
    #[error("Unable to load resource: {0}")]
    Load(#[from] LoadResourceError),
    #[error("Error reading HTTP response: {0}")]
    Parse(#[from] serde_json::Error),
}

/// Fetch a credential from a HTTP(S) URL.
/// The resulting verifiable credential is not yet validated or verified.
///
/// The size of the loaded credential must not be greater than [`MAX_RESPONSE_LENGTH`].
pub async fn load_credential(url: &str) -> Result<Credential, LoadCredentialError> {
    let data = load_resource(url).await?;
    // TODO: support JWT-VC
    let credential: Credential = serde_json::from_slice(&data)?;
    Ok(credential)
}

#[derive(Error, Debug)]
pub enum CredentialConversionError {
    #[error("Conversion to JSON: {0}")]
    ToValue(serde_json::Error),
    #[error("Conversion from JSON: {0}")]
    FromValue(serde_json::Error),
    #[error("Missing expected URI in @context: {0}")]
    MissingContext(&'static str),
    #[error("Missing expected type: {0}. Found: {0:?}")]
    MissingType(&'static str, OneOrMany<String>),
    #[error("Missing issuer")]
    MissingIssuer,
}

/// Convert Credential to a [RevocationList2020Credential], while validating it.
// https://w3c-ccg.github.io/vc-status-rl-2020/#validate-algorithm
impl TryFrom<Credential> for RevocationList2020Credential {
    type Error = CredentialConversionError;
    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        if !credential
            .context
            .contains_uri(REVOCATION_LIST_2020_V1_CONTEXT.into_str())
        {
            return Err(CredentialConversionError::MissingContext(
                REVOCATION_LIST_2020_V1_CONTEXT.into_str(),
            ));
        }
        if !credential
            .type_
            .contains(&"RevocationList2020Credential".to_string())
        {
            return Err(CredentialConversionError::MissingType(
                "RevocationList2020Credential",
                credential.type_,
            ));
        }
        let credential =
            serde_json::to_value(credential).map_err(CredentialConversionError::ToValue)?;
        let credential =
            serde_json::from_value(credential).map_err(CredentialConversionError::FromValue)?;
        Ok(credential)
    }
}

impl TryFrom<RevocationList2020Credential> for Credential {
    type Error = CredentialConversionError;
    fn try_from(credential: RevocationList2020Credential) -> Result<Self, Self::Error> {
        let mut credential =
            serde_json::to_value(credential).map_err(CredentialConversionError::ToValue)?;
        use crate::DEFAULT_CONTEXT;
        use serde_json::json;
        credential["@context"] = json!([DEFAULT_CONTEXT, REVOCATION_LIST_2020_V1_CONTEXT]);
        credential["type"] = json!(["VerifiableCredential", "RevocationList2020Credential"]);
        let credential =
            serde_json::from_value(credential).map_err(CredentialConversionError::FromValue)?;
        Ok(credential)
    }
}

/// Convert Credential to a [StatusList2021Credential], while [validating](https://w3c-ccg.github.io/vc-status-list-2021/#validate-algorithm) it.
///
/// Note: this is a lossy operation. Only known StatusList2021Credential fields are preserved.
impl TryFrom<Credential> for StatusList2021Credential {
    type Error = CredentialConversionError;
    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        if !credential
            .context
            .contains_uri(STATUS_LIST_2021_V1_CONTEXT.into_str())
        {
            return Err(CredentialConversionError::MissingContext(
                STATUS_LIST_2021_V1_CONTEXT.into_str(),
            ));
        }
        if !credential
            .type_
            .contains(&"StatusList2021Credential".to_string())
        {
            return Err(CredentialConversionError::MissingType(
                "StatusList2021Credential",
                credential.type_,
            ));
        }
        let credential =
            serde_json::to_value(credential).map_err(CredentialConversionError::ToValue)?;
        let credential =
            serde_json::from_value(credential).map_err(CredentialConversionError::FromValue)?;
        Ok(credential)
    }
}

impl TryFrom<StatusList2021Credential> for Credential {
    type Error = CredentialConversionError;
    fn try_from(credential: StatusList2021Credential) -> Result<Self, Self::Error> {
        let mut credential =
            serde_json::to_value(credential).map_err(CredentialConversionError::ToValue)?;
        use crate::DEFAULT_CONTEXT;
        use serde_json::json;
        credential["@context"] = json!([DEFAULT_CONTEXT, STATUS_LIST_2021_V1_CONTEXT]);
        credential["type"] = json!(["VerifiableCredential", "StatusList2021Credential"]);
        let credential =
            serde_json::from_value(credential).map_err(CredentialConversionError::FromValue)?;
        Ok(credential)
    }
}

/// Convert Credential to a [BitstringStatusListCredential], while
/// [validating](https://www.w3.org/TR/vc-bitstring-status-list/#validate-algorithm) it.
///
/// Note: this is a lossy operation. Only known BitstringStatusListCredential fields are preserved.
impl TryFrom<Credential> for BitstringStatusListCredential {
    type Error = CredentialConversionError;
    fn try_from(credential: Credential) -> Result<Self, Self::Error> {
        if !has_bitstring_status_list_context(&credential) {
            return Err(CredentialConversionError::MissingContext(
                crate::DEFAULT_CONTEXT_V2,
            ));
        }
        if !credential
            .type_
            .contains(&"BitstringStatusListCredential".to_string())
        {
            return Err(CredentialConversionError::MissingType(
                "BitstringStatusListCredential",
                credential.type_,
            ));
        }
        let credential =
            serde_json::to_value(credential).map_err(CredentialConversionError::ToValue)?;
        let credential =
            serde_json::from_value(credential).map_err(CredentialConversionError::FromValue)?;
        Ok(credential)
    }
}

impl TryFrom<BitstringStatusListCredential> for Credential {
    type Error = CredentialConversionError;
    fn try_from(credential: BitstringStatusListCredential) -> Result<Self, Self::Error> {
        let mut credential =
            serde_json::to_value(credential).map_err(CredentialConversionError::ToValue)?;
        use serde_json::json;
        credential["@context"] = json!([crate::DEFAULT_CONTEXT_V2]);
        credential["type"] = json!(["VerifiableCredential", "BitstringStatusListCredential"]);
        let credential =
            serde_json::from_value(credential).map_err(CredentialConversionError::FromValue)?;
        Ok(credential)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn default_list() {
        let list = List(vec![0; MIN_BITSTRING_LENGTH / 8]);
        let revoked_indexes = list.iter_revoked_indexes().unwrap().collect::<Vec<usize>>();
        let empty: Vec<usize> = Vec::new();
        assert_eq!(revoked_indexes, empty);
        let el = EncodedList::try_from(&list).unwrap();
        assert_eq!(EncodedList::default(), el);
        let decoded_list = List::try_from(&el).unwrap();
        assert_eq!(decoded_list, list);
    }

    #[test]
    fn bitstring_status_list_encoded_list() {
        let list = List(vec![0; MIN_BITSTRING_LENGTH / 8]);
        let encoded = BitstringStatusListEncodedList::try_from(&list).unwrap();
        assert!(encoded.0.starts_with('u'));
        let decoded_list = List::try_from(&encoded).unwrap();
        assert_eq!(decoded_list, list);
    }

    #[test]
    fn set_status() {
        let mut rl = RevocationList2020::default();
        rl.set_status(1, true).unwrap();
        rl.set_status(5, true).unwrap();
        let decoded_list = List::try_from(&rl.encoded_list).unwrap();
        let revoked_indexes = decoded_list
            .iter_revoked_indexes()
            .unwrap()
            .collect::<Vec<usize>>();
        assert_eq!(revoked_indexes, vec![1, 5]);
    }
}
