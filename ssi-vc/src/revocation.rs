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
use ssi_json_ld::{ContextLoader, REVOCATION_LIST_2020_V1_CONTEXT, STATUS_LIST_2021_V1_CONTEXT};
use ssi_ldp::VerificationResult;
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct EncodedList(pub String);

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

impl TryFrom<&EncodedList> for List {
    type Error = DecodeListError;
    fn try_from(encoded_list: &EncodedList) -> Result<Self, Self::Error> {
        let string = &encoded_list.0;
        let bytes = base64::decode_config(string, base64::URL_SAFE)?;
        let mut data = Vec::new();
        use flate2::bufread::GzDecoder;
        use std::io::Read;
        GzDecoder::new(bytes.as_slice()).read_to_end(&mut data)?;
        Ok(Self(data))
        // TODO: streaming decode the revocation list, for less memory use for large bitvecs.
    }
}

impl TryFrom<&List> for EncodedList {
    type Error = EncodeListError;
    fn try_from(list: &List) -> Result<Self, Self::Error> {
        use flate2::{write::GzEncoder, Compression};
        use std::io::Write;
        let mut e = GzEncoder::new(Vec::new(), Compression::default());
        e.write_all(&list.0)?;
        let bytes = e.finish()?;
        let string = base64::encode_config(bytes, base64::URL_SAFE_NO_PAD);
        Ok(EncodedList(string))
    }
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
                "Missing expected context URI {REVOCATION_LIST_2020_V1_CONTEXT} for credential using RevocationList2020"
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
                        .with_error(format!("Unable to fetch revocation list credential: {e}"));
                }
            };
        let list_issuer_id = match &revocation_list_credential.issuer {
            Some(issuer) => issuer.get_id().clone(),
            None => {
                return result
                    .with_error("Revocation list credential is missing issuer".to_string());
            }
        };
        if issuer_id != list_issuer_id {
            return result.with_error(format!(
                "Revocation list issuer mismatch. Credential: {issuer_id}, Revocation list: {list_issuer_id}"
            ));
        }

        if let Err(e) = revocation_list_credential.validate() {
            return result.with_error(format!("Invalid list credential: {e}"));
        }
        let vc_result = revocation_list_credential
            .verify(None, resolver, context_loader)
            .await;
        for warning in vc_result.warnings {
            result.warnings.push(format!("Revocation list: {warning}"));
        }
        for error in vc_result.errors {
            result.errors.push(format!("Revocation list: {error}"));
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
                        .with_error(format!("Unable to parse revocation list credential: {e}"));
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
            Err(e) => return result.with_error(format!("Unable to decode revocation list: {e}")),
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
                "Missing expected context URI {STATUS_LIST_2021_V1_CONTEXT} for credential using StatusList2021"
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
            // TODO: an option to allow HTTP?
            // TODO: load from DID URLs?
            Some((_scheme, _)) => return result.with_error(format!("Invalid schema: {}", self.id)),
            _ => return result.with_error(format!("Invalid rsrc: {}", self.id)),
        }
        let status_list_credential = match load_credential(&self.status_list_credential).await {
            Ok(credential) => credential,
            Err(e) => {
                return result.with_error(format!("Unable to fetch status list credential: {e}"));
            }
        };
        let list_issuer_id = match &status_list_credential.issuer {
            Some(issuer) => issuer.get_id().clone(),
            None => {
                return result.with_error("Status list credential is missing issuer".to_string());
            }
        };
        if issuer_id != list_issuer_id {
            return result.with_error(format!(
                "Status list issuer mismatch. Credential: {issuer_id}, Status list: {list_issuer_id}"
            ));
        }

        if let Err(e) = status_list_credential.validate() {
            return result.with_error(format!("Invalid list credential: {e}"));
        }
        let vc_result = status_list_credential
            .verify(None, resolver, context_loader)
            .await;
        for warning in vc_result.warnings {
            result.warnings.push(format!("Status list: {warning}"));
        }
        if let Some(error) = vc_result.errors.into_iter().next() {
            result.errors.push(format!("Status list: {error}"));
            return result;
        }
        // Note: vc_result.checks is not checked here. It is assumed that default checks passed.

        let status_list_credential =
            match StatusList2021Credential::try_from(status_list_credential) {
                Ok(credential) => credential,
                Err(e) => {
                    return result
                        .with_error(format!("Unable to parse status list credential: {e}"));
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
            Err(e) => return result.with_error(format!("Unable to decode status list: {e}")),
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
        if revoked {
            return result.with_error("Credential is revoked.".to_string());
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
