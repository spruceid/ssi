//! Revocation List, a privacy-preserving mechanism for revoking Verifiable
//! Credentials.
//!
//! See: <https://w3c-ccg.github.io/vc-status-rl-2020/>
use base64::Engine;
use bitvec::prelude::Lsb0;
use bitvec::slice::BitSlice;
use core::convert::TryFrom;
use iref::{IriBuf, UriBuf};
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ProofPreparationError, ProofValidationError};
use ssi_data_integrity::AnyDataIntegrity;
use ssi_verification_methods::{AnyMethod, VerificationMethodResolver};
use thiserror::Error;

mod v2020;
mod v2021;

pub use v2020::*;
pub use v2021::*;

use super::SpecializedJsonCredential;

/// Minimum length of a revocation list bit-string.
///
/// See: <https://w3c-ccg.github.io/vc-status-rl-2020/#revocation-bitstring-length>
pub const MIN_BITSTRING_LENGTH: usize = 131072;

/// Maximum size of a revocation list credential.
pub const MAX_RESPONSE_LENGTH: usize = 2097152; // 2MB

const EMPTY_RLIST: &str = "H4sIAAAAAAAA_-3AMQEAAADCoPVPbQwfKAAAAAAAAAAAAAAAAAAAAOBthtJUqwBAAAA";

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

/// Integer identifying a bit position of the revocation status of a verifiable credential in a
/// revocation list, e.g. in a [RevocationList2020].
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct RevocationListIndex(usize);

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
        let bytes = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(string)?;
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
        let string = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(bytes);
        Ok(EncodedList(string))
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Reason {
    #[error("Missing expected context IRI `{0}`")]
    MissingRequiredLdContext(IriBuf),

    #[error("Expected revocationListCredential to be different from status id: `{0}`")]
    StatusIdMatchesCredentialId(UriBuf),

    #[error("Invalid URI scheme `{0}`")]
    UnsupportedUriScheme(iref::uri::SchemeBuf),

    #[error("Revocation list issuer mismatch (credential issuer is `{0}`, revocation list issuer is `{1}`)")]
    IssuerMismatch(UriBuf, UriBuf),

    #[error("Revocation list credential id mismatch (expected `{1}`, found `{0}`)")]
    IdMismatch(UriBuf, UriBuf),

    #[error("Missing credential subject")]
    MissingCredentialSubject,

    #[error("Too many credential subjects")]
    TooManyCredentialSubjects,

    #[error("Credential verification failed: {0}")]
    CredentialVerification(ssi_claims_core::Invalid),

    #[error("Unable to decode revocation list: {0}")]
    DecodeListError(DecodeListError),

    #[error("Invalid revocation list index")]
    InvalidRevocationListIndex,

    #[error("Credential is revoked")]
    Revoked,
}

pub enum StatusCheck {
    Valid,
    Invalid(Reason),
}

#[derive(Debug, thiserror::Error)]
pub enum StatusCheckError {
    #[error("Loading credential failed: {0}")]
    LoadCredential(#[from] LoadResourceError),

    #[error("Syntax error: {0}")]
    Syntax(#[from] serde_json::Error),

    #[error("Proof preparation failed: {0}")]
    ProofPreparation(#[from] ProofPreparationError),

    #[error("Credential verification failed: {0}")]
    CredentialVerification(#[from] ProofValidationError),

    #[error("Revocation list is too large (length is `{0}`)")]
    RevocationListTooLarge(usize),
}

pub trait CredentialStatus {
    #[allow(async_fn_in_trait)]
    async fn check(
        &self,
        credential: &AnyDataIntegrity<SpecializedJsonCredential>,
        resolver: &impl VerificationMethodResolver<Method = AnyMethod>,
    ) -> Result<StatusCheck, StatusCheckError>;
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
        tests::EXAMPLE_REVOCATION_2020_LIST_URL => {
            return Ok(tests::EXAMPLE_REVOCATION_2020_LIST.to_vec());
        }
        tests::EXAMPLE_STATUS_LIST_2021_URL => {
            return Ok(tests::EXAMPLE_STATUS_LIST_2021.to_vec());
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
    // #[error("Error reading HTTP response: {0}")]
    // Decode(#[from] ssi_data_integrity::DecodeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    pub const EXAMPLE_REVOCATION_2020_LIST_URL: &str = "https://example.test/revocationList.json";
    pub const EXAMPLE_REVOCATION_2020_LIST: &[u8] =
        include_bytes!("../../../../../../../tests/revocationList.json");

    pub const EXAMPLE_STATUS_LIST_2021_URL: &str = "https://example.com/credentials/status/3";
    pub const EXAMPLE_STATUS_LIST_2021: &[u8] =
        include_bytes!("../../../../../../../tests/statusList.json");

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
