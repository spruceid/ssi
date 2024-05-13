//! W3C Bitstring Status List v1.0
//!
//! A privacy-preserving, space-efficient, and high-performance mechanism for
//! publishing status information such as suspension or revocation of Verifiable
//! Credentials through use of bitstrings.
//!
//! See: <https://www.w3.org/TR/vc-bitstring-status-list/>

use std::{
    borrow::Cow,
    collections::HashMap,
    hash::Hash,
    io::{self, Read, Write},
    time::Duration,
};

use flate2::{read::GzDecoder, write::GzEncoder, Compression};
use iref::{Uri, UriBuf};
use multibase::Base;
use rdf_types::VocabularyMut;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{ClaimsValidity, DateTimeEnvironment, InvalidClaims, Proof, Validate, ValidateProof, Verifiable, Invalid};
use ssi_data_integrity::{ssi_rdf::Expandable, AnyInputContext, AnyProofs};
use ssi_json_ld::{
    AnyJsonLdEnvironment, CompactJsonLd, JsonLdError, JsonLdNodeObject, JsonLdObject,
};
use ssi_vc::{
    json::{JsonCredentialTypes, RequiredCredentialType},
    Context, V2,
};
use ssi_verification_methods::ssi_core::OneOrMany;

use crate::{EncodedStatusMap, FromBytes, StatusMap, StatusMapEntry, StatusMapEntrySet};

pub const BITSTRING_STATUS_LIST_TYPE: &str = "BitstringStatusList";
pub const BITSTRING_STATUS_LIST_CREDENTIAL_TYPE: &str = "BitstringStatusListCredential";
pub const BITSTRING_STATUS_LIST_ENTRY_TYPE: &str = "BitstringStatusListEntry";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListCredential {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context<V2>,

    /// Credential identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes<BitstringStatusListCredentialType>,

    /// Valid from.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_from: Option<xsd_types::DateTimeStamp>,

    /// Valid until.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub valid_until: Option<xsd_types::DateTimeStamp>,

    /// Status list.
    pub credential_subject: BitstringStatusList,

    /// Other properties.
    #[serde(flatten)]
    pub other_properties: HashMap<String, serde_json::Value>,
}

impl BitstringStatusListCredential {
    pub fn new(id: Option<UriBuf>, credential_subject: BitstringStatusList) -> Self {
        Self {
            context: Context::default(),
            id,
            types: JsonCredentialTypes::default(),
            valid_from: None,
            valid_until: None,
            credential_subject,
            other_properties: HashMap::default(),
        }
    }

    pub fn decode_status_list(&self) -> Result<StatusList, DecodeError> {
        self.credential_subject.decode()
    }
}

impl JsonLdObject for BitstringStatusListCredential {
    fn json_ld_context(&self) -> Option<Cow<json_ld::syntax::Context>> {
        Some(Cow::Borrowed(self.context.as_ref()))
    }
}

impl JsonLdNodeObject for BitstringStatusListCredential {
    fn json_ld_type(&self) -> ssi_json_ld::JsonLdTypes {
        self.types.to_json_ld_types()
    }
}

impl<V, E, L> Expandable<E> for BitstringStatusListCredential
where
    E: AnyJsonLdEnvironment<Vocabulary = V, Loader = L>,
    V: VocabularyMut,
    V::Iri: Clone + Eq + Hash,
    V::BlankId: Clone + Eq + Hash,
    L: json_ld::Loader<V::Iri>,
    L::Error: std::fmt::Display,
{
    type Error = JsonLdError<L::Error>;
    type Expanded = json_ld::ExpandedDocument<V::Iri, V::BlankId>;

    async fn expand(&self, environment: &mut E) -> Result<Self::Expanded, Self::Error> {
        CompactJsonLd(json_syntax::to_value(self).unwrap())
            .expand(environment)
            .await
    }
}

impl<E> Validate<E> for BitstringStatusListCredential
where
    E: DateTimeEnvironment
{
    fn validate(&self, env: &E) -> ClaimsValidity {
        // TODO use `ssi`'s own VC DM v2.0 validation function once it's implemented.
        let now = env.date_time();

        if let Some(valid_from) = self.valid_from {
            if now < valid_from {
                return Err(InvalidClaims::Premature {
                    now,
                    valid_from: valid_from.into()
                })
            }
        }

        if let Some(valid_until) = self.valid_until {
            if now > valid_until {
                return Err(InvalidClaims::Expired {
                    now,
                    valid_until: valid_until.into()
                })
            }
        }

        Ok(())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid multibase: {0}")]
    Multibase(#[from] multibase::Error),

    #[error("GZIP error: {0}")]
    Gzip(io::Error),
}

impl EncodedStatusMap for BitstringStatusListCredential {
    type Decoded = StatusList;
    type DecodeError = DecodeError;

    fn decode(&self) -> Result<Self::Decoded, Self::DecodeError> {
        self.decode_status_list()
    }
}

enum CredentialMediaType {
    DataIntegrity,
    Jwt,
}

impl CredentialMediaType {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "application/vc+ld+json" | "application/ld+json" => Some(Self::DataIntegrity),
            "application/jwt" | "application/sd-jwt" => Some(Self::Jwt),
            _ => None,
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromBytesError {
    #[error("verification failed: {0}")]
    VerificationFailed(String),

    #[error("invalid proof")]
    InvalidProof(Invalid),

    #[error("invalid credential: {0}")]
    Credential(String),

    #[error("decoding failed: {0}")]
    Decoding(DecodeError),

    #[error("unsupported credential media type `{0}`")]
    UnsupportedMediaType(String),
}

impl<V> FromBytes<V> for BitstringStatusListCredential
where
    <AnyProofs as Proof>::Prepared: ValidateProof<Self, V>
{
    type Error = FromBytesError;

    async fn from_bytes(
        bytes: &[u8],
        media_type_name: Option<&str>,
        verifier: &V,
    ) -> Result<Self, Self::Error> {
        let media_type = match media_type_name {
            Some(name) => CredentialMediaType::from_name(name)
                .ok_or_else(|| FromBytesError::UnsupportedMediaType(name.to_owned()))?,
            None => CredentialMediaType::DataIntegrity,
        };

        match media_type {
            CredentialMediaType::DataIntegrity => {
                let vc: Verifiable<Self, AnyProofs> =
                    ssi_data_integrity::from_json_slice(bytes, AnyInputContext::default())
                        .await
                        .map_err(|e| FromBytesError::Credential(e.to_string()))?;
                vc
                    .verify(verifier)
                    .await
                    .map_err(|e| FromBytesError::VerificationFailed(e.to_string()))?
                    .map_err(FromBytesError::InvalidProof)?;

                Ok(vc.into_parts().0)
            }
            CredentialMediaType::Jwt => {
                // TODO support for JWTs.
                Err(FromBytesError::UnsupportedMediaType(
                    media_type_name.unwrap().to_owned(),
                ))
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct BitstringStatusListCredentialType;

impl RequiredCredentialType for BitstringStatusListCredentialType {
    const REQUIRED_CREDENTIAL_TYPE: &'static str = "BitstringStatusListCredential";
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusList {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// `BitstringStatusList` type.
    #[serde(rename = "type")]
    pub type_: BitstringStatusListType,

    /// Status purpose.
    pub status_purpose: StatusPurpose,

    #[serde(default, skip_serializing_if = "StatusSize::is_default")]
    pub status_size: StatusSize,

    /// Encoded status list.
    pub encoded_list: EncodedList,

    /// Time to live.
    #[serde(default, skip_serializing_if = "TimeToLive::is_default")]
    pub ttl: TimeToLive,

    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub status_message: Vec<StatusMessage>,

    /// URL to material related to the status.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_reference: Option<UriBuf>,
}

impl BitstringStatusList {
    pub fn new(
        id: Option<UriBuf>,
        status_purpose: StatusPurpose,
        status_size: StatusSize,
        encoded_list: EncodedList,
        ttl: TimeToLive,
        status_message: Vec<StatusMessage>,
    ) -> Self {
        Self {
            id,
            type_: BitstringStatusListType,
            status_purpose,
            status_size,
            encoded_list,
            ttl,
            status_message,
            status_reference: None,
        }
    }

    pub fn decode(&self) -> Result<StatusList, DecodeError> {
        let bytes = self.encoded_list.decode(None)?;
        Ok(StatusList::from_bytes(self.status_size, self.ttl, bytes))
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct StatusMessage {
    pub status: u8,
    pub message: String,
}

#[derive(Debug, thiserror::Error)]
#[error("invalid status size `{0}`")]
pub struct InvalidStatusSize(u8);

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct StatusSize(u8);

impl TryFrom<u8> for StatusSize {
    type Error = InvalidStatusSize;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if value <= 8 {
            Ok(Self(value))
        } else {
            Err(InvalidStatusSize(value))
        }
    }
}

impl Default for StatusSize {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl StatusSize {
    pub const DEFAULT: Self = Self(1);

    pub fn is_default(&self) -> bool {
        *self == Self::DEFAULT
    }

    fn offset_of(&self, index: usize) -> Offset {
        let bit_offset = self.0 as usize * index;
        Offset {
            byte: bit_offset / 8,
            bit: bit_offset % 8,
        }
    }

    fn mask(&self) -> u8 {
        if self.0 == 8 {
            0xff
        } else {
            (1 << self.0) - 1
        }
    }
}

impl<'de> Deserialize<'de> for StatusSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u8::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

struct Offset {
    byte: usize,
    bit: usize,
}

impl Offset {
    fn left_shift(&self, status_size: StatusSize) -> (isize, Option<usize>) {
        let high = 8 - status_size.0 as isize - self.bit as isize;
        let low = if high < 0 {
            Some((8 + high) as usize)
        } else {
            None
        };

        (high, low)
    }
}

/// Multibase-encoded base64url (with no padding) representation of the
/// GZIP-compressed bitstring values for the associated range of a bitstring
/// status list verifiable credential.
#[derive(Debug, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EncodedList(String);

impl EncodedList {
    /// Minimum bitstring size (16KB).
    pub const MINIMUM_SIZE: usize = 16 * 1024;

    /// Default maximum bitstring size allowed by the `decode` function.
    ///
    /// 16MB.
    pub const DEFAULT_LIMIT: u64 = 16 * 1024 * 1024;

    pub fn encode(bytes: &[u8]) -> Self {
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(bytes).unwrap();

        // Add padding to satisfy the minimum bitstring size constraint.
        const PADDING_BUFFER_LEN: usize = 1024;
        let padding = [0; PADDING_BUFFER_LEN];
        let mut it = (bytes.len()..Self::MINIMUM_SIZE)
            .step_by(PADDING_BUFFER_LEN)
            .peekable();
        while let Some(start) = it.next() {
            let end = it.peek().copied().unwrap_or(Self::MINIMUM_SIZE);
            let len = end - start;
            encoder.write_all(&padding[..len]).unwrap();
        }

        let compressed = encoder.finish().unwrap();
        Self(multibase::encode(Base::Base64Url, compressed))
    }

    pub fn decode(&self, limit: Option<u64>) -> Result<Vec<u8>, DecodeError> {
        let limit = limit.unwrap_or(Self::DEFAULT_LIMIT);
        let (_base, compressed) = multibase::decode(&self.0)?;
        let mut decoder = GzDecoder::new(compressed.as_slice()).take(limit);
        let mut bytes = Vec::new();
        decoder.read_to_end(&mut bytes).map_err(DecodeError::Gzip)?;
        Ok(bytes)
    }
}

/// Maximum duration, in milliseconds, an implementer is allowed to cache a
/// status list.
///
/// Default value is 300000.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct TimeToLive(pub u64);

impl Default for TimeToLive {
    fn default() -> Self {
        Self::DEFAULT
    }
}

impl TimeToLive {
    pub const DEFAULT: Self = Self(300000);

    pub fn is_default(&self) -> bool {
        *self == Self::DEFAULT
    }
}

impl From<TimeToLive> for Duration {
    fn from(value: TimeToLive) -> Self {
        Duration::from_millis(value.0)
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitstringStatusListType;

impl Serialize for BitstringStatusListType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        BITSTRING_STATUS_LIST_TYPE.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BitstringStatusListType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let type_ = String::deserialize(deserializer)?;
        if type_ == BITSTRING_STATUS_LIST_TYPE {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "expected `BitstringStatusList` type",
            ))
        }
    }
}

/// Bitstring status list entry.
///
/// References a particular entry of a status list, for a given status purpose.
/// It is the type of the `credentialStatus` property of a Verifiable
/// Credential.
///
/// See: <https://www.w3.org/TR/vc-bitstring-status-list/#bitstringstatuslistentry>
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListEntry {
    /// Optional identifier for the status list entry.
    ///
    /// Identifies the status information associated with the verifiable
    /// credential. Must *not* be the URL of the status list.
    id: Option<UriBuf>,

    /// `BitstringStatusListEntry` type.
    #[serde(rename = "type")]
    type_: BitstringStatusListEntryType,

    /// Purpose of the status entry.
    status_purpose: StatusPurpose,

    /// URL to a `BitstringStatusListCredential` verifiable credential.
    status_list_credential: UriBuf,

    /// Arbitrary size integer greater than or equal to 0, encoded as a string
    /// in base 10.
    #[serde(with = "base10_nat_string")]
    status_list_index: usize,
}

impl StatusMapEntry for BitstringStatusListEntry {
    type Key = usize;

    fn status_list_url(&self) -> &Uri {
        &self.status_list_credential
    }

    fn key(&self) -> Self::Key {
        self.status_list_index
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BitstringStatusListEntrySetCredential {
    /// JSON-LD context.
    #[serde(rename = "@context")]
    pub context: Context<V2>,

    /// Credential identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<UriBuf>,

    /// Credential type.
    #[serde(rename = "type")]
    pub types: JsonCredentialTypes,

    pub credential_status: OneOrMany<BitstringStatusListEntry>,

    #[serde(flatten)]
    pub other_properties: HashMap<String, serde_json::Value>,
}

impl StatusMapEntrySet for BitstringStatusListEntrySetCredential {
    type Entry<'a> = &'a BitstringStatusListEntry where Self: 'a;

    fn get_entry(&self, purpose: crate::StatusPurpose<&str>) -> Option<Self::Entry<'_>> {
        (&self.credential_status).into_iter().find(|&entry| entry.status_purpose == purpose)
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StatusPurpose {
    /// Cancel the validity of a verifiable credential.
    ///
    /// This status is not reversible.
    Revocation,

    /// Temporarily prevent the acceptance of a verifiable credential.
    ///
    /// This status is reversible.
    Suspension,

    /// Convey an arbitrary message related to the status of the verifiable
    /// credential.
    Message,
}

impl<'a> From<&'a StatusPurpose> for crate::StatusPurpose<&'a str> {
    fn from(value: &'a StatusPurpose) -> Self {
        match value {
            StatusPurpose::Revocation => Self::Revocation,
            StatusPurpose::Suspension => Self::Suspension,
            StatusPurpose::Message => Self::Other("message"),
        }
    }
}

impl<'a> PartialEq<crate::StatusPurpose<&'a str>> for StatusPurpose {
    fn eq(&self, other: &crate::StatusPurpose<&'a str>) -> bool {
        matches!(
            (self, other),
            (Self::Revocation, crate::StatusPurpose::Revocation) |
            (Self::Suspension, crate::StatusPurpose::Suspension) |
            (Self::Message, crate::StatusPurpose::Other("message"))
        )
    }
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitstringStatusListEntryType;

impl Serialize for BitstringStatusListEntryType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        BITSTRING_STATUS_LIST_ENTRY_TYPE.serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for BitstringStatusListEntryType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let type_ = String::deserialize(deserializer)?;
        if type_ == BITSTRING_STATUS_LIST_ENTRY_TYPE {
            Ok(Self)
        } else {
            Err(serde::de::Error::custom(
                "expected `BitstringStatusListEntry` type",
            ))
        }
    }
}

mod base10_nat_string {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(n: &usize, serializer: S) -> Result<S::Ok, S::Error> {
        n.to_string().serialize(serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<usize, D::Error> {
        let string = String::deserialize(deserializer)?;
        string.parse().map_err(serde::de::Error::custom)
    }
}

/// Bit-string as defined by the W3C Bitstring Status List specification.
///
/// Bits are indexed from most significant to least significant.
/// ```text
/// | 0 | 1 | 2 | 3 | 4 | 5 | 6 | 7 | ... | n-8 | n-7 | n-6 | n-5 | n-4 | n-3 | n-2 | n-1 |
/// | byte 0                        | ... | byte k-1                                      |
/// ```
///
/// See: <https://www.w3.org/TR/vc-bitstring-status-list/#bitstring-encoding>
#[derive(Debug, Clone)]
pub struct StatusList {
    status_size: StatusSize,
    bytes: Vec<u8>,
    len: usize,
    ttl: TimeToLive,
}

impl StatusList {
    pub fn new(status_size: StatusSize, ttl: TimeToLive) -> Self {
        Self {
            status_size,
            bytes: Vec::new(),
            len: 0,
            ttl,
        }
    }

    pub fn from_bytes(status_size: StatusSize, ttl: TimeToLive, bytes: Vec<u8>) -> Self {
        let len = bytes.len() * 8usize / status_size.0 as usize;
        Self {
            status_size,
            bytes,
            len,
            ttl,
        }
    }

    pub fn get(&self, index: usize) -> Option<u8> {
        let offset = self.status_size.offset_of(index);
        let (high_shift, low_shift) = offset.left_shift(self.status_size);
        let high = *self.bytes.get(offset.byte)? >> high_shift;
        let low = match low_shift {
            Some(low_shift) => *self.bytes.get(offset.byte + 1)? >> low_shift,
            None => 0,
        };
        Some((high | low) & self.status_size.mask())
    }

    pub fn set(&mut self, index: usize, value: u8) {
        let mask = self.status_size.mask();
        let value = value & mask;
        let offset = self.status_size.offset_of(index);
        let (high_shift, low_shift) = offset.left_shift(self.status_size);

        self.bytes[offset.byte] &= !mask << high_shift; // clear high
        self.bytes[offset.byte] |= value << high_shift; // set high
        if let Some(low_shift) = low_shift {
            self.bytes[offset.byte + 1] &= !mask << low_shift; // clear low
            self.bytes[offset.byte + 1] |= value << low_shift; // set low
        }
    }

    pub fn push(&mut self, value: u8) -> usize {
        let value = value & self.status_size.mask();
        let index = self.len;
        let offset = self.status_size.offset_of(index);
        let (high_shift, low_shift) = offset.left_shift(self.status_size);

        if offset.byte == self.bytes.len() {
            self.bytes.push(value << high_shift);
        } else {
            self.bytes[offset.byte] |= value << high_shift
        }

        if let Some(low_shift) = low_shift {
            self.bytes.push(value << low_shift);
        }

        self.len += 1;
        index
    }

    pub fn iter(&self) -> StatusListIter {
        StatusListIter {
            status_list: self,
            index: 0,
        }
    }

    pub fn to_credential_subject(
        &self,
        id: Option<UriBuf>,
        status_purpose: StatusPurpose,
        status_message: Vec<StatusMessage>,
    ) -> BitstringStatusList {
        BitstringStatusList::new(
            id,
            status_purpose,
            self.status_size,
            EncodedList::encode(&self.bytes),
            self.ttl,
            status_message,
        )
    }
}

pub struct StatusListIter<'a> {
    status_list: &'a StatusList,
    index: usize,
}

impl<'a> Iterator for StatusListIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.status_list.get(self.index).map(|status| {
            self.index += 1;
            status
        })
    }
}

impl StatusMap for StatusList {
    type Key = usize;
    type Status = u8;

    fn time_to_live(&self) -> Option<Duration> {
        Some(self.ttl.into())
    }

    fn get_by_key(&self, key: Self::Key) -> Option<u8> {
        self.get(key).map(Into::into)
    }
}
