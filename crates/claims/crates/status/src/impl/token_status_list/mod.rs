//! IETF Token Status List.
//!
//! A Token Status List provides a way to represent the status
//! of tokens secured by JSON Object Signing and Encryption (JOSE) or CBOR
//! Object Signing and Encryption (COSE). Such tokens can include JSON Web
//! Tokens (JWTs), CBOR Web Tokens (CWTs) and ISO mdoc.
//!
//! Token status lists are themselves encoded as JWTs or CWTs.
//!
//! See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html>
use iref::Uri;
use serde::Serialize;
use std::time::Duration;

pub mod cbor;
pub mod json;

pub use json::StatusListJwt;
use ssi_jws::{CompactJWS, InvalidCompactJWS, JWSVerifier};
use ssi_jwt::{ClaimSet, JWTClaims, ToDecodedJWT};

use crate::{
    EncodedStatusMap, FromBytes, FromBytesOptions, StatusMap, StatusMapEntry, StatusMapEntrySet,
};

/// Token Status List, serialized as a JWT or CWT.
pub enum StatusListToken {
    Jwt(StatusListJwt),
}

impl StatusListToken {
    pub fn decode_status_list(self) -> Result<StatusList, DecodeError> {
        match self {
            Self::Jwt(claims) => json::decode_status_list_jwt(claims),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromBytesError {
    #[error("missing media type")]
    MissingMediaType,

    #[error("unexpected media type `{0}`")]
    UnexpectedMediaType(String),

    #[error(transparent)]
    JWS(#[from] InvalidCompactJWS<Vec<u8>>),

    #[error("invalid JWT: {0}")]
    JWT(#[from] ssi_jwt::DecodeError),

    #[error("unexpected JWS type `{0}`")]
    UnexpectedJWSType(String),

    #[error("missing JWS type")]
    MissingJWSType,

    #[error("proof preparation failed: {0}")]
    Preparation(#[from] ssi_claims_core::ProofPreparationError),

    #[error("proof verification failed: {0}")]
    Verification(#[from] ssi_claims_core::ProofValidationError),

    #[error(transparent)]
    Rejected(#[from] ssi_claims_core::Invalid),
}

impl<V: JWSVerifier> FromBytes<V> for StatusListToken {
    type Error = FromBytesError;

    async fn from_bytes_with(
        bytes: &[u8],
        media_type: &str,
        verifier: &V,
        _options: FromBytesOptions,
    ) -> Result<Self, Self::Error> {
        match media_type {
            "statuslist+jwt" => {
                use ssi_claims_core::VerifiableClaims;
                let jwt = CompactJWS::new(bytes)
                    .map_err(InvalidCompactJWS::into_owned)?
                    .to_decoded_custom_jwt::<json::StatusListJwtPrivateClaims>()?
                    .into_verifiable()
                    .await?;

                match jwt.header.type_.as_deref() {
                    Some("statuslist+jwt") => {
                        jwt.verify(verifier).await??;
                        Ok(Self::Jwt(jwt.into_parts().0.payload))
                    }
                    Some(other) => Err(FromBytesError::UnexpectedJWSType(other.to_owned())),
                    None => Err(FromBytesError::MissingJWSType),
                }
            }
            "statuslist+cwt" => {
                todo!()
            }
            other => Err(FromBytesError::UnexpectedMediaType(other.to_owned())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid claim: {0}")]
    Claim(String),

    #[error("missing issuer")]
    MissingIssuer,

    #[error("missing subject")]
    MissingSubject,

    #[error("missing `status_list` claim")]
    MissingStatusList,

    #[error("invalid base64: {0}")]
    Base64(#[from] base64::DecodeError),
}

impl DecodeError {
    pub fn claim(e: impl ToString) -> Self {
        Self::Claim(e.to_string())
    }
}

impl EncodedStatusMap for StatusListToken {
    type Decoded = StatusList;
    type DecodeError = DecodeError;

    fn decode(self) -> Result<Self::Decoded, Self::DecodeError> {
        self.decode_status_list()
    }
}

/// Type of a JWT representing a status list.
///
/// This is the required value of the JWT Header's `typ` field.
pub const JWT_TYPE: &str = "statuslist+jwt";

#[derive(Debug, thiserror::Error)]
#[error("invalid status size {0}")]
pub struct InvalidStatusSize(u8);

/// Number of bits per Referenced Token in a Status List.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct StatusSize(u8);

impl StatusSize {
    /// Returns the number of statuses per status list byte.
    pub const fn status_per_byte(&self) -> usize {
        8 / self.0 as usize
    }

    /// Returns the bit-mask necessary to extract a status.
    pub const fn status_mask(&self) -> u8 {
        match self.0 {
            1 => 0b1,
            2 => 0b11,
            4 => 0b1111,
            _ => 0b11111111,
        }
    }

    /// Returns the byte index storing the given status index in a status list
    /// with this status size, along with the intra-byte offset.
    pub const fn offset_of(&self, index: usize) -> (usize, usize) {
        let spb = self.status_per_byte();
        (index / spb, (index % spb) * self.0 as usize)
    }
}

impl TryFrom<u8> for StatusSize {
    type Error = InvalidStatusSize;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        if matches!(value, 1 | 2 | 4 | 8) {
            Ok(Self(value))
        } else {
            Err(InvalidStatusSize(value))
        }
    }
}

impl<'de> serde::Deserialize<'de> for StatusSize {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = StatusSize;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(formatter, "number of bits per Referenced Token")
            }

            fn visit_u8<E>(self, v: u8) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.try_into().map_err(serde::de::Error::custom)
            }
        }

        deserializer.deserialize_u8(Visitor)
    }
}

#[derive(Clone)]
pub struct StatusList {
    bit_string: BitString,
    ttl: Option<u64>,
}

impl StatusList {
    pub fn new(bit_string: BitString, ttl: Option<u64>) -> Self {
        Self { bit_string, ttl }
    }

    pub fn iter(&self) -> BitStringIter {
        self.bit_string.iter()
    }
}

impl StatusMap for StatusList {
    type Key = usize;
    type Status = u8;

    fn time_to_live(&self) -> Option<Duration> {
        self.ttl.map(Duration::from_secs)
    }

    fn get_by_key(&self, key: Self::Key) -> Option<Self::Status> {
        self.bit_string.get(key)
    }
}

/// Status List.
///
/// A Status List is a byte array that contains the statuses of many
/// Referenced Tokens represented by one or multiple bits.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#section-4>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BitString {
    status_size: StatusSize,
    bytes: Vec<u8>,
    len: usize,
}

impl BitString {
    /// Creates a new status list with the given status size.
    pub fn new(status_size: StatusSize) -> Self {
        Self {
            status_size,
            bytes: Vec::new(),
            len: 0,
        }
    }

    /// Creates a new status list with the given status size and capacity
    /// (in number of statuses).
    pub fn with_capacity(status_size: StatusSize, capacity: usize) -> Self {
        Self {
            status_size,
            bytes: Vec::with_capacity(capacity / status_size.status_per_byte()),
            len: 0,
        }
    }

    /// Creates a new status list from a status size and byte array.
    pub fn from_parts(status_size: StatusSize, data: Vec<u8>) -> Self {
        let len = data.len() * 8usize / status_size.0 as usize;
        Self {
            status_size,
            bytes: data,
            len,
        }
    }

    pub fn status_size(&self) -> StatusSize {
        self.status_size
    }

    /// Returns `i`-th status in the list.
    pub fn get(&self, index: usize) -> Option<u8> {
        if index < self.len {
            let (a, b) = self.status_size.offset_of(index);
            Some((self.bytes[a] >> b) & self.status_size.status_mask())
        } else {
            None
        }
    }

    pub fn set(&mut self, index: usize, value: u8) {
        let (a, b) = self.status_size.offset_of(index);
        self.bytes[a] &= !self.status_size.status_mask() << b; // clear
        self.bytes[a] |= (value & self.status_size.status_mask()) << b; // set
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn iter(&self) -> BitStringIter {
        BitStringIter {
            bit_string: self,
            index: 0,
        }
    }

    pub fn into_parts(self) -> (StatusSize, Vec<u8>) {
        (self.status_size, self.bytes)
    }
}

pub struct BitStringIter<'a> {
    bit_string: &'a BitString,
    index: usize,
}

impl<'a> Iterator for BitStringIter<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        self.bit_string.get(self.index).map(|status| {
            self.index += 1;
            status
        })
    }
}

#[derive(Debug, thiserror::Error)]
pub enum EntrySetFromBytesError {
    #[error(transparent)]
    Json(#[from] serde_json::Error),

    #[error(transparent)]
    JWS(#[from] InvalidCompactJWS<Vec<u8>>),

    #[error(transparent)]
    JWT(#[from] ssi_jwt::DecodeError),

    #[error("proof preparation failed: {0}")]
    ProofPreparation(#[from] ssi_claims_core::ProofPreparationError),

    #[error("proof validation failed: {0}")]
    ProofValidation(#[from] ssi_claims_core::ProofValidationError),

    #[error("rejected claims: {0}")]
    Rejected(#[from] ssi_claims_core::Invalid),

    #[error("missing status")]
    MissingStatus,
}

pub enum AnyStatusListEntrySet {
    Json(json::Status),
}

impl<V: JWSVerifier> FromBytes<V> for AnyStatusListEntrySet {
    type Error = EntrySetFromBytesError;

    async fn from_bytes_with(
        bytes: &[u8],
        media_type: &str,
        verifier: &V,
        _options: FromBytesOptions,
    ) -> Result<Self, EntrySetFromBytesError> {
        match media_type {
            "application/json" => {
                let claims: JWTClaims = serde_json::from_slice(bytes)?;
                Ok(Self::Json(
                    claims
                        .try_get::<json::Status>()?
                        .ok_or(EntrySetFromBytesError::MissingStatus)?
                        .into_owned(),
                ))
            }
            "application/jwt" => {
                use ssi_claims_core::VerifiableClaims;
                let jwt = CompactJWS::new(bytes)
                    .map_err(InvalidCompactJWS::into_owned)?
                    .to_decoded_jwt()?
                    .into_verifiable()
                    .await?;
                jwt.verify(verifier).await??;

                Ok(Self::Json(
                    jwt.payload
                        .try_get::<json::Status>()?
                        .ok_or(EntrySetFromBytesError::MissingStatus)?
                        .into_owned(),
                ))
            }
            // "application/cbor" => {
            //     // ...
            // },
            // "application/cwt" => {
            //     // ...
            // },
            _ => todo!(),
        }
    }
}

impl StatusMapEntrySet for AnyStatusListEntrySet {
    type Entry<'a> = AnyStatusListReference<'a> where Self: 'a;

    fn get_entry(&self, purpose: crate::StatusPurpose<&str>) -> Option<Self::Entry<'_>> {
        match self {
            Self::Json(s) => s.get_entry(purpose).map(AnyStatusListReference::Json),
        }
    }
}

pub enum AnyStatusListReference<'a> {
    Json(&'a json::StatusListReference),
}

impl<'a> StatusMapEntry for AnyStatusListReference<'a> {
    type Key = usize;

    fn key(&self) -> Self::Key {
        match self {
            Self::Json(e) => e.key(),
        }
    }

    fn status_list_url(&self) -> &Uri {
        match self {
            Self::Json(e) => e.status_list_url(),
        }
    }
}
