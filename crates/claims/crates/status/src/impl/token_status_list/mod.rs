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
use std::borrow::Cow;

use iref::Uri;
use serde::Serialize;

pub mod cbor;
pub mod json;

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

/// Status List.
///
/// A Status List is a byte array that contains the statuses of many
/// Referenced Tokens represented by one or multiple bits.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#section-4>
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StatusList {
    status_size: StatusSize,
    bytes: Vec<u8>,
}

impl StatusList {
    /// Creates a new status list with the given status size.
    pub fn new(status_size: StatusSize) -> Self {
        Self {
            status_size,
            bytes: Vec::new(),
        }
    }

    /// Creates a new status list with the given status size and capacity
    /// (in number of statuses).
    pub fn with_capacity(status_size: StatusSize, capacity: usize) -> Self {
        Self {
            status_size,
            bytes: Vec::with_capacity(capacity / status_size.status_per_byte()),
        }
    }

    /// Creates a new status list from a status size and byte array.
    pub fn from_parts(status_size: StatusSize, data: Vec<u8>) -> Self {
        Self {
            status_size,
            bytes: data,
        }
    }

    pub fn status_size(&self) -> StatusSize {
        self.status_size
    }

    /// Returns `i`-th status in the list.
    pub fn get(&self, index: usize) -> u8 {
        let (a, b) = self.status_size.offset_of(index);
        (self.bytes[a] >> b) & self.status_size.status_mask()
    }

    pub fn set(&mut self, index: usize, value: u8) {
        let (a, b) = self.status_size.offset_of(index);
        self.bytes[a] &= !self.status_size.status_mask() << b; // clear
        self.bytes[a] |= (value & self.status_size.status_mask()) << b; // set
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.bytes.as_slice()
    }

    pub fn into_parts(self) -> (StatusSize, Vec<u8>) {
        (self.status_size, self.bytes)
    }
}

pub trait StatusListToken {
    fn status_list(&self) -> &StatusList;

    fn status_list_mut(&mut self) -> &mut StatusList;
}

pub trait ReferencedToken {
    fn status_list_url(&self) -> ReferencedTokenStatusList;
}

pub struct ReferencedTokenStatusList<'a> {
    pub status_list: Cow<'a, Uri>,

    pub index: usize,
}
