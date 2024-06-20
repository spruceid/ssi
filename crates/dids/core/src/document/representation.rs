//! DID Document representations.
//!
//! A "representation" is a concrete serialization of a DID document.
//! Multiple representations are defined by the DID specification, such as
//! JSON and JSON-LD. In practice, any representation can be used, such as XML
//! or YAML, as long as it is capable of expressing the data model of DID
//! documents.
//!
//! A simple serialization (e.g. with `serde`) is not possible for all
//! representations, as some of them, such as JSON-LD, require serializing
//! representation-specific properties that are outside the core data model
//! (for instance the `@context` property of a JSON-LD document).
//!
//! See: <https://www.w3.org/TR/did-core/#representations>

use core::fmt;
use std::{ops::Deref, str::FromStr};

use serde::{Deserialize, Serialize};
pub mod json;
pub mod json_ld;

pub use self::json_ld::JsonLd;
pub use json::Json;

use crate::Document;

/// DID document in a specific representation.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Represented<D = Document> {
    Json(Json<D>),
    JsonLd(JsonLd<D>),
}

impl<D> Represented<D> {
    pub fn new(document: D, options: Options) -> Self {
        match options {
            Options::Json => Self::Json(Json::new(document)),
            Options::JsonLd(o) => Self::JsonLd(JsonLd::new(document, o)),
        }
    }

    pub fn media_type(&self) -> MediaType {
        match self {
            Self::Json(_) => MediaType::Json,
            Self::JsonLd(_) => MediaType::JsonLd,
        }
    }

    pub fn document(&self) -> &D {
        match self {
            Self::Json(d) => d.document(),
            Self::JsonLd(d) => d.document(),
        }
    }

    pub fn into_document(self) -> D {
        match self {
            Self::Json(d) => d.into_document(),
            Self::JsonLd(d) => d.into_document(),
        }
    }
}

impl<D: Serialize> Represented<D> {
    pub fn to_bytes(&self) -> Vec<u8> {
        match self {
            Self::Json(d) => d.to_bytes(),
            Self::JsonLd(d) => d.to_bytes(),
        }
    }
}

impl<D> Deref for Represented<D> {
    type Target = D;

    fn deref(&self) -> &Self::Target {
        self.document()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unknown DID document representation `{0}`")]
pub struct Unknown(pub String);

/// DID document representation media type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum MediaType {
    /// `application/did+json`.
    #[serde(rename = "application/did+json")]
    Json,

    /// `application/did+ld+json`.
    #[serde(rename = "application/did+ld+json")]
    JsonLd,
}

impl MediaType {
    /// Returns the name of the media type.
    pub fn name(&self) -> &'static str {
        match self {
            Self::Json => "application/did+json",
            Self::JsonLd => "application/did+ld+json",
        }
    }

    pub fn into_name(self) -> &'static str {
        self.name()
    }
}

impl From<MediaType> for String {
    fn from(value: MediaType) -> Self {
        value.name().to_owned()
    }
}

impl fmt::Display for MediaType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.name().fmt(f)
    }
}

impl FromStr for MediaType {
    type Err = Unknown;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "application/did+json" => Ok(Self::Json),
            "application/did+ld+json" => Ok(Self::JsonLd),
            unknown => Err(Unknown(unknown.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidMediaType {
    #[error(transparent)]
    Unknown(Unknown),

    #[error("invalid DID document media type")]
    NotAString,
}

impl<'a> TryFrom<&'a [u8]> for MediaType {
    type Error = InvalidMediaType;

    fn try_from(s: &'a [u8]) -> Result<Self, Self::Error> {
        match s {
            b"application/did+json" => Ok(Self::Json),
            b"application/did+ld+json" => Ok(Self::JsonLd),
            unknown => match String::from_utf8(unknown.to_vec()) {
                Ok(s) => Err(InvalidMediaType::Unknown(Unknown(s))),
                Err(_) => Err(InvalidMediaType::NotAString),
            },
        }
    }
}

/// Representation configuration.
pub enum Options {
    Json,
    JsonLd(json_ld::Options),
}

impl Options {
    pub fn from_media_type(
        type_: MediaType,
        json_ld_options: impl FnOnce() -> json_ld::Options,
    ) -> Self {
        match type_ {
            MediaType::Json => Self::Json,
            MediaType::JsonLd => Self::JsonLd(json_ld_options()),
        }
    }
}
