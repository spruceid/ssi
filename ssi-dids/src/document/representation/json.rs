use std::{ops::Deref, str::FromStr};

use serde::{Deserialize, Serialize};

use crate::Document;

/// DID document represented as a JSON document.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Json<D = Document>(D);

impl<D> Json<D> {
    pub fn new(document: D) -> Self {
        Self(document)
    }

    pub fn document(&self) -> &D {
        &self.0
    }

    pub fn into_document(self) -> D {
        self.0
    }
}

impl<D: Serialize> Json<D> {
    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(&self).unwrap()
    }
}

impl Json {
    /// Construct a DID document from JSON bytes.
    pub fn from_bytes(json: &[u8]) -> Result<Self, serde_json::Error> {
        serde_json::from_slice(json)
    }
}

impl FromStr for Json {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl<D> Deref for Json<D> {
    type Target = D;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
