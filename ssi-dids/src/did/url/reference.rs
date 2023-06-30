use std::borrow::Cow;

use serde::{Deserialize, Serialize};

use crate::DID;

use super::{relative::RelativeDIDURLBuf, DIDURLBuf, RelativeDIDURL, DIDURL};

pub enum DIDURLReference<'a> {
    Absolute(&'a DIDURL),
    Relative(&'a RelativeDIDURL),
}

impl<'a> DIDURLReference<'a> {
    pub fn resolve(&self, base_id: &DID) -> Cow<DIDURL> {
        match self {
            Self::Absolute(a) => Cow::Borrowed(a),
            Self::Relative(r) => Cow::Owned(r.resolve(base_id)),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
pub enum DIDURLReferenceBuf {
    Absolute(DIDURLBuf),
    Relative(RelativeDIDURLBuf),
}

impl DIDURLReferenceBuf {
    pub fn as_did_reference(&self) -> DIDURLReference {
        match self {
            Self::Absolute(a) => DIDURLReference::Absolute(a),
            Self::Relative(r) => DIDURLReference::Relative(r),
        }
    }

    pub fn resolve(&self, base_id: &DID) -> Cow<DIDURL> {
        match self {
            Self::Absolute(a) => Cow::Borrowed(a.as_did_url()),
            Self::Relative(r) => Cow::Owned(r.resolve(base_id)),
        }
    }
}

impl From<DIDURLBuf> for DIDURLReferenceBuf {
    fn from(value: DIDURLBuf) -> Self {
        Self::Absolute(value)
    }
}

impl From<RelativeDIDURLBuf> for DIDURLReferenceBuf {
    fn from(value: RelativeDIDURLBuf) -> Self {
        Self::Relative(value)
    }
}
