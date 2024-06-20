use serde::Serialize;

use crate::{Document, DID, DIDURL};

use super::DIDVerificationMethod;

/// Reference to an arbitrary resource in a DID document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Resource {
    /// DID document.
    Document(Document),

    /// Verification method.
    VerificationMethod(DIDVerificationMethod),
}

impl Resource {
    pub fn as_verification_method(&self) -> Option<&DIDVerificationMethod> {
        match self {
            Self::VerificationMethod(m) => Some(m),
            _ => None,
        }
    }

    pub fn into_verification_method(self) -> Result<DIDVerificationMethod, Self> {
        match self {
            Self::VerificationMethod(m) => Ok(m),
            other => Err(other),
        }
    }
}

/// Reference to an arbitrary resource in a DID document.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResourceRef<'a> {
    /// DID document.
    Document(&'a Document),

    /// Verification method.
    VerificationMethod(&'a DIDVerificationMethod),
}

pub trait UsesResource {
    fn uses_resource(&self, base_id: &DID, id: &DIDURL) -> bool;
}

impl<T: UsesResource> UsesResource for Option<T> {
    fn uses_resource(&self, base_did: &DID, id: &DIDURL) -> bool {
        self.as_ref().is_some_and(|t| t.uses_resource(base_did, id))
    }
}

impl<T: UsesResource> UsesResource for Vec<T> {
    fn uses_resource(&self, base_did: &DID, id: &DIDURL) -> bool {
        self.iter().any(|t| t.uses_resource(base_did, id))
    }
}

/// Find a resource definition.
pub trait FindResource {
    fn find_resource(&self, base_did: &DID, id: &DIDURL) -> Option<ResourceRef>;
}

impl<T: FindResource> FindResource for Option<T> {
    fn find_resource(&self, base_did: &DID, id: &DIDURL) -> Option<ResourceRef> {
        self.as_ref().and_then(|t| t.find_resource(base_did, id))
    }
}

impl<T: FindResource> FindResource for Vec<T> {
    fn find_resource(&self, base_did: &DID, id: &DIDURL) -> Option<ResourceRef> {
        self.iter().find_map(|t| t.find_resource(base_did, id))
    }
}

pub trait ExtractResource {
    fn extract_resource(self, base_did: &DID, id: &DIDURL) -> Option<Resource>;
}

impl<T: ExtractResource> ExtractResource for Option<T> {
    fn extract_resource(self, base_did: &DID, id: &DIDURL) -> Option<Resource> {
        self.and_then(|t| t.extract_resource(base_did, id))
    }
}

impl<T: ExtractResource> ExtractResource for Vec<T> {
    fn extract_resource(self, base_did: &DID, id: &DIDURL) -> Option<Resource> {
        self.into_iter()
            .find_map(|t| t.extract_resource(base_did, id))
    }
}
