use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use ssi_verification_methods_core::GenericVerificationMethod;

use crate::{DIDBuf, DIDURLBuf, DIDURLReference, DIDURLReferenceBuf, DID, DIDURL};

use super::{
    resource::{ExtractResource, FindResource, Resource, UsesResource},
    ResourceRef,
};

/// Reference to, or value of, a verification method.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum ValueOrReference {
    Reference(DIDURLReferenceBuf),
    /// Embedded verification method.
    Value(DIDVerificationMethod),
}

impl ValueOrReference {
    pub fn id(&self) -> DIDURLReference {
        match self {
            Self::Reference(r) => r.as_did_reference(),
            Self::Value(v) => DIDURLReference::Absolute(&v.id),
        }
    }

    pub fn as_value(&self) -> Option<&DIDVerificationMethod> {
        match self {
            Self::Value(v) => Some(v),
            _ => None,
        }
    }
}

impl From<DIDURLBuf> for ValueOrReference {
    fn from(value: DIDURLBuf) -> Self {
        Self::Reference(value.into())
    }
}

impl From<DIDURLReferenceBuf> for ValueOrReference {
    fn from(value: DIDURLReferenceBuf) -> Self {
        Self::Reference(value)
    }
}

impl From<DIDVerificationMethod> for ValueOrReference {
    fn from(value: DIDVerificationMethod) -> Self {
        Self::Value(value)
    }
}

impl UsesResource for ValueOrReference {
    fn uses_resource(&self, base_id: &DID, id: &DIDURL) -> bool {
        match self {
            Self::Reference(r) => *r.resolve(base_id) == *id,
            Self::Value(v) => v.uses_resource(base_id, id),
        }
    }
}

impl FindResource for ValueOrReference {
    fn find_resource(&self, base_did: &DID, id: &DIDURL) -> Option<ResourceRef> {
        match self {
            Self::Reference(_) => None,
            Self::Value(m) => m.find_resource(base_did, id),
        }
    }
}

impl ExtractResource for ValueOrReference {
    fn extract_resource(self, base_did: &DID, id: &DIDURL) -> Option<Resource> {
        match self {
            Self::Reference(_) => None,
            Self::Value(m) => m.extract_resource(base_did, id),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct DIDVerificationMethod {
    /// Verification method identifier.
    pub id: DIDURLBuf,

    /// type [property](https://www.w3.org/TR/did-core/#dfn-did-urls) of a verification method map.
    /// Should be registered in [DID Specification
    /// registries - Verification method types](https://www.w3.org/TR/did-spec-registries/#verification-method-types).
    #[serde(rename = "type")]
    pub type_: String,

    // Note: different than when the DID Document is the subject:
    //    The value of the controller property, which identifies the
    //    controller of the corresponding private key, MUST be a valid DID.
    /// [controller](https://w3c-ccg.github.io/ld-proofs/#controller) property of a verification
    /// method map.
    ///
    /// Not to be confused with the [controller](https://www.w3.org/TR/did-core/#dfn-controller) property of a DID document.
    pub controller: DIDBuf,

    /// Verification methods properties.
    #[serde(flatten)]
    pub properties: BTreeMap<String, serde_json::Value>,
}

impl DIDVerificationMethod {
    pub fn new(
        id: DIDURLBuf,
        type_: String,
        controller: DIDBuf,
        properties: BTreeMap<String, serde_json::Value>,
    ) -> Self {
        Self {
            id,
            type_,
            controller,
            properties,
        }
    }
}

impl From<DIDVerificationMethod> for GenericVerificationMethod {
    fn from(value: DIDVerificationMethod) -> Self {
        GenericVerificationMethod {
            id: value.id.into(),
            type_: value.type_,
            controller: value.controller.into(),
            properties: value.properties,
        }
    }
}

impl UsesResource for DIDVerificationMethod {
    fn uses_resource(&self, _base_did: &DID, id: &DIDURL) -> bool {
        self.id == *id
    }
}

impl FindResource for DIDVerificationMethod {
    fn find_resource(&self, _base_did: &DID, id: &DIDURL) -> Option<ResourceRef> {
        if self.id == *id {
            Some(ResourceRef::VerificationMethod(self))
        } else {
            None
        }
    }
}

impl ExtractResource for DIDVerificationMethod {
    fn extract_resource(self, _base_did: &DID, id: &DIDURL) -> Option<Resource> {
        if self.id == *id {
            Some(Resource::VerificationMethod(self))
        } else {
            None
        }
    }
}
