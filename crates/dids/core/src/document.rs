use std::{collections::BTreeMap, str::FromStr};

use iref::IriBuf;
use serde::{Deserialize, Serialize};
use ssi_core::one_or_many::OneOrMany;
use ssi_verification_methods_core::{ProofPurpose, ProofPurposes};

use crate::{DIDBuf, DIDURLReferenceBuf, DID, DIDURL};

pub mod representation;
pub mod resource;
pub mod service;
pub mod verification_method;

pub use representation::Represented;
pub use resource::{Resource, ResourceRef};
pub use service::Service;
pub use verification_method::DIDVerificationMethod;

use self::resource::{ExtractResource, FindResource};

/// A [DID document]
///
/// [DID document]: https://www.w3.org/TR/did-core/#dfn-did-documents
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct Document {
    /// DID subject identifier.
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-subject>
    pub id: DIDBuf,

    /// Other URIs for the DID subject.
    ///
    /// See: <https://www.w3.org/TR/did-core/#also-known-as>
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub also_known_as: Vec<IriBuf>,

    /// Verification relationships.
    ///
    /// Properties that express the relationship between the DID subject and a
    /// verification method using a verification relationship.
    ///
    /// See: <https://www.w3.org/TR/did-core/#verification-relationships>
    #[serde(flatten)]
    pub verification_relationships: VerificationRelationships,

    /// Controllers(s).
    ///
    /// See: <https://www.w3.org/TR/did-core/#did-controller>
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<OneOrMany<DIDBuf>>,

    /// [`verificationMethod`](https://www.w3.org/TR/did-core/#dfn-verificationmethod) property of a
    /// DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verification_method: Vec<DIDVerificationMethod>,

    /// [`publicKey`](https://www.w3.org/TR/did-spec-registries/#publickey) property of a DID
    /// document (deprecated in favor of `verificationMethod`).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub public_key: Vec<DIDVerificationMethod>,

    /// `service` property of a DID document, expressing
    /// [services](https://www.w3.org/TR/did-core/#services), generally as endpoints.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub service: Vec<Service>,

    /// Additional properties of a DID document. Some may be registered in [DID Specification
    /// Registries](https://www.w3.org/TR/did-spec-registries/#did-document-properties).
    #[serde(flatten)]
    pub property_set: BTreeMap<String, serde_json::Value>,
}

impl Document {
    /// Construct a new DID document with the given id (DID).
    pub fn new(id: DIDBuf) -> Document {
        Document {
            id,
            also_known_as: Vec::new(),
            controller: None,
            verification_method: Vec::new(),
            verification_relationships: VerificationRelationships::default(),
            service: Vec::new(),
            property_set: BTreeMap::new(),
            public_key: Vec::new(),
        }
    }

    /// Construct a DID document from JSON.
    pub fn from_json(json: &str) -> Result<representation::Json, serde_json::Error> {
        representation::Json::from_str(json)
    }

    /// Construct a DID document from JSON bytes.
    pub fn from_json_bytes(json: &[u8]) -> Result<representation::Json, serde_json::Error> {
        representation::Json::from_bytes(json)
    }

    pub fn from_bytes(
        type_: representation::MediaType,
        bytes: &[u8],
    ) -> Result<Represented, InvalidData> {
        match type_ {
            representation::MediaType::Json => Ok(Represented::Json(
                representation::Json::from_bytes(bytes).map_err(InvalidData::Json)?,
            )),
            representation::MediaType::JsonLd => Ok(Represented::JsonLd(
                representation::JsonLd::from_bytes(bytes).map_err(InvalidData::JsonLd)?,
            )),
        }
    }

    /// Select an object in the DID document.
    ///
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary>
    pub fn find_resource(&self, id: &DIDURL) -> Option<ResourceRef> {
        if self.id == *id {
            Some(ResourceRef::Document(self))
        } else {
            self.verification_method
                .find_resource(&self.id, id)
                .or_else(|| self.verification_relationships.find_resource(&self.id, id))
        }
    }

    /// Select an object in the DID document.
    ///
    /// See: <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary>
    pub fn into_resource(self, id: &DIDURL) -> Option<Resource> {
        if self.id == *id {
            Some(Resource::Document(self))
        } else {
            self.verification_method
                .extract_resource(&self.id, id)
                .or_else(|| {
                    self.verification_relationships
                        .extract_resource(&self.id, id)
                })
        }
    }

    /// Returns the service with the given `id`, if any.
    pub fn service(&self, id: &str) -> Option<&Service> {
        self.service
            .iter()
            .find(|s| s.id.fragment().is_some_and(|f| f.as_str() == id))
    }

    pub fn into_representation(self, options: representation::Options) -> Represented {
        Represented::new(self, options)
    }

    /// Consumes the document and returns any verification method in contains.
    ///
    /// This will return the first verification method found, although users
    /// should not expect the DID documents to always list verification methods
    /// in the same order.
    pub fn into_any_verification_method(self) -> Option<DIDVerificationMethod> {
        self.verification_method.into_iter().next()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid DID document representation data")]
pub enum InvalidData {
    Json(serde_json::Error),
    JsonLd(serde_json::Error),
}

/// Document metadata.
#[derive(Debug, Default, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub deactivated: Option<bool>,
}

#[derive(Debug, Default, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationRelationships {
    /// [`authentication`](https://www.w3.org/TR/did-core/#dfn-authentication) property of a DID
    /// document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [authentication](https://www.w3.org/TR/did-core/#authentication) purposes (e.g. generating verifiable presentations).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authentication: Vec<verification_method::ValueOrReference>,

    /// [`assertionMethod`](https://www.w3.org/TR/did-core/#dfn-assertionmethod) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [assertion](https://www.w3.org/TR/did-core/#assertion) purposes (e.g. issuing verifiable credentials).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub assertion_method: Vec<verification_method::ValueOrReference>,

    /// [`keyAgreement`](https://www.w3.org/TR/did-core/#dfn-keyagreement) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [key agreement](https://www.w3.org/TR/did-core/#key-agreement) purposes.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub key_agreement: Vec<verification_method::ValueOrReference>,

    /// [`capabilityInvocation`](https://www.w3.org/TR/did-core/#dfn-capabilityinvocation) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [invoking cryptographic capabilities](https://www.w3.org/TR/did-core/#capability-invocation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_invocation: Vec<verification_method::ValueOrReference>,

    /// [`capabilityDelegation`](https://www.w3.org/TR/did-core/#dfn-capabilitydelegation) property of a DID document, expressing [verification
    /// methods](https://www.w3.org/TR/did-core/#verification-methods) for
    /// [delegating cryptographic capabilities](https://www.w3.org/TR/did-core/#capability-delegation).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub capability_delegation: Vec<verification_method::ValueOrReference>,
}

impl VerificationRelationships {
    pub fn proof_purpose(&self, purpose: ProofPurpose) -> &[verification_method::ValueOrReference] {
        match purpose {
            ProofPurpose::Authentication => &self.authentication,
            ProofPurpose::Assertion => &self.assertion_method,
            ProofPurpose::KeyAgreement => &self.key_agreement,
            ProofPurpose::CapabilityInvocation => &self.capability_invocation,
            ProofPurpose::CapabilityDelegation => &self.capability_delegation,
        }
    }

    pub fn contains(&self, base_did: &DID, id: &DIDURL, proof_purposes: ProofPurposes) -> bool {
        for p in proof_purposes {
            for v in self.proof_purpose(p) {
                if *v.id().resolve(base_did) == *id {
                    return true;
                }
            }
        }

        false
    }

    /// Creates verification relationships by putting the given method reference
    /// into all the relations selected by `proof_purposes`.
    pub fn from_reference(vm_reference: DIDURLReferenceBuf, proof_purposes: ProofPurposes) -> Self {
        Self {
            authentication: if proof_purposes.contains(ProofPurpose::Authentication) {
                vec![verification_method::ValueOrReference::Reference(
                    vm_reference.clone(),
                )]
            } else {
                Vec::new()
            },
            key_agreement: if proof_purposes.contains(ProofPurpose::KeyAgreement) {
                vec![verification_method::ValueOrReference::Reference(
                    vm_reference.clone(),
                )]
            } else {
                Vec::new()
            },
            capability_invocation: if proof_purposes.contains(ProofPurpose::CapabilityInvocation) {
                vec![verification_method::ValueOrReference::Reference(
                    vm_reference.clone(),
                )]
            } else {
                Vec::new()
            },
            capability_delegation: if proof_purposes.contains(ProofPurpose::CapabilityDelegation) {
                vec![verification_method::ValueOrReference::Reference(
                    vm_reference.clone(),
                )]
            } else {
                Vec::new()
            },
            assertion_method: if proof_purposes.contains(ProofPurpose::Assertion) {
                vec![verification_method::ValueOrReference::Reference(
                    vm_reference,
                )]
            } else {
                Vec::new()
            },
        }
    }
}

impl FindResource for VerificationRelationships {
    fn find_resource(&self, base_did: &DID, id: &DIDURL) -> Option<ResourceRef> {
        self.authentication
            .find_resource(base_did, id)
            .or_else(|| self.assertion_method.find_resource(base_did, id))
            .or_else(|| self.key_agreement.find_resource(base_did, id))
            .or_else(|| self.capability_invocation.find_resource(base_did, id))
            .or_else(|| self.capability_delegation.find_resource(base_did, id))
    }
}

impl ExtractResource for VerificationRelationships {
    fn extract_resource(self, base_did: &DID, id: &DIDURL) -> Option<Resource> {
        self.authentication
            .extract_resource(base_did, id)
            .or_else(|| self.assertion_method.extract_resource(base_did, id))
            .or_else(|| self.key_agreement.extract_resource(base_did, id))
            .or_else(|| self.capability_invocation.extract_resource(base_did, id))
            .or_else(|| self.capability_delegation.extract_resource(base_did, id))
    }
}
