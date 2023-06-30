use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

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
    Value(AnyVerificationMethod),
}

impl ValueOrReference {
    pub fn id(&self) -> DIDURLReference {
        match self {
            Self::Reference(r) => r.as_did_reference(),
            Self::Value(v) => DIDURLReference::Absolute(&v.id),
        }
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

pub trait VerificationMethod {
    fn id(&self) -> &DIDURL;

    fn type_(&self) -> &str;

    fn controller(&self) -> &DID;
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
pub struct AnyVerificationMethod {
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

impl AnyVerificationMethod {
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

impl UsesResource for AnyVerificationMethod {
    fn uses_resource(&self, _base_did: &DID, id: &DIDURL) -> bool {
        self.id == *id
    }
}

impl FindResource for AnyVerificationMethod {
    fn find_resource(&self, _base_did: &DID, id: &DIDURL) -> Option<ResourceRef> {
        if self.id == *id {
            Some(ResourceRef::VerificationMethod(self))
        } else {
            None
        }
    }
}

impl ExtractResource for AnyVerificationMethod {
    fn extract_resource(self, _base_did: &DID, id: &DIDURL) -> Option<Resource> {
        if self.id == *id {
            Some(Resource::VerificationMethod(self))
        } else {
            None
        }
    }
}

// impl VerificationMethod {
//     /// Return a DID URL for this verification method, given a DID as base URI.
//     pub fn get_id(&self, did: &str) -> String {
//         match self {
//             Self::DIDURL(didurl) => didurl.to_string(),
//             Self::RelativeDIDURL(relative_did_url) => relative_did_url.to_absolute(did).to_string(),
//             Self::Map(map) => map.get_id(did),
//         }
//     }
// }

// impl VerificationMethodMap {
//     /// Return a DID URL for this verification method, given a DID as base URI
//     pub fn get_id(&self, did: &str) -> String {
//         if let Ok(rel_did_url) = RelativeDIDURL::from_str(&self.id) {
//             rel_did_url.to_absolute(did).to_string()
//         } else {
//             self.id.to_string()
//         }
//     }

//     /// Get the verification material as a JWK, from the publicKeyJwk property, or converting from other
//     /// public key properties as needed.
//     pub fn get_jwk(&self) -> Result<JWK, Error> {
//         let pk_hex_value = self
//             .property_set
//             .as_ref()
//             .and_then(|cc| cc.get("publicKeyHex"));
//         let pk_multibase_opt = match self.property_set {
//             Some(ref props) => match props.get("publicKeyMultibase") {
//                 Some(Value::String(string)) => Some(string.clone()),
//                 Some(Value::Null) => None,
//                 Some(_) => return Err(Error::ExpectedStringPublicKeyMultibase),
//                 None => None,
//             },
//             None => None,
//         };
//         let pk_bytes = match (
//             self.public_key_jwk.as_ref(),
//             self.public_key_base58.as_ref(),
//             pk_hex_value,
//             pk_multibase_opt,
//         ) {
//             (Some(pk_jwk), None, None, None) => return Ok(pk_jwk.clone()),
//             (None, Some(pk_bs58), None, None) => bs58::decode(&pk_bs58).into_vec()?,
//             (None, None, Some(pk_hex), None) => {
//                 let pk_hex = match pk_hex {
//                     Value::String(string) => string,
//                     _ => return Err(Error::HexString),
//                 };
//                 let pk_hex = pk_hex.strip_prefix("0x").unwrap_or(pk_hex);
//                 hex::decode(pk_hex)?
//             }
//             (None, None, None, Some(pk_mb)) => multibase::decode(pk_mb)?.1,
//             (None, None, None, None) => return Err(Error::MissingKey),
//             _ => {
//                 // https://w3c.github.io/did-core/#verification-material
//                 // "expressing key material in a verification method using both publicKeyJwk and
//                 // publicKeyBase58 at the same time is prohibited."
//                 return Err(Error::MultipleKeyMaterial);
//             }
//         };
//         Ok(ssi_jwk::JWK::from_vm_type(&self.type_, pk_bytes)?)
//     }

//     /// Verify that a given JWK can be used to satisfy this verification method.
//     pub fn match_jwk(&self, jwk: &JWK) -> Result<(), Error> {
//         if let Some(ref account_id) = self.blockchain_account_id {
//             let account_id = BlockchainAccountId::from_str(account_id)?;
//             account_id.verify(jwk)?;
//         } else {
//             let resolved_jwk = self.get_jwk()?;
//             if !resolved_jwk.equals_public(jwk) {
//                 return Err(Error::KeyMismatch);
//             }
//         }
//         Ok(())
//     }
// }
