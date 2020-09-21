use std::collections::HashMap as Map;
use std::convert::TryFrom;

use crate::error::Error;
use crate::one_or_many::OneOrMany;

use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;

// ***********************************************
// * Data Structures for Decentralized Identifiers
// * W3C Working Draft 29 May 2020
// * Accessed July 3, 2019
// * https://w3c.github.io/did-core/
// ***********************************************
// @TODO `id` must be URI

pub const DEFAULT_CONTEXT: &str = "https://www.w3.org/ns/did/v1";

// v0.11 context used by universal resolver
pub const V0_11_CONTEXT: &str = "https://w3id.org/did/v0.11";

// @TODO parsed data structs for DID and DIDURL
type DID = String;
type DIDURL = String;

#[derive(Debug, Serialize, Deserialize, Builder, Clone)]
#[serde(rename_all = "camelCase")]
#[builder(
    setter(into, strip_option),
    default,
    build_fn(validate = "Self::validate")
)]
pub struct Document {
    #[serde(rename = "@context")]
    pub context: Contexts,
    pub id: DID,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<Controller>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
#[serde(try_from = "OneOrMany<String>")]
pub enum Contexts {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum PublicKey {
    One(PublicKeyEntry),
    Many(Vec<PublicKeyEntry>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum PublicKeyEntry {
    DIDURL(DIDURL),
    PublicKeyObject(PublicKeyObject),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyObject {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    // Note: different than when the DID Document is the subject:
    //    The value of the controller property, which identifies the
    //    controller of the corresponding private key, MUST be a valid DID.
    pub controller: DID,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum VerificationMethod {
    DIDURL(DIDURL),
    PublicKey(PublicKey),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum Controller {
    One(DID),
    Many(Vec<DID>),
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    pub service_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

impl Default for Document {
    fn default() -> Self {
        Document {
            context: Contexts::One(DEFAULT_CONTEXT.to_string()),
            id: "".to_string(),
            created: None,
            updated: None,
            authentication: None,
            service: None,
            public_key: None,
            controller: None,
            proof: None,
            property_set: None,
        }
    }
}

impl TryFrom<OneOrMany<String>> for Contexts {
    type Error = Error;
    fn try_from(context: OneOrMany<String>) -> Result<Self, Self::Error> {
        let first_uri = match context.first() {
            None => return Err(Error::MissingContext),
            Some(uri) => uri,
        };
        if first_uri != DEFAULT_CONTEXT && first_uri != V0_11_CONTEXT {
            return Err(Error::InvalidContext);
        }
        Ok(match context {
            OneOrMany::One(context) => Contexts::One(context),
            OneOrMany::Many(contexts) => Contexts::Many(contexts),
        })
    }
}

impl From<Contexts> for OneOrMany<String> {
    fn from(contexts: Contexts) -> OneOrMany<String> {
        match contexts {
            Contexts::One(context) => OneOrMany::One(context),
            Contexts::Many(contexts) => OneOrMany::Many(contexts),
        }
    }
}

impl DocumentBuilder {
    fn validate(&self) -> Result<(), Error> {
        // validate is called before defaults are assigned.
        // None means default will be used.
        if self.id == None || self.id == Some("".to_string()) {
            return Err(Error::MissingDocumentId);
        }
        if let Some(first_context) = match &self.context {
            None => None,
            Some(Contexts::One(context)) => Some(context),
            Some(Contexts::Many(contexts)) => {
                if contexts.len() > 0 {
                    Some(&contexts[0])
                } else {
                    None
                }
            }
        } {
            if first_context != &DEFAULT_CONTEXT && first_context != &V0_11_CONTEXT {
                return Err(Error::InvalidContext);
            }
        }
        Ok(())
    }
}

impl Document {
    pub fn new(id: &str) -> Document {
        Document {
            context: Contexts::One(DEFAULT_CONTEXT.to_string()),
            id: String::from(id),
            created: None,
            updated: None,
            authentication: None,
            service: None,
            public_key: None,
            controller: None,
            proof: None,
            property_set: None,
        }
    }

    pub fn from_json(json: &str) -> Result<Document, serde_json::Error> {
        serde_json::from_str(json)
    }

    pub fn from_json_bytes(json: &[u8]) -> Result<Document, serde_json::Error> {
        serde_json::from_slice(json)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_document() {
        let id = "did:test:deadbeefcafe";
        let doc = Document::new(id);
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(doc.id, id);
    }

    #[test]
    fn build_document() {
        let id = "did:test:deadbeefcafe";
        let doc = DocumentBuilder::default()
            .id(id.to_owned())
            .build()
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(doc.id, id);
    }

    #[test]
    #[should_panic(expected = "Missing document ID")]
    fn build_document_no_id() {
        let doc = DocumentBuilder::default().build().unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    }

    #[test]
    #[should_panic(expected = "Invalid context")]
    fn build_document_invalid_context() {
        let id = "did:test:deadbeefcafe";
        let doc = DocumentBuilder::default()
            .context(Contexts::One("example:bad".to_string()))
            .id(id)
            .build()
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    }

    #[test]
    fn document_from_json() {
        let doc_str = "{\
            \"@context\": \"https://www.w3.org/ns/did/v1\",\
            \"id\": \"did:test:deadbeefcafe\"\
        }";
        let id = "did:test:deadbeefcafe";
        let doc = Document::from_json(doc_str).unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(doc.id, id);
    }

    #[test]
    fn public_key() {
        let id = "did:test:deadbeefcafe";
        let mut doc = Document::new(id);
        doc.public_key = Some(PublicKey::One(PublicKeyEntry::DIDURL(String::from(
            "did:pubkey:okay",
        ))));
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        let pko = PublicKeyObject {
            id: String::from("did:example:123456789abcdefghi#keys-1"),
            type_: String::from("RSASignature2019"),
            controller: String::from("did:example:123456789abcdefghi"),
            property_set: None,
        };
        doc.public_key = Some(PublicKey::Many(vec![
            PublicKeyEntry::DIDURL(String::from("did:pubkey:okay")),
            PublicKeyEntry::PublicKeyObject(pko),
        ]));
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(doc.id, id);
    }
}
