use std::collections::HashMap as Map;

use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::{json, Value};

// ***********************************************
// * Data Structures for Decentralized Identifiers
// * W3C Working Draft 29 May 2020
// * Accessed July 3, 2019
// * https://w3c.github.io/did-core/
// ***********************************************
// @TODO `id` must be URI

pub const DEFAULT_CONTEXT: &str = "https://www.w3.org/2019/did/v1";

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
    context: String,
    id: DID,
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    authentication: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<Vec<Service>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    public_key: Option<PublicKey>,
    #[serde(skip_serializing_if = "Option::is_none")]
    controller: Option<Controller>,
    #[serde(skip_serializing_if = "Option::is_none")]
    proof: Option<Proof>,
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
    id: String,
    #[serde(rename = "type")]
    type_: String,
    // Note: different than when the DID Document is the subject:
    //    The value of the controller property, which identifies the
    //    controller of the corresponding private key, MUST be a valid DID.
    controller: DID,
    #[serde(flatten)]
    property_set: Option<Map<String, Value>>,
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
    id: String,
    #[serde(rename = "type")]
    type_: String,
    service_endpoint: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

impl Default for Document {
    fn default() -> Self {
        Document {
            context: DEFAULT_CONTEXT.to_string(),
            id: "".to_string(),
            created: None,
            updated: None,
            authentication: None,
            service: None,
            public_key: None,
            controller: None,
            proof: None,
        }
    }
}

impl DocumentBuilder {
    fn validate(&self) -> Result<(), String> {
        // validate is called before defaults are assigned.
        // None means default will be used.
        if self.id == None || self.id == Some("".to_string()) {
            return Err("Missing document id".to_string());
        }
        if self.context != None && self.context != Some(DEFAULT_CONTEXT.to_string()) {
            return Err("Invalid context".to_string());
        }
        Ok(())
    }
}

impl Document {
    pub fn new(id: &str) -> Document {
        Document {
            context: DEFAULT_CONTEXT.to_string(),
            id: String::from(id),
            created: None,
            updated: None,
            authentication: None,
            service: None,
            public_key: None,
            controller: None,
            proof: None,
        }
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
    #[should_panic(expected = "Missing document id")]
    fn build_document_no_id() {
        let doc = DocumentBuilder::default().build().unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    }

    #[test]
    #[should_panic(expected = "Invalid context")]
    fn build_document_invalid_context() {
        let id = "did:test:deadbeefcafe";
        let doc = DocumentBuilder::default()
            .context("example:bad")
            .id(id)
            .build()
            .unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
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
