use std::collections::HashMap as Map;
use std::convert::TryFrom;

use crate::error::Error;
use crate::jwk::JWK;
use crate::one_or_many::OneOrMany;

use serde::{Deserialize, Serialize};
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(try_from = "String")]
#[serde(into = "String")]
pub struct DIDURL {
    pub did: String,
    pub path_abempty: String,
    pub query: Option<String>,
    pub fragment: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Builder, Clone, PartialEq)]
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
    pub also_known_as: Option<Vec<String>>, // TODO: URI
    #[serde(skip_serializing_if = "Option::is_none")]
    pub controller: Option<OneOrMany<DID>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub verification_method: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authentication: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assertion_method: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_agreement: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_invocation: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_delegation: Option<Vec<VerificationMethod>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<Vec<Service>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proof>,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(untagged)]
#[serde(try_from = "OneOrMany<String>")]
pub enum Contexts {
    One(String),
    Many(Vec<String>),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct VerificationMethodMap {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
    // Note: different than when the DID Document is the subject:
    //    The value of the controller property, which identifies the
    //    controller of the corresponding private key, MUST be a valid DID.
    pub controller: DID,
    #[serde(skip_serializing_if = "Option::is_none")]
    // TODO: make sure this JWK does not have private key material
    pub public_key_jwk: Option<JWK>,
    #[serde(skip_serializing_if = "Option::is_none")]
    // TODO: make Base58 type like Base64urlUIntString
    pub public_key_base58: Option<String>,
    // TODO: ensure that not both key parameters are set
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum VerificationMethod {
    DIDURL(DIDURL),
    Map(VerificationMethodMap),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
#[serde(untagged)]
pub enum ServiceEndpoint {
    URI(String),
    Map(Value),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Service {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: OneOrMany<String>, // TODO: set
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_endpoint: Option<OneOrMany<ServiceEndpoint>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

impl TryFrom<String> for DIDURL {
    type Error = Error;
    fn try_from(s: String) -> Result<Self, Self::Error> {
        if !s.starts_with("did:") {
            return Err(Error::DIDURL);
        }
        let mut parts = s.splitn(2, '#');
        let before_fragment = parts.next().unwrap().to_string();
        let fragment = parts.next().map(|x| x.to_owned());
        let mut parts = before_fragment.splitn(2, '?');
        let before_query = parts.next().unwrap().to_string();
        let query = parts.next().map(|x| x.to_owned());
        let (did, path_abempty) = match before_query.find('/') {
            Some(i) => match before_query.split_at(i) {
                (did, path_abempty) => (did.to_string(), path_abempty.to_string()),
            },
            None => (before_query, "".to_string()),
        };
        Ok(Self {
            did,
            path_abempty,
            query,
            fragment,
        })
    }
}

impl From<DIDURL> for String {
    fn from(didurl: DIDURL) -> String {
        let mut didurl_string = didurl.did.to_owned() + &didurl.path_abempty;
        if let Some(ref query) = didurl.query {
            didurl_string.push('?');
            didurl_string.push_str(query);
        }
        if let Some(ref fragment) = didurl.fragment {
            didurl_string.push('#');
            didurl_string.push_str(fragment);
        }
        didurl_string
    }
}

impl Default for Document {
    fn default() -> Self {
        Document::new("")
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
                if !contexts.is_empty() {
                    Some(&contexts[0])
                } else {
                    None
                }
            }
        } {
            if first_context != DEFAULT_CONTEXT && first_context != V0_11_CONTEXT {
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
            also_known_as: None,
            controller: None,
            verification_method: None,
            authentication: None,
            assertion_method: None,
            key_agreement: None,
            capability_invocation: None,
            capability_delegation: None,
            service: None,
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
    fn parse_did_url() {
        // https://w3c.github.io/did-core/#example-3-a-did-url-with-a-service-did-parameter
        let didurl_str = "did:foo:21tDAKCERh95uGgKbJNHYp?service=agent";
        let didurl = DIDURL::try_from(didurl_str.to_string()).unwrap();
        assert_eq!(
            didurl,
            DIDURL {
                did: "did:foo:21tDAKCERh95uGgKbJNHYp".to_string(),
                path_abempty: "".to_string(),
                query: Some("service=agent".to_string()),
                fragment: None,
            }
        );
    }

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
    fn verification_method() {
        let id = "did:test:deadbeefcafe";
        let mut doc = Document::new(id);
        doc.verification_method = Some(vec![VerificationMethod::DIDURL(
            DIDURL::try_from("did:pubkey:okay".to_string()).unwrap(),
        )]);
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        let pko = VerificationMethodMap {
            id: String::from("did:example:123456789abcdefghi#keys-1"),
            type_: String::from("Ed25519VerificationKey2018"),
            controller: String::from("did:example:123456789abcdefghi"),
            public_key_jwk: None,
            public_key_base58: None,
            property_set: None,
        };
        doc.verification_method = Some(vec![
            VerificationMethod::DIDURL(DIDURL::try_from("did:pubkey:okay".to_string()).unwrap()),
            VerificationMethod::Map(pko),
        ]);
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(doc.id, id);
    }
}
