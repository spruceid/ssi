use std::collections::HashMap as Map;
use std::convert::TryFrom;

use chrono::prelude::*;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::{json, Value};

// ********************************************
// * Data Structures for Verifiable Credentials
// * W3C Editor's Draft 15 January 2020
// * https://w3c.github.io/vc-data-model/
// ********************************************
// @TODO items:
// - `id` fields must all be URIs

pub const DEFAULT_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Credential {
    #[serde(rename = "@context")]
    pub context: Contexts,
    pub id: String,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    pub credential_subject: Subjects,
    pub issuer: Issuer,
    pub issuance_date: DateTime<Utc>, // must be RFC3339
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proofs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_date: Option<DateTime<Utc>>, // must be RFC3339
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_status: Option<Status>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub terms_of_use: Option<Vec<TermsOfUse>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub evidence: Option<Evidences>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_schema: Option<Schemas>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub refresh_service: Option<RefreshServices>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
#[serde(try_from = "ContextsUnchecked")]
pub enum Contexts {
    One(Context),
    Many(Vec<Context>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ContextsUnchecked {
    One(Context),
    Many(Vec<Context>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Context {
    URI(URI),
    Object(Map<String, Value>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Subjects {
    One(Subject),
    Many(Vec<Subject>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Subject {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Issuer {
    URI(URI),
    Object(ObjectWithId),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ObjectWithId {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Proofs {
    One(Proof),
    Many(Vec<Proof>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proof {
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TermsOfUse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Evidences {
    One(Evidence),
    Many(Vec<Evidence>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Evidence {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub id: String,
    #[serde(rename = "type")]
    pub type_: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(try_from = "String")]
#[serde(untagged)]
pub enum URI {
    String(String),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Schemas {
    One(Schema),
    Many(Vec<Schemas>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Schema {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RefreshServices {
    One(RefreshService),
    Many(Vec<RefreshService>),
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RefreshService {
    pub id: URI,
    #[serde(rename = "type")]
    pub type_: String,
    #[serde(flatten)]
    pub property_set: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Presentation {
    #[serde(rename = "@context")]
    pub context: Vec<String>,
    #[serde(rename = "type")]
    pub type_: Vec<String>,
    // @TODO: credential must have credential_schema
    pub verifiable_credential: Vec<Credential>,
    // This field is populated only when using
    // embedded proofs such as LD-PROOF
    //   https://w3c-ccg.github.io/ld-proofs/
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proof: Option<Proofs>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub holder: Option<String>,
}

impl TryFrom<ContextsUnchecked> for Contexts {
    type Error = &'static str;
    fn try_from(context: ContextsUnchecked) -> Result<Self, Self::Error> {
        // first context must be the default
        match context {
            // @TODO: make more DRY
            ContextsUnchecked::One(context) => match context {
                Context::URI(URI::String(uri)) => {
                    if uri != DEFAULT_CONTEXT {
                        Err("Invalid context")
                    } else {
                        Ok(Contexts::One(Context::URI(URI::String(uri))))
                    }
                }
                _ => Err("Base context must be URI"),
            },
            ContextsUnchecked::Many(contexts) => {
                if contexts.len() == 0 {
                    return Err("Missing context");
                }
                let first_context = &contexts[0];
                match first_context {
                    Context::URI(URI::String(uri)) => {
                        if uri != DEFAULT_CONTEXT {
                            return Err("Invalid context");
                        }
                        Ok(Contexts::Many(contexts))
                    }
                    _ => Err("Base context must be URI"),
                }
            }
        }
    }
}

impl TryFrom<String> for URI {
    type Error = &'static str;
    fn try_from(uri: String) -> Result<Self, Self::Error> {
        // @TODO: more complete checking
        if uri.contains(":") {
            Ok(URI::String(uri))
        } else {
            Err("String is not a URI")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_from_json() {
        let doc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let id = "http://example.org/credentials/3731";
        let doc: Credential = serde_json::from_str(doc_str).unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(doc.id, id);
    }

    #[test]
    fn credential_multiple_contexts() {
        let doc_str = r###"{
            "@context": [
              "https://www.w3.org/2018/credentials/v1",
              "https://www.w3.org/2018/credentials/examples/v1"
            ],
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let doc: Credential = serde_json::from_str(doc_str).unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
        if let Contexts::Many(contexts) = doc.context {
            assert_eq!(contexts.len(), 2);
        } else {
            assert!(false);
        }
    }

    #[test]
    #[should_panic(expected = "Invalid context")]
    fn credential_invalid_context() {
        let doc_str = r###"{
            "@context": "https://example.org/invalid-context",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let doc: Credential = serde_json::from_str(doc_str).unwrap();
        println!("{}", serde_json::to_string_pretty(&doc).unwrap());
    }
}
