/*
To generate test vectors:
    ln -s ../did-test-suite/packages/did-core-test-server/suites/implementations impl
    cargo run --example did-test-suite
    cargo run --example did-test-suite did key > impl/did-key-spruce.json
    cargo run --example did-test-suite did pkh > impl/did-pkh.json
    cargo run --example did-test-suite did web > impl/did-web-spruce.json
    cargo run --example did-test-suite did webkey > impl/did-webkey.json
    cargo run --example did-test-suite resolver pkh > impl/resolver-pkh.json
    cargo run --example did-test-suite resolver key > impl/resolver-spruce-key.json
    cargo run --example did-test-suite resolver web > impl/resolver-spruce-web.json
    cargo run --example did-test-suite resolver webkey > impl/resolver-webkey.json
*/

use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::BTreeMap as Map;

use ssi::did::DIDURL;
use ssi::did_resolve::{DocumentMetadata, ResolutionMetadata};

type DID = String;
type ContentType = String;

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct RepresentationSpecificEntries {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDDocumentDataModel {
    pub properties: Map<String, Value>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDDocumentDataModel2 {
    pub representation_specific_entries: RepresentationSpecificEntries,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDData {
    pub did_document_data_model: DIDDocumentDataModel2,
    pub representation: String,
    pub did_document_metadata: DocumentMetadata,
    pub did_resolution_metadata: ResolutionMetadata,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDVector {
    pub did_document_data_model: DIDDocumentDataModel,
    #[serde(flatten)]
    pub did_data: Map<ContentType, DIDData>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDImplementation {
    pub did_method: String,
    pub implementation: String,
    pub implementer: String,
    pub supported_content_types: Vec<ContentType>,
    pub dids: Vec<DID>,
    pub did_parameters: Map<String, DIDURL>,
    #[serde(flatten)]
    pub did_vectors: Map<DID, DIDVector>,
}

#[async_std::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let section = args.next().unwrap();
    let method = args.next().unwrap();
    args.next().ok_or(()).unwrap_err();
    let writer = std::io::BufWriter::new(std::io::stdout());
    // serde_json::to_writer_pretty(writer, &value).unwrap();
}
