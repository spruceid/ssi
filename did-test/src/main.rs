use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap as Map, HashMap};
use std::env::Args;
use std::str::FromStr;

use ssi_dids::{
    did_resolve::{
        dereference, Content, ContentMetadata, DIDResolver, DereferencingInputMetadata,
        DereferencingMetadata, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
        ERROR_INVALID_DID, ERROR_INVALID_DID_URL, ERROR_NOT_FOUND,
        ERROR_REPRESENTATION_NOT_SUPPORTED, TYPE_DID_LD_JSON,
    },
    Document, DIDURL,
};

#[allow(clippy::upper_case_acronyms)]
type DID = String;
type ContentType = String;

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Hash)]
#[serde(rename_all = "camelCase")]
pub enum ResolverOutcome {
    DefaultOutcome,
    #[serde(rename = "invalidDidErrorOutcome")]
    InvalidDIDErrorOutcome,
    #[serde(rename = "invalidDidUrlErrorOutcome")]
    InvalidDIDURLErrorOutcome,
    NotFoundErrorOutcome,
    RepresentationNotSupportedErrorOutcome,
    DeactivatedOutcome,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ResolverFunction {
    Resolve,
    ResolveRepresentation,
    Dereference,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ExecutionInput {
    #[serde(rename_all = "camelCase")]
    Resolve {
        did: DID,
        resolution_options: ResolutionInputMetadata,
    },
    #[serde(rename_all = "camelCase")]
    Dereference {
        did_url: DID,
        dereference_options: DereferencingInputMetadata,
    },
}

#[allow(clippy::large_enum_variant)]
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ExecutionOutput {
    #[serde(rename_all = "camelCase")]
    Resolve {
        did_document: Option<Document>,
        did_resolution_metadata: ResolutionMetadata,
        did_document_metadata: DocumentMetadata,
    },
    #[serde(rename_all = "camelCase")]
    ResolveRepresentation {
        did_document_stream: String,
        did_resolution_metadata: ResolutionMetadata,
        did_document_metadata: DocumentMetadata,
    },
    #[serde(rename_all = "camelCase")]
    Dereference {
        dereferencing_metadata: DereferencingMetadata,
        content_stream: String,
        content_metadata: ContentMetadata,
    },
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResolverExecution {
    pub function: ResolverFunction,
    pub input: ExecutionInput,
    pub output: ExecutionOutput,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DIDResolverImplementation {
    pub did_method: String,
    pub implementation: String,
    pub implementer: String,
    pub expected_outcomes: HashMap<ResolverOutcome, Vec<usize>>,
    pub executions: Vec<ResolverExecution>,
}

async fn did_method_vector(resolver: &dyn DIDResolver, did: &str) -> DIDVector {
    let (res_meta, doc, doc_meta_opt) = resolver
        .resolve(did, &ResolutionInputMetadata::default())
        .await;
    assert_eq!(res_meta.error, None);
    let doc_meta = doc_meta_opt.unwrap();
    assert_eq!(res_meta.content_type, None);
    let mut did_data = Map::new();

    let input_meta = ResolutionInputMetadata {
        accept: Some(TYPE_DID_LD_JSON.to_string()),
        ..Default::default()
    };
    let (res_repr_meta, doc_repr, _doc_repr_meta_opt) =
        resolver.resolve_representation(did, &input_meta).await;
    assert_eq!(res_repr_meta.error, None);
    let representation = String::from_utf8(doc_repr).unwrap();
    let content_type = res_repr_meta.content_type.clone().unwrap();
    assert_eq!(content_type, TYPE_DID_LD_JSON);

    let mut doc_value = serde_json::to_value(doc).unwrap();
    let mut representation_specific_entries = RepresentationSpecificEntries::default();
    match &content_type[..] {
        TYPE_DID_LD_JSON => {
            representation_specific_entries.context =
                doc_value.as_object_mut().unwrap().remove("@context");
        }
        _ => unreachable!(),
    }
    let properties: Map<String, Value> = serde_json::from_value(doc_value).unwrap();
    let resolution_result = DIDData {
        did_document_data_model: DIDDocumentDataModel2 {
            representation_specific_entries,
        },
        representation,
        did_document_metadata: doc_meta,
        did_resolution_metadata: res_repr_meta,
    };
    did_data.insert(content_type, resolution_result);
    DIDVector {
        did_document_data_model: DIDDocumentDataModel { properties },
        did_data,
    }
}

async fn report_method_key() {
    let did_parameters = Map::new();
    let mut did_vectors = Map::new();
    let supported_content_types = vec![TYPE_DID_LD_JSON.to_string()];

    for did in &[
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", // Ed25519
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme", // Secp256k1
        "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169", // Secp256r1
    ] {
        let did_vector = did_method_vector(&did_method_key::DIDKey, did).await;
        did_vectors.insert(did.to_string(), did_vector);
    }

    let dids = did_vectors.keys().cloned().collect();
    let report = DIDImplementation {
        did_method: "did:key".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-key".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        supported_content_types,
        dids,
        did_parameters,
        did_vectors,
    };
    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_method_web() {
    let mut did_parameters = Map::new();
    did_parameters.insert(
        "service".to_string(),
        DIDURL::from_str("did:web:demo.spruceid.com:2021:07:14:service-example?service=hello")
            .unwrap(),
    );

    let mut did_vectors = Map::new();
    let supported_content_types = vec![TYPE_DID_LD_JSON.to_string()];

    let did = "did:web:demo.spruceid.com:2021:07:08";
    let did_vector = did_method_vector(&did_web::DIDWeb, did).await;
    did_vectors.insert(did.to_string(), did_vector);

    let dids = did_vectors.keys().cloned().collect();
    let report = DIDImplementation {
        did_method: "did:web".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-web".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        supported_content_types,
        dids,
        did_parameters,
        did_vectors,
    };
    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_method_tz() {
    let did_tz = did_tz::DIDTz::default();
    let did_parameters = Map::new();
    let mut did_vectors = Map::new();
    let supported_content_types = vec![TYPE_DID_LD_JSON.to_string()];

    for did in &[
        "did:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x",
        "did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq",
        "did:tz:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
        "did:tz:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
    ] {
        let did_vector = did_method_vector(&did_tz, did).await;
        did_vectors.insert(did.to_string(), did_vector);
    }

    let dids = did_vectors.keys().cloned().collect();
    let report = DIDImplementation {
        did_method: "did:tz".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-tezos".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        supported_content_types,
        dids,
        did_parameters,
        did_vectors,
    };
    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_method_onion() {
    let resolver = did_onion::DIDOnion::default();
    let did_parameters = Map::new();
    let mut did_vectors = Map::new();
    let supported_content_types = vec![TYPE_DID_LD_JSON.to_string()];

    {
        let did = &"did:onion:fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid";
        let did_vector = did_method_vector(&resolver, did).await;
        did_vectors.insert(did.to_string(), did_vector);
    }

    let dids = did_vectors.keys().cloned().collect();
    let report = DIDImplementation {
        did_method: "did:onion".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-onion".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        supported_content_types,
        dids,
        did_parameters,
        did_vectors,
    };
    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_method_pkh() {
    let resolver = did_pkh::DIDPKH;
    let did_parameters = Map::new();
    let mut did_vectors = Map::new();
    let supported_content_types = vec![TYPE_DID_LD_JSON.to_string()];

    for did in &[
        "did:pkh:doge:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",
        "did:pkh:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x",
        "did:pkh:eth:0xb9c5714089478a327f09197987f16f9e5d936e8a",
        "did:pkh:btc:128Lkh3S7CkDTBZ8W7BbpsN3YYizJMp8p6",
        "did:pkh:celo:0xa0ae58da58dfa46fa55c3b86545e7065f90ff011",
        "did:pkh:sol:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev",
    ] {
        let did_vector = did_method_vector(&resolver, did).await;
        did_vectors.insert(did.to_string(), did_vector);
    }

    let dids = did_vectors.keys().cloned().collect();
    let report = DIDImplementation {
        did_method: "did:pkh".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-pkh".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        supported_content_types,
        dids,
        did_parameters,
        did_vectors,
    };
    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_method_webkey() {
    let resolver = did_webkey::DIDWebKey;
    let did_parameters = Map::new();
    let mut did_vectors = Map::new();
    let supported_content_types = vec![TYPE_DID_LD_JSON.to_string()];

    {
        let did = &"did:webkey:ssh:demo.spruceid.com:2021:07:14:keys";
        let did_vector = did_method_vector(&resolver, did).await;
        did_vectors.insert(did.to_string(), did_vector);
    }

    let dids = did_vectors.keys().cloned().collect();
    let report = DIDImplementation {
        did_method: "did:webkey".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-webkey".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        supported_content_types,
        dids,
        did_parameters,
        did_vectors,
    };
    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

impl ResolverOutcome {
    fn from_error_or_deactivated(error: Option<String>, deactivated: Option<bool>) -> Self {
        if let Some(error) = error {
            match &error[..] {
                ERROR_INVALID_DID => return Self::InvalidDIDErrorOutcome,
                ERROR_INVALID_DID_URL => return Self::InvalidDIDURLErrorOutcome,
                ERROR_REPRESENTATION_NOT_SUPPORTED => {
                    return Self::RepresentationNotSupportedErrorOutcome
                }
                ERROR_NOT_FOUND => return Self::NotFoundErrorOutcome,
                _ => panic!("Unknown outcome for error: {error}"),
            }
        }
        if deactivated == Some(true) {
            return Self::DeactivatedOutcome;
        }
        Self::DefaultOutcome
    }
}

impl DIDResolverImplementation {
    async fn resolve(
        &mut self,
        resolver: &dyn DIDResolver,
        did: &str,
        options: &ResolutionInputMetadata,
    ) {
        let (res_meta, doc_opt, doc_meta_opt) = resolver.resolve(did, options).await;
        let input = ExecutionInput::Resolve {
            did: did.to_string(),
            resolution_options: options.to_owned(),
        };
        let error_opt = res_meta.error.clone();
        let doc_meta = doc_meta_opt.unwrap_or_default();
        let deactivated_opt = doc_meta.deactivated;
        let output = ExecutionOutput::Resolve {
            did_document: doc_opt,
            did_resolution_metadata: res_meta,
            did_document_metadata: doc_meta,
        };
        let execution = ResolverExecution {
            function: ResolverFunction::Resolve,
            input,
            output,
        };
        self.add_execution(execution, error_opt, deactivated_opt);
    }

    async fn resolve_representation(
        &mut self,
        resolver: &dyn DIDResolver,
        did: &str,
        options: &ResolutionInputMetadata,
    ) {
        let (res_meta, doc_repr, doc_meta_opt) =
            resolver.resolve_representation(did, options).await;
        let representation = String::from_utf8(doc_repr).unwrap();
        let input = ExecutionInput::Resolve {
            did: did.to_string(),
            resolution_options: options.to_owned(),
        };
        let error_opt = res_meta.error.clone();
        let doc_meta = doc_meta_opt.unwrap_or_default();
        let deactivated_opt = doc_meta.deactivated;
        let output = ExecutionOutput::ResolveRepresentation {
            did_document_stream: representation,
            did_resolution_metadata: res_meta,
            did_document_metadata: doc_meta,
        };
        let execution = ResolverExecution {
            function: ResolverFunction::ResolveRepresentation,
            input,
            output,
        };
        self.add_execution(execution, error_opt, deactivated_opt);
    }

    async fn dereference(
        &mut self,
        resolver: &dyn DIDResolver,
        did_url: &str,
        options: &DereferencingInputMetadata,
    ) {
        let (deref_meta, content, content_meta) = dereference(resolver, did_url, options).await;
        let input = ExecutionInput::Dereference {
            did_url: did_url.to_string(),
            dereference_options: options.to_owned(),
        };
        let error_opt = deref_meta.error.clone();
        let deactivated_opt = if let ContentMetadata::DIDDocument(ref did_doc_meta) = content_meta {
            did_doc_meta.deactivated
        } else {
            None
        };
        let content_stream = match content {
            Content::DIDDocument(doc) => serde_json::to_string(&doc).unwrap(),
            Content::URL(url) => url,
            Content::Object(resource) => serde_json::to_string(&resource).unwrap(),
            Content::Data(vec) => String::from_utf8(vec).unwrap(),
            Content::Null => "".to_string(),
        };
        let output = ExecutionOutput::Dereference {
            dereferencing_metadata: deref_meta,
            content_stream,
            content_metadata: content_meta,
        };
        let execution = ResolverExecution {
            function: ResolverFunction::Dereference,
            input,
            output,
        };
        self.add_execution(execution, error_opt, deactivated_opt);
    }

    fn add_execution(
        &mut self,
        execution: ResolverExecution,
        error_opt: Option<String>,
        deactivated_opt: Option<bool>,
    ) {
        let i = self.executions.len();
        self.executions.push(execution);
        let outcome = ResolverOutcome::from_error_or_deactivated(error_opt, deactivated_opt);
        self.expected_outcomes.entry(outcome).or_default().push(i);
    }
}

async fn report_resolver_key() {
    let mut report = DIDResolverImplementation {
        did_method: "did:key".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-key".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did in &[
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH", // Ed25519
        "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme", // Secp256k1
        "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169", // Secp256r1
        "did:key;invalid", // should return invalidDid error
    ] {
        report
            .resolve(
                &did_method_key::DIDKey,
                did,
                &ResolutionInputMetadata::default(),
            )
            .await;
    }

    {
        let did = &"did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        report
            .resolve_representation(
                &did_method_key::DIDKey,
                did,
                &ResolutionInputMetadata::default(),
            )
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_resolver_web() {
    let mut report = DIDResolverImplementation {
        did_method: "did:web".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-web".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did in &[
        "did:web:identity.foundation",
        "did:web:did.actor:nonexistent",
    ] {
        report
            .resolve(&did_web::DIDWeb, did, &ResolutionInputMetadata::default())
            .await;
    }

    {
        let did = &"did:web:identity.foundation";
        report
            .resolve_representation(&did_web::DIDWeb, did, &ResolutionInputMetadata::default())
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_resolver_tz() {
    let did_tz = did_tz::DIDTz::default();
    let mut report = DIDResolverImplementation {
        did_method: "did:tz".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-tezos".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did in &[
        "did:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x",
        "did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq",
        "did:tz:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
        "did:tz:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
    ] {
        report
            .resolve(&did_tz, did, &ResolutionInputMetadata::default())
            .await;
    }

    {
        let did = &"did:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x";
        report
            .resolve_representation(&did_tz, did, &ResolutionInputMetadata::default())
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_resolver_onion() {
    let resolver = did_onion::DIDOnion::default();
    let mut report = DIDResolverImplementation {
        did_method: "did:onion".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-onion".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    {
        let did = &"did:onion:fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid";
        report
            .resolve(&resolver, did, &ResolutionInputMetadata::default())
            .await;
    }

    {
        let did = &"did:onion:fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid";
        report
            .resolve_representation(&resolver, did, &ResolutionInputMetadata::default())
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_resolver_pkh() {
    let resolver = did_pkh::DIDPKH;
    let mut report = DIDResolverImplementation {
        did_method: "did:pkh".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-pkh".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    {
        let did = &"did:pkh:doge:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L";
        report
            .resolve(&resolver, did, &ResolutionInputMetadata::default())
            .await;
    }

    {
        let did = &"did:pkh:doge:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L";
        report
            .resolve_representation(&resolver, did, &ResolutionInputMetadata::default())
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_resolver_webkey() {
    let resolver = did_webkey::DIDWebKey;
    let mut report = DIDResolverImplementation {
        did_method: "did:webkey".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-webkey".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    {
        let did = &"did:webkey:ssh:demo.spruceid.com:2021:07:14:keys";
        report
            .resolve(&resolver, did, &ResolutionInputMetadata::default())
            .await;
    }

    {
        let did = &"did:webkey:ssh:demo.spruceid.com:2021:07:14:keys";
        report
            .resolve_representation(&resolver, did, &ResolutionInputMetadata::default())
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_dereferencer_key() {
    let mut report = DIDResolverImplementation {
        did_method: "did:key".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-key".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did_url in &[
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH",
        "bad:invalid",
    ] {
        report
            .dereference(
                &did_method_key::DIDKey,
                did_url,
                &DereferencingInputMetadata::default(),
            )
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_dereferencer_web() {
    let mut report = DIDResolverImplementation {
        did_method: "did:web".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-web".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did_url in &[
        "did:web:did.actor:nonexistent",
        "did:web:demo.spruceid.com:2021:07:14:service-example",
        "did:web:demo.spruceid.com:2021:07:14:service-example?service=hello",
    ] {
        report
            .dereference(
                &did_web::DIDWeb,
                did_url,
                &DereferencingInputMetadata::default(),
            )
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_dereferencer_tz() {
    let did_tz = did_tz::DIDTz::default();
    let mut report = DIDResolverImplementation {
        did_method: "did:tz".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-tezos".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };
    for did_url in &[
        "did:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x",
        "did:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x#blockchainAccountId",
    ] {
        report
            .dereference(&did_tz, did_url, &DereferencingInputMetadata::default())
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_dereferencer_onion() {
    let resolver = did_onion::DIDOnion::default();
    let mut report = DIDResolverImplementation {
        did_method: "did:onion".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-onion".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did_url in &[
        "did:onion:fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid",
        "did:onion:fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid#g7r2t9G8dBBnG7yZkD8sly3ImDlrntB25s2pGuaD97E"
    ] {
        report
            .dereference(&resolver, did_url, &DereferencingInputMetadata::default())
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_dereferencer_pkh() {
    let resolver = did_pkh::DIDPKH;
    let mut report = DIDResolverImplementation {
        did_method: "did:pkh".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-pkh".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did_url in &[
        "did:pkh:doge:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L",
        "did:pkh:doge:DH5yaieqoZN36fDVciNyRueRGvGLR3mr7L#blockchainAccountId",
    ] {
        report
            .dereference(&resolver, did_url, &DereferencingInputMetadata::default())
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_dereferencer_webkey() {
    let resolver = did_webkey::DIDWebKey;
    let mut report = DIDResolverImplementation {
        did_method: "did:webkey".to_string(),
        implementation: "https://github.com/spruceid/ssi/tree/main/did-webkey".to_string(),
        implementer: "Spruce Systems, Inc.".to_string(),
        expected_outcomes: HashMap::new(),
        executions: Vec::new(),
    };

    for did_url in &[
        "did:webkey:ssh:demo.spruceid.com:2021:07:14:keys",
        "did:webkey:ssh:demo.spruceid.com:2021:07:14:keys#b2sb-RCkrCm9c569tNc76JBbirQiR9WCL6kf8GlqbvQ"
    ] {
        report
            .dereference(&resolver, did_url, &DereferencingInputMetadata::default())
            .await;
    }

    let writer = std::io::BufWriter::new(std::io::stdout());
    serde_json::to_writer_pretty(writer, &report).unwrap();
}

async fn report_method(mut args: Args) {
    let method = args.next().expect("expected method argument");
    args.next().ok_or(()).expect_err("unexpected argument");
    match &method[..] {
        "key" => report_method_key().await,
        "web" => report_method_web().await,
        "tz" => report_method_tz().await,
        "onion" => report_method_onion().await,
        "pkh" => report_method_pkh().await,
        "webkey" => report_method_webkey().await,
        method => panic!("unknown method {method}"),
    }
}

async fn report_resolver(mut args: Args) {
    let method = args.next().expect("expected method argument");
    args.next().ok_or(()).expect_err("unexpected argument");
    match &method[..] {
        "key" => report_resolver_key().await,
        "web" => report_resolver_web().await,
        "tz" => report_resolver_tz().await,
        "onion" => report_resolver_onion().await,
        "pkh" => report_resolver_pkh().await,
        "webkey" => report_resolver_webkey().await,
        method => panic!("unknown method {method}"),
    }
}

async fn report_dereferencer(mut args: Args) {
    let method = args.next().expect("expected method argument");
    args.next().ok_or(()).expect_err("unexpected argument");
    match &method[..] {
        "key" => report_dereferencer_key().await,
        "web" => report_dereferencer_web().await,
        "tz" => report_dereferencer_tz().await,
        "onion" => report_dereferencer_onion().await,
        "pkh" => report_dereferencer_pkh().await,
        "webkey" => report_dereferencer_webkey().await,
        method => panic!("unknown method {method}"),
    }
}

#[async_std::main]
async fn main() {
    let mut args = std::env::args();
    args.next();
    let section = args.next().expect("expected section argument");
    match &section[..] {
        "method" => report_method(args).await,
        "resolver" => report_resolver(args).await,
        "dereferencer" => report_dereferencer(args).await,
        section => panic!("unknown section {section}"),
    }
}
