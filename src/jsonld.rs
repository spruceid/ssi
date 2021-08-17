use std::collections::BTreeMap as Map;
use std::convert::TryFrom;
use std::str::FromStr;

use crate::error::Error;
use crate::rdf::{
    BlankNodeLabel, DataSet, Graph, GraphLabel, IRIOrBlankNodeIdentifier, IRIRef, Lang, Literal,
    Object, Predicate, StringLiteral, Subject, Triple, LANG_STRING_IRI_STR,
};

use crate::json_ld;
use futures::future::{BoxFuture, FutureExt};
use iref::{Iri, IriBuf};
use json::JsonValue;
use json_ld::{util::AsJson, Document, JsonContext, Loader, ProcessingMode, RemoteDocument};

#[derive(Debug, Clone)]
pub enum RdfDirection {
    I18nDatatype,
    CompoundLiteral,
}

/// <https://w3c.github.io/json-ld-api/#the-jsonldoptions-type>
// Options implemented as needed
#[derive(Debug, Clone)]
pub struct JsonLdOptions {
    /// <https://w3c.github.io/json-ld-api/#dom-jsonldoptions-base>
    pub base: Option<String>,
    /// <https://w3c.github.io/json-ld-api/#dom-jsonldoptions-expandcontext>
    pub expand_context: Option<String>,
    /// <https://w3c.github.io/json-ld-api/#dom-jsonldoptions-ordered>
    pub ordered: bool,
    /// <https://w3c.github.io/json-ld-api/#dom-jsonldoptions-processingmode>
    pub processing_mode: ProcessingMode,
    /// <https://w3c.github.io/json-ld-api/#dom-jsonldoptions-producegeneralizedrdf>
    pub produce_generalized_rdf: Option<bool>,
    /// <https://w3c.github.io/json-ld-api/#dom-jsonldoptions-rdfdirection>
    pub rdf_direction: Option<RdfDirection>,
}

pub const DEFAULT_JSON_LD_OPTIONS: JsonLdOptions = JsonLdOptions {
    base: None,
    expand_context: None,
    ordered: false,
    processing_mode: ProcessingMode::JsonLd1_1,
    produce_generalized_rdf: None,
    rdf_direction: None,
};

impl Default for JsonLdOptions {
    fn default() -> Self {
        DEFAULT_JSON_LD_OPTIONS.clone()
    }
}

/// <https://www.w3.org/TR/json-ld11/#keywords>
pub const AT_BASE: &str = "@base";
pub const AT_CONTAINER: &str = "@container";
pub const AT_CONTEXT: &str = "@context";
pub const AT_DEFAULT: &str = "@default";
pub const AT_DIRECTION: &str = "@direction";
pub const AT_GRAPH: &str = "@graph";
pub const AT_ID: &str = "@id";
pub const AT_IMPORT: &str = "@import";
pub const AT_INCLUDED: &str = "@included";
pub const AT_INDEX: &str = "@index";
pub const AT_JSON: &str = "@json";
pub const AT_LANGUAGE: &str = "@language";
pub const AT_LIST: &str = "@list";
pub const AT_NEST: &str = "@nest";
pub const AT_NONE: &str = "@none";
pub const AT_PREFIX: &str = "@prefix";
pub const AT_PROPAGATE: &str = "@propagate";
pub const AT_PROTECTED: &str = "@protected";
pub const AT_REVERSE: &str = "@reverse";
pub const AT_SET: &str = "@set";
pub const AT_TYPE: &str = "@type";
pub const AT_VALUE: &str = "@value";
pub const AT_VERSION: &str = "@version";
pub const AT_VOCAB: &str = "@vocab";

pub fn is_keyword(string: &str) -> bool {
    matches!(
        string,
        AT_BASE
            | AT_CONTAINER
            | AT_CONTEXT
            | AT_DIRECTION
            | AT_GRAPH
            | AT_ID
            | AT_IMPORT
            | AT_INCLUDED
            | AT_INDEX
            | AT_JSON
            | AT_LANGUAGE
            | AT_LIST
            | AT_NEST
            | AT_NONE
            | AT_PREFIX
            | AT_PROPAGATE
            | AT_PROTECTED
            | AT_REVERSE
            | AT_SET
            | AT_TYPE
            | AT_VALUE
            | AT_VERSION
            | AT_VOCAB
    )
}

pub fn is_iri(string: &str) -> bool {
    IriBuf::new(string).is_ok()
}

pub const CREDENTIALS_V1_CONTEXT: &str = "https://www.w3.org/2018/credentials/v1";
pub const CREDENTIALS_EXAMPLES_V1_CONTEXT: &str = "https://www.w3.org/2018/credentials/examples/v1";
pub const ODRL_CONTEXT: &str = "https://www.w3.org/ns/odrl.jsonld";
pub const SECURITY_V1_CONTEXT: &str = "https://w3id.org/security/v1";
pub const SECURITY_V2_CONTEXT: &str = "https://w3id.org/security/v2";
pub const SCHEMA_ORG_CONTEXT: &str = "https://schema.org/";
pub const DID_V1_CONTEXT: &str = "https://www.w3.org/ns/did/v1";
pub const W3ID_DID_V1_CONTEXT: &str = "https://w3id.org/did/v1";
pub const DID_RESOLUTION_V1_CONTEXT: &str = "https://w3id.org/did-resolution/v1";
pub const DIF_ESRS2020_CONTEXT: &str = "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020/lds-ecdsa-secp256k1-recovery2020-0.0.jsonld";
pub const ESRS2020_EXTRA_CONTEXT: &str =
    "https://demo.spruceid.com/EcdsaSecp256k1RecoverySignature2020/esrs2020-extra-0.0.jsonld";
pub const LDS_JWS2020_V1_CONTEXT: &str =
    "https://w3c-ccg.github.io/lds-jws2020/contexts/lds-jws2020-v1.json";
pub const CITIZENSHIP_V1_CONTEXT: &str = "https://w3id.org/citizenship/v1";
pub const VACCINATION_V1_CONTEXT: &str = "https://w3id.org/vaccination/v1";
pub const TRACEABILITY_CONTEXT: &str = "https://w3id.org/traceability/v1";
pub const EIP712SIG_V0_1_CONTEXT: &str = "https://demo.spruceid.com/ld/eip712sig-2021/v0.1.jsonld";
pub const BBS_V1_CONTEXT: &str = "https://w3id.org/security/bbs/v1";
pub const SUBMISSION_CONTEXT: &str = "https://identity.foundation/presentation-exchange/submission/v1";

lazy_static! {
    pub static ref CREDENTIALS_V1_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::CREDENTIALS_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(CREDENTIALS_V1_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref CREDENTIALS_EXAMPLES_V1_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::CREDENTIALS_EXAMPLES_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(CREDENTIALS_EXAMPLES_V1_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref ODRL_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::ODRL;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(ODRL_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref SCHEMA_ORG_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::SCHEMA_ORG;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(SCHEMA_ORG_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref SECURITY_V1_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::SECURITY_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(SECURITY_V1_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref SECURITY_V2_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::SECURITY_V2;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(SECURITY_V2_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref DID_V1_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::DID_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(DID_V1_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref DID_RESOLUTION_V1_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::DID_RESOLUTION_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(DID_RESOLUTION_V1_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref DIF_ESRS2020_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::DIF_ESRS2020;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(DIF_ESRS2020_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref ESRS2020_EXTRA_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::ESRS2020_EXTRA;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(ESRS2020_EXTRA_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref LDS_JWS2020_V1_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::LDS_JWS2020_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(LDS_JWS2020_V1_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref CITIZENSHIP_V1_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::CITIZENSHIP_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(CITIZENSHIP_V1_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref VACCINATION_V1_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::VACCINATION_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(VACCINATION_V1_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref TRACEABILITY_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::TRACEABILITY_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(TRACEABILITY_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref EIP712SIG_V0_1_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::EIP712SIG_V0_1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(EIP712SIG_V0_1_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref BBS_V1_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::BBS_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(BBS_V1_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
    pub static ref SUBMISSION_CONTEXT_DOCUMENT: RemoteDocument<JsonValue> = {
        let jsonld = ssi_contexts::PRESENTATION_SUBMISSION_V1;
        let doc = json::parse(jsonld).unwrap();
        let iri = Iri::new(SUBMISSION_CONTEXT).unwrap();
        RemoteDocument::new(doc, iri)
    };
}

pub struct StaticLoader;
impl Loader for StaticLoader {
    type Document = JsonValue;
    fn load<'a>(
        &'a mut self,
        url: Iri<'_>,
    ) -> BoxFuture<'a, Result<RemoteDocument<Self::Document>, json_ld::Error>> {
        let url: IriBuf = url.into();
        async move {
            match url.as_str() {
                CREDENTIALS_V1_CONTEXT => Ok(CREDENTIALS_V1_CONTEXT_DOCUMENT.clone()),
                CREDENTIALS_EXAMPLES_V1_CONTEXT => {
                    Ok(CREDENTIALS_EXAMPLES_V1_CONTEXT_DOCUMENT.clone())
                }
                ODRL_CONTEXT => Ok(ODRL_CONTEXT_DOCUMENT.clone()),
                SECURITY_V1_CONTEXT => Ok(SECURITY_V1_CONTEXT_DOCUMENT.clone()),
                SECURITY_V2_CONTEXT => Ok(SECURITY_V2_CONTEXT_DOCUMENT.clone()),
                SCHEMA_ORG_CONTEXT => Ok(SCHEMA_ORG_CONTEXT_DOCUMENT.clone()),
                DID_V1_CONTEXT | W3ID_DID_V1_CONTEXT => Ok(DID_V1_CONTEXT_DOCUMENT.clone()),
                DID_RESOLUTION_V1_CONTEXT => Ok(DID_RESOLUTION_V1_CONTEXT_DOCUMENT.clone()),
                DIF_ESRS2020_CONTEXT => Ok(DIF_ESRS2020_CONTEXT_DOCUMENT.clone()),
                ESRS2020_EXTRA_CONTEXT => Ok(ESRS2020_EXTRA_CONTEXT_DOCUMENT.clone()),
                LDS_JWS2020_V1_CONTEXT => Ok(LDS_JWS2020_V1_CONTEXT_DOCUMENT.clone()),
                CITIZENSHIP_V1_CONTEXT => Ok(CITIZENSHIP_V1_CONTEXT_DOCUMENT.clone()),
                VACCINATION_V1_CONTEXT => Ok(VACCINATION_V1_CONTEXT_DOCUMENT.clone()),
                TRACEABILITY_CONTEXT => Ok(TRACEABILITY_CONTEXT_DOCUMENT.clone()),
                EIP712SIG_V0_1_CONTEXT => Ok(EIP712SIG_V0_1_CONTEXT_DOCUMENT.clone()),
                BBS_V1_CONTEXT => Ok(BBS_V1_CONTEXT_DOCUMENT.clone()),
                SUBMISSION_CONTEXT => Ok(SUBMISSION_CONTEXT_DOCUMENT.clone()),
                _ => {
                    eprintln!("unknown context {}", url);
                    Err(json_ld::ErrorCode::LoadingDocumentFailed.into())
                }
            }
        }
        .boxed()
    }
}

impl FromStr for RdfDirection {
    type Err = Error;
    fn from_str(purpose: &str) -> Result<Self, Self::Err> {
        match purpose {
            "i18n-datatype" => Ok(Self::I18nDatatype),
            "compound-literal" => Ok(Self::CompoundLiteral),
            _ => Err(Error::UnknownRdfDirection(purpose.to_owned())),
        }
    }
}

impl From<&JsonLdOptions> for json_ld::expansion::Options {
    fn from(options: &JsonLdOptions) -> Self {
        Self {
            ordered: options.ordered,
            processing_mode: options.processing_mode,
            ..Self::default()
        }
    }
}

impl From<&JsonLdOptions> for json_ld::context::ProcessingOptions {
    fn from(options: &JsonLdOptions) -> Self {
        Self {
            processing_mode: options.processing_mode,
            ..Self::default()
        }
    }
}

pub enum JsonValuesIter<'a> {
    Multiple(std::slice::Iter<'a, JsonValue>),
    Single(Option<&'a JsonValue>),
}

impl<'a> Iterator for JsonValuesIter<'a> {
    type Item = &'a JsonValue;
    fn next(&mut self) -> Option<Self::Item> {
        match self {
            Self::Multiple(iter) => iter.next(),
            Self::Single(option) => option.take(),
        }
    }
}

impl<'a> From<&'a JsonValue> for JsonValuesIter<'a> {
    fn from(value: &'a JsonValue) -> Self {
        match value {
            JsonValue::Array(array) => Self::Multiple(array.iter()),
            JsonValue::Null => Self::Single(None),
            value => Self::Single(Some(value)),
        }
    }
}

type NodeMap = Map<String, Map<String, JsonValue>>;

pub fn is_blank_node_identifier(value: &JsonValue) -> bool {
    let value_str = match value.as_str() {
        Some(value_str) => value_str,
        None => return false,
    };
    value_str.get(..2) == Some("_:")
}

#[derive(Debug, Clone, Default)]
pub struct BlankNodeIdentifierGenerator {
    pub identifier_map: Map<String, JsonValue>,
    pub counter: u64,
}

impl BlankNodeIdentifierGenerator {
    /// <https://w3c.github.io/json-ld-api/#generate-blank-node-identifier>
    pub fn generate(&mut self, identifier: &JsonValue) -> Result<JsonValue, Error> {
        let identifier_str = if identifier.is_null() {
            None
        } else {
            match identifier.as_str() {
                Some(id) => Some(id),
                None => return Err(Error::ExpectedString),
            }
        };
        // 1
        if let Some(identifier_str) = identifier_str {
            if let Some(id) = self.identifier_map.get(identifier_str) {
                return Ok(id.clone());
            }
        }
        // 2
        // Generate new blank unique node identifier
        let blank_node_id_prefix = "_:b";
        let new_id = blank_node_id_prefix.to_string() + &self.counter.to_string();
        self.counter += 1;
        let id = JsonValue::String(new_id);
        // 3
        if let Some(old_id) = identifier_str {
            self.identifier_map.insert(old_id.to_string(), id.clone());
        }
        // 4
        Ok(id)
    }
}

/// <https://w3c.github.io/json-ld-api/#node-map-generation>
pub fn generate_node_map(
    element: JsonValue,
    node_map: &mut NodeMap,
    active_graph: Option<&str>,
    active_subject: Option<&JsonValue>,
    active_property: Option<&str>,
    list: Option<&mut JsonValue>,
    blank_node_id_generator: &mut BlankNodeIdentifierGenerator,
) -> Result<(), Error> {
    let mut null: JsonValue = JsonValue::Null;
    let list = list.unwrap_or(&mut null);
    let mut element_obj = match element {
        JsonValue::Array(array) => {
            // 1
            for item in array.into_iter() {
                // 1.1
                generate_node_map(
                    item,
                    node_map,
                    active_graph,
                    active_subject,
                    active_property,
                    Some(list),
                    blank_node_id_generator,
                )?;
            }
            return Ok(());
        }
        JsonValue::Object(object) => object,
        _ => return Err(Error::ExpectedObject),
    };
    let active_graph = active_graph.unwrap_or(AT_DEFAULT);
    // 2
    let graph = node_map
        .entry(active_graph.to_string())
        .or_insert_with(Map::new);
    let subject_node = match active_subject {
        Some(active_subject) => match active_subject.as_str() {
            Some(subject) => graph.get_mut(subject),
            // On reverse, active subject is a map.
            None => None,
            // https://github.com/w3c/json-ld-api/issues/519
            // None => return Err(Error::ExpectedString),
        },
        None => None,
    };
    // 3
    if let Some(types) = match element_obj.remove(AT_TYPE) {
        Some(JsonValue::Array(items)) => Some(JsonValue::Array(
            items
                .into_iter()
                .map(|item| {
                    // 3.1
                    if is_blank_node_identifier(&item) {
                        blank_node_id_generator.generate(&item)
                    } else {
                        Ok(item)
                    }
                })
                .collect::<Result<Vec<JsonValue>, Error>>()?,
        )),
        Some(item) => {
            // 3.1
            if is_blank_node_identifier(&item) {
                Some(blank_node_id_generator.generate(&item)?)
            } else {
                Some(item)
            }
        }
        None => None,
    } {
        element_obj.insert(AT_TYPE, types);
    }
    // 4
    if element_obj.get(AT_VALUE).is_some() {
        // Reconstruct element since it was partially moved.
        let element = JsonValue::Object(element_obj);
        if let Some(ref mut list) = match list {
            JsonValue::Object(list) => Some(list),
            JsonValue::Null => None,
            _ => return Err(Error::ExpectedObject),
        } {
            // 4.2
            let array = match list.get_mut(AT_LIST) {
                Some(JsonValue::Array(vec)) => vec,
                _ => return Err(Error::ExpectedArrayList),
            };
            array.push(element);
        } else {
            // 4.1
            let subject_node = match subject_node {
                Some(JsonValue::Object(object)) => object,
                _ => return Err(Error::ExpectedObject),
            };
            let active_property = match active_property {
                Some(active_property) => active_property,
                None => return Err(Error::MissingActiveProperty),
            };
            if let Some(entry) = subject_node.get_mut(active_property) {
                // 4.1.2
                let array = match entry {
                    JsonValue::Array(array) => array,
                    _ => return Err(Error::ExpectedArray),
                };
                if !array.contains(&element) {
                    array.push(element);
                }
            } else {
                // 4.1.1
                let entry = array![element];
                subject_node.insert(active_property, entry);
            }
        }
    // 5
    } else if let Some(element_list) = element_obj.remove(AT_LIST) {
        // 5.1
        let mut result: JsonValue = JsonValue::new_object();
        result.insert(AT_LIST, JsonValue::new_array())?;
        // 5.2
        generate_node_map(
            element_list,
            node_map,
            Some(active_graph),
            active_subject,
            active_property,
            Some(&mut result),
            blank_node_id_generator,
        )?;
        if list.is_null() {
            // 5.3
            // Get graph again to avoid multiple mutable borrows
            let graph = match node_map.get_mut(active_graph) {
                Some(graph) => graph,
                None => return Err(Error::MissingGraph),
            };
            let subject_node = match active_subject {
                Some(active_subject) => match active_subject.as_str() {
                    Some(active_subject_str) => graph.get_mut(active_subject_str),
                    None => return Err(Error::ExpectedString),
                },
                None => None,
            };
            let subject_node = match subject_node {
                Some(JsonValue::Object(object)) => object,
                _ => return Err(Error::ExpectedObject),
            };
            let active_property = match active_property {
                Some(active_property) => active_property,
                None => return Err(Error::MissingActiveProperty),
            };
            let entry = match subject_node.get_mut(active_property) {
                Some(JsonValue::Array(array)) => array,
                None => return Err(Error::MissingActivePropertyEntry),
                _ => return Err(Error::ExpectedArray),
            };
            entry.push(result);
        } else {
            // 5.4
            let list = match list {
                JsonValue::Object(list) => list,
                _ => return Err(Error::ExpectedObject),
            };
            let list_entry_of_list = match list.get_mut(AT_LIST) {
                Some(JsonValue::Array(list)) => list,
                _ => return Err(Error::ExpectedArrayList),
            };
            list_entry_of_list.push(result);
        };
    // 6
    } else {
        // 6.1
        let id = match element_obj.remove(AT_ID) {
            Some(id) => {
                if is_blank_node_identifier(&id) {
                    blank_node_id_generator.generate(&id)?
                } else {
                    id
                }
            }
            // 6.2
            None => blank_node_id_generator.generate(&JsonValue::Null)?,
        };
        let id_string = match id.as_str() {
            Some(id) => id,
            None => return Err(Error::ExpectedString),
        };
        // 6.3
        if !graph.contains_key(id_string) {
            let mut object = json::object::Object::new();
            object.insert(AT_ID, id.clone());
            let entry = JsonValue::Object(object);
            graph.insert(id_string.to_string(), entry);
        };
        // 6.4
        let node = match graph.get_mut(id_string) {
            Some(JsonValue::Object(node)) => node,
            _ => return Err(Error::ExpectedObject),
        };
        // 6.5
        if let Some(JsonValue::Object(_)) = active_subject {
            if let Some(active_subject) = active_subject {
                let active_property = match active_property {
                    Some(active_property) => active_property,
                    None => return Err(Error::MissingActiveProperty),
                };
                if let Some(entry) = node.get_mut(active_property) {
                    // 6.5.2
                    let array = match entry {
                        JsonValue::Array(vec) => vec,
                        _ => return Err(Error::ExpectedArray),
                    };
                    if !array.contains(active_subject) {
                        array.push(active_subject.clone());
                    }
                } else {
                    // 6.5.1
                    let entry = array![active_subject.clone()];
                    node.insert(active_property, entry);
                }
            }
        } else {
            // 6.6
            if let Some(active_property) = active_property {
                // 6.6.1
                let mut reference_object = json::object::Object::new();
                reference_object.insert(AT_ID, id.clone());
                let reference = JsonValue::Object(reference_object);
                if list.is_null() {
                    // 6.6.2
                    let subject_node = match active_subject {
                        Some(value) => match value.as_str() {
                            Some(subject) => graph.get_mut(subject),
                            None => return Err(Error::ExpectedString),
                        },
                        None => None,
                    };
                    let subject_node = match subject_node {
                        Some(JsonValue::Object(object)) => object,
                        _ => return Err(Error::ExpectedObject),
                    };
                    if let Some(entry) = subject_node.get_mut(active_property) {
                        // 6.6.2.2
                        let array = match entry {
                            JsonValue::Array(array) => array,
                            _ => return Err(Error::ExpectedArray),
                        };
                        if !array.contains(&reference) {
                            array.push(reference);
                        }
                    } else {
                        // 6.6.2.1
                        let entry = array![reference];
                        subject_node.insert(active_property, entry);
                    }
                } else {
                    // 6.6.3
                    let list = match list {
                        JsonValue::Object(list) => list,
                        _ => return Err(Error::ExpectedObject),
                    };
                    let list_entry_of_list = match list.get_mut(AT_LIST) {
                        Some(JsonValue::Array(list)) => list,
                        _ => return Err(Error::ExpectedArrayList),
                    };
                    list_entry_of_list.push(reference);
                }
            }
        }
        // 6.7
        // Get graph/node again to avoid multiple mutable borrows
        let node = match graph.get_mut(id_string) {
            Some(JsonValue::Object(node)) => node,
            _ => return Err(Error::ExpectedObject),
        };
        if let Some(element_type) = element_obj.remove(AT_TYPE) {
            let element_type_array = match element_type {
                JsonValue::Array(array) => array,
                _ => return Err(Error::ExpectedArray),
            };
            if let Some(node_type) = node.get_mut(AT_TYPE) {
                let node_type_array = match node_type {
                    JsonValue::Array(array) => array,
                    _ => return Err(Error::ExpectedArray),
                };
                for type_ in element_type_array.into_iter() {
                    if !node_type_array.contains(&type_) {
                        node_type_array.push(type_);
                    }
                }
            } else {
                node.insert("type", JsonValue::Array(element_type_array));
            }
        }
        // 6.8
        if let Some(element_index) = element_obj.remove(AT_INDEX) {
            if let Some(node_index) = node.get(AT_INDEX) {
                if node_index != &element_index {
                    return Err(Error::ConflictingIndexes);
                }
            } else {
                node.insert("index", element_index);
            }
        }
        // 6.9, 6.9.2, 6.9.4
        if let Some(reverse_map) = element_obj.remove(AT_REVERSE) {
            // 6.9.1
            let mut object = json::object::Object::new();
            object.insert(AT_ID, id.clone());
            let referenced_node = JsonValue::Object(object);
            // 6.9.3
            let reverse_map_object = match reverse_map {
                JsonValue::Object(object) => object,
                _ => return Err(Error::ExpectedObject),
            };
            // Clone since Object does not have a consuming iterator.
            // https://github.com/maciejhirsz/json-rust/pull/190
            for (property, value) in reverse_map_object.iter() {
                let values = match value {
                    JsonValue::Array(array) => array.to_vec(),
                    value => vec![value.clone()],
                };
                // 6.9.3.1
                for value in values.into_iter() {
                    // 6.9.3.1.1
                    generate_node_map(
                        value,
                        node_map,
                        Some(active_graph),
                        Some(&referenced_node),
                        Some(&property),
                        None,
                        blank_node_id_generator,
                    )?;
                }
            }
        }
        // 6.10
        if let Some(graph) = element_obj.remove(AT_GRAPH) {
            let id_string = match id.as_str() {
                Some(id) => id,
                None => return Err(Error::ExpectedString),
            };
            generate_node_map(
                graph,
                node_map,
                Some(id_string),
                None,
                None,
                None,
                blank_node_id_generator,
            )?;
        }
        // 6.11
        if let Some(included) = element_obj.remove(AT_INCLUDED) {
            generate_node_map(
                included,
                node_map,
                Some(active_graph),
                None,
                None,
                None,
                blank_node_id_generator,
            )?;
        }
        // 6.12
        let mut element_property_values: Vec<(String, JsonValue)> = element_obj
            .iter()
            .map(|(prop, value)| (prop.to_owned(), value.to_owned()))
            .collect();
        element_property_values.sort_by(|(property1, _), (property2, _)| property1.cmp(property2));
        for (property_str, value) in element_property_values {
            // 6.12.1
            let mut property = JsonValue::String(property_str.to_string());
            if is_blank_node_identifier(&property) {
                property = blank_node_id_generator.generate(&property)?;
            }
            let property_str = match property.as_str() {
                Some(property) => property,
                None => return Err(Error::ExpectedString),
            };
            // 6.12.2
            // Get graph/node again to avoid multiple mutable borrows
            let graph = match node_map.get_mut(active_graph) {
                Some(graph) => graph,
                None => return Err(Error::MissingGraph),
            };
            let node = match graph.get_mut(id_string) {
                Some(JsonValue::Object(node)) => node,
                _ => return Err(Error::ExpectedObject),
            };
            if node.get(property_str).is_none() {
                node.insert(property_str, JsonValue::new_array());
            }
            // 6.12.3
            generate_node_map(
                value,
                node_map,
                Some(active_graph),
                Some(&id),
                Some(property_str),
                None,
                blank_node_id_generator,
            )?;
        }
    }
    Ok(())
}

/// <https://w3c.github.io/json-ld-api/#deserialize-json-ld-to-rdf-algorithm>
pub fn json_ld_to_rdf(
    node_map: &NodeMap,
    dataset: &mut DataSet,
    options: Option<&JsonLdOptions>,
    blank_node_id_generator: &mut BlankNodeIdentifierGenerator,
) -> Result<(), Error> {
    let options = options.unwrap_or(&DEFAULT_JSON_LD_OPTIONS);
    // 1
    let mut graphs: Vec<(&String, &Map<String, JsonValue>)> = node_map.iter().collect();
    graphs.sort_by(|(name1, _), (name2, _)| name1.cmp(name2));
    for (graph_name, graph) in graphs {
        // 1.1
        // 1.2
        let triples = if graph_name == AT_DEFAULT {
            &mut dataset.default_graph
        } else {
            let graph_name = match GraphLabel::try_from(graph_name.to_string()) {
                Ok(name) => name,
                Err(_) => continue,
            };
            dataset
                .named_graphs
                .entry(graph_name)
                .or_insert_with(Graph::default)
        };
        // 1.3
        let mut nodes: Vec<(&String, &JsonValue)> = graph.iter().collect();
        nodes.sort_by(|(subject1, _), (subject2, _)| subject1.cmp(subject2));
        for (subject, node) in nodes {
            // 1.3.1
            let subject = match Subject::try_from(subject.to_string()) {
                Ok(subject) => subject,
                Err(_) => continue,
            };
            let node_object = match node {
                JsonValue::Object(object) => object,
                _ => return Err(Error::ExpectedObject),
            };
            let mut property_values: Vec<(&str, &JsonValue)> = node_object.iter().collect();
            property_values.sort_by(|(property1, _), (property2, _)| property1.cmp(property2));
            // 1.3.2
            for (property, values) in property_values {
                // 1.3.2.1
                #[allow(clippy::if_same_then_else)]
                if property == AT_TYPE
                // TODO: find out why type is not getting turned into @type here
                || property == "type"
                {
                    for type_ in JsonValuesIter::from(values) {
                        let type_ = match Object::try_from(type_.to_string()) {
                            Ok(type_) => type_,
                            Err(_) => continue,
                        };
                        let triple = Triple {
                            subject: subject.clone(),
                            predicate: Predicate::IRIRef(IRIRef(
                                "http://www.w3.org/1999/02/22-rdf-syntax-ns#type".to_string(),
                            )),
                            object: type_,
                        };
                        triples.add(triple);
                    }
                } else if is_keyword(property) {
                    // 1.3.2.2
                    continue;
                } else if is_blank_node_identifier(&JsonValue::String(property.to_string()))
                    && options.produce_generalized_rdf != Some(true)
                {
                    // 1.3.2.3
                    continue;
                } else {
                    // 1.3.2.4
                    let property = match IRIOrBlankNodeIdentifier::try_from(property.to_string()) {
                        Ok(property) => property,
                        Err(_) => continue,
                    };
                    let predicate = Predicate::try_from(property)?;
                    // 1.3.2.5
                    // property is an IRI or blank node identifier
                    for item in JsonValuesIter::from(values) {
                        // 1.3.2.5.1
                        let mut list_triples = vec![];
                        // 1.3.2.5.2
                        let item = ItemObject::try_from(item)?;
                        if let Some(object) = object_to_rdf(
                            item,
                            &mut list_triples,
                            Some(options),
                            blank_node_id_generator,
                        )? {
                            let triple = Triple {
                                subject: subject.clone(),
                                predicate: predicate.clone(),
                                object,
                            };
                            triples.add(triple);
                        }
                        // 1.3.2.5.3
                        triples.triples.append(&mut list_triples);
                    }
                }
            }
        }
    }
    Ok(())
}

#[derive(Debug, Clone)]
pub enum ItemObject {
    Value(ValueObject),
    List(ListObject),
    Node(NodeObject),
}

/// <https://www.w3.org/TR/json-ld11/#dfn-value-object>
#[derive(Debug, Clone)]
pub struct NodeObject {
    pub id: Option<String>,
    pub entries: json::object::Object,
}

/// <https://www.w3.org/TR/json-ld11/#dfn-list-object>
#[derive(Debug, Clone)]
pub struct ListObject {
    pub list: JsonValue,
    pub index: Option<JsonValue>,
    pub more_properties: json::object::Object,
}

/// <https://www.w3.org/TR/json-ld11/#value-objects>
#[derive(Debug, Clone)]
pub struct ValueObject {
    pub value: JsonValue,
    pub type_: Option<JsonValue>,
    pub language: Option<JsonValue>,
    pub direction: Option<JsonValue>,
    pub index: Option<JsonValue>,
    pub context: Option<JsonValue>,
    pub more_properties: json::object::Object,
}

impl TryFrom<&JsonValue> for ValueObject {
    type Error = Error;
    fn try_from(object: &JsonValue) -> Result<Self, Self::Error> {
        let mut object = match object {
            JsonValue::Object(object) => object,
            _ => return Err(Error::ExpectedObject),
        }
        .clone();
        let value = match object.remove(AT_VALUE) {
            Some(value) => value,
            None => return Err(Error::ExpectedValue),
        };
        let type_ = object.remove(AT_TYPE);
        let type_str = match type_ {
            Some(ref type_) => match type_.as_str() {
                Some(type_str) => Some(type_str),
                None => return Err(Error::ExpectedString),
            },
            None => None,
        };
        // TODO:
        // - The value associated with the @type key MUST be a term, an IRI, a compact IRI, a string which can be turned into an IRI using the vocabulary mapping, @json, or null.
        // - The value associated with the @language key MUST have the lexical form described in [BCP47], or be null.
        if (value.is_array() || value.is_object()) && type_str != Some(AT_JSON) {
            return Err(Error::ExpectedValueTypeJson);
        }
        let language = object.remove(AT_LANGUAGE);
        let direction = object.remove(AT_DIRECTION);
        if let Some(ref direction) = direction {
            if !direction.is_null() {
                match direction.as_str() {
                    Some("ltr") | Some("rtl") => {}
                    _ => return Err(Error::UnrecognizedDirection),
                }
            }
        }
        let index = object.remove(AT_INDEX);
        if let Some(ref index) = index {
            if !index.is_string() {
                return Err(Error::ExpectedStringIndex);
            }
        }
        let context = object.remove(AT_CONTEXT);
        if type_.is_some() && (language.is_some() || direction.is_some()) {
            return Err(Error::ValueObjectLanguageType);
        }
        for (key, _) in object.iter() {
            if is_keyword(key) {
                return Err(Error::UnexpectedKeyword);
            }
            if is_iri(key) {
                return Err(Error::UnexpectedIRI);
            }
        }
        Ok(Self {
            value,
            type_,
            language,
            direction,
            index,
            context,
            more_properties: object,
        })
    }
}

// https://www.w3.org/TR/json-ld11/#node-objects
impl TryFrom<&JsonValue> for NodeObject {
    type Error = Error;
    fn try_from(object: &JsonValue) -> Result<Self, Self::Error> {
        let object = match object {
            JsonValue::Object(object) => object,
            _ => return Err(Error::ExpectedObject),
        };
        if object.get(AT_VALUE).is_some() {
            return Err(Error::UnexpectedValue);
        }
        if object.get(AT_LIST).is_some() {
            return Err(Error::UnexpectedList);
        }
        if object.get(AT_SET).is_some() {
            return Err(Error::UnexpectedSet);
        }
        let mut object = object.clone();
        // TODO:
        // - it is not the top-most map in the JSON-LD document consisting of no other entries than @graph and @context,
        // - it is not a graph object.
        // - All keys which are not IRIs, compact IRIs, terms valid in the active context, or one of the following keywords (or alias of such a keyword) MUST be ignored when processed: @context, @id, @included, @graph, @nest, @type, @reverse, or @index
        // - Keys in a node object that are not keywords MAY expand to an IRI using the active context. The values associated with keys that expand to an IRI MUST be one of the following: string, number, true, false, null, node object, graph object, value object, list object, set object, an array of zero or more of any of the possibilities above, a language map, an index map, an included block an id map, or a type map
        if let Some(_context) = object.get(AT_CONTEXT) {
            // TODO
        }
        let id = match object.remove(AT_ID) {
            None => None,
            Some(value) => {
                let id_str = match value.as_str() {
                    Some(id_str) => id_str,
                    None => return Err(Error::ExpectedString),
                };
                // TODO: MUST be an IRI reference, or a compact IRI (including blank node identifiers
                Some(id_str.to_owned())
            }
        };
        if let Some(_graph) = object.get(AT_GRAPH) {
            // TODO
        }
        if let Some(_type_) = object.get(AT_TYPE) {
            // TODO
        }
        if let Some(_reverse) = object.get(AT_REVERSE) {
            // TODO
        }
        if let Some(_included) = object.get(AT_INCLUDED) {
            // TODO
        }
        if let Some(index) = object.get(AT_INDEX) {
            if !index.is_string() {
                return Err(Error::ExpectedString);
            }
        }
        if let Some(_nest) = object.get(AT_NEST) {
            // TODO
        }

        Ok(Self {
            id,
            entries: object,
        })
    }
}

// https://www.w3.org/TR/json-ld11/#lists-and-sets
impl TryFrom<&JsonValue> for ListObject {
    type Error = Error;
    fn try_from(object: &JsonValue) -> Result<Self, Self::Error> {
        let mut object = match object {
            JsonValue::Object(object) => object,
            _ => return Err(Error::ExpectedObject),
        }
        .clone();
        let list = match object.remove(AT_LIST) {
            Some(value) => value,
            None => return Err(Error::ExpectedList),
        };
        let index = object.remove(AT_INDEX);
        for (key, _) in object.iter() {
            if is_keyword(key) {
                return Err(Error::UnexpectedKeyword);
            }
            if is_iri(key) {
                return Err(Error::UnexpectedIRI);
            }
        }
        for item in JsonValuesIter::from(&list) {
            match item {
                JsonValue::String(_)
                | JsonValue::Number(_)
                | JsonValue::Short(_)
                | JsonValue::Boolean(_)
                | JsonValue::Null => {}
                JsonValue::Array(_) => {
                    return Err(Error::UnexpectedNestedArray);
                }
                JsonValue::Object(_) => {
                    ItemObject::try_from(item)?;
                }
            }
        }
        Ok(Self {
            list,
            index,
            more_properties: object,
        })
    }
}

impl TryFrom<&JsonValue> for ItemObject {
    type Error = Error;
    fn try_from(value: &JsonValue) -> Result<Self, Self::Error> {
        Ok(if value.has_key(AT_LIST) {
            Self::List(ListObject::try_from(value)?)
        } else if value.has_key(AT_VALUE) {
            Self::Value(ValueObject::try_from(value)?)
        } else {
            Self::Node(NodeObject::try_from(value)?)
        })
    }
}

/// <https://w3c.github.io/json-ld-api/#object-to-rdf-conversion>
pub fn object_to_rdf(
    item: ItemObject,
    list_triples: &mut Vec<Triple>,
    options: Option<&JsonLdOptions>,
    blank_node_id_generator: &mut BlankNodeIdentifierGenerator,
) -> Result<Option<Object>, Error> {
    let options = options.unwrap_or(&DEFAULT_JSON_LD_OPTIONS);
    let item = match item {
        ItemObject::Node(node) => {
            // 1
            let id = match match node.id {
                Some(id) => IRIOrBlankNodeIdentifier::try_from(id).ok(),
                None => None,
            } {
                Some(id) => id,
                None => return Ok(None),
            };
            // 2
            return Ok(Some(Object::from(id)));
        }
        ItemObject::List(list) => {
            // 3
            return Ok(Some(list_to_rdf(
                list.list,
                list_triples,
                Some(options),
                blank_node_id_generator,
            )?));
        }
        ItemObject::Value(value) => value,
    };
    // 4
    let mut value = item.value;
    // 5
    let datatype = item.type_.unwrap_or(JsonValue::Null);
    // 6
    let mut datatype = if datatype.is_null() {
        None
    } else {
        let datatype = match datatype.as_str() {
            Some(datatype) => datatype,
            None => return Ok(None),
        };
        // TODO: use IRI here rather than IRIRef
        if datatype != AT_JSON && IRIRef::try_from(datatype.to_string()).is_err() {
            return Ok(None);
        }
        Some(datatype)
    };
    // 7
    if let Some(ref language) = item.language {
        let language_str = match language.as_str() {
            Some(language_str) => language_str,
            None => return Ok(None),
        };
        if Lang::from_str(language_str).is_err() {
            return Ok(None);
        }
    }
    // 8
    if datatype == Some(AT_JSON) {
        value = JsonValue::String(canonicalize_json(&value));
        datatype = Some("http://www.w3.org/1999/02/22-rdf-syntax-ns#JSON");
    }
    // 9
    if let Some(value_bool) = match value {
        JsonValue::Boolean(true) => Some("true"),
        JsonValue::Boolean(false) => Some("false"),
        _ => None,
    } {
        value = JsonValue::String(value_bool.to_string());
        if datatype == None {
            datatype = Some("http://www.w3.org/2001/XMLSchema#boolean");
        }
    } else if let Some(num) = value.as_number() {
        let num_f64 = f64::from(num);
        if num_f64 % 1f64 != 0f64
            || num_f64 >= 1e21
            || datatype == Some("http://www.w3.org/2001/XMLSchema#double")
        {
            // 10
            // https://w3c.github.io/json-ld-api/#data-round-tripping
            // https://www.w3.org/TR/xmlschema11-2/#f-doubleCanmap
            let num = format!("{:.15E}", num_f64);
            // Replace (\d)0*E with $1E
            // TODO: optimize
            let mut num_vec: Vec<char> = num.chars().collect();
            let mut i = match num_vec.iter().position(|x| *x == 'E') {
                Some(i) => i - 1,
                None => return Err(Error::SerializeDouble),
            };
            while i > 1 && num_vec.get(i) == Some(&'0') && num_vec.get(i - 1) != Some(&'.') {
                num_vec.remove(i);
                i -= 1;
            }
            let num: String = num_vec.iter().collect();
            value = JsonValue::String(num);
            if datatype == None {
                datatype = Some("http://www.w3.org/2001/XMLSchema#double");
            }
        } else {
            // 11
            let num = if num_f64 == -0.0 {
                "0".to_string()
            } else {
                format!("{:.0}", num_f64)
            };
            value = JsonValue::String(num);
            if datatype == None {
                datatype = Some("http://www.w3.org/2001/XMLSchema#integer");
            }
        }
    } else if datatype == None {
        // 12
        datatype = Some(match item.language.is_some() {
            true => "http://www.w3.org/1999/02/22-rdf-syntax-ns#langString",
            false => "http://www.w3.org/2001/XMLSchema#string",
        });
    }
    // 13
    let value_string = match value.as_str() {
        Some(val) => val.to_string(),
        None => return Err(Error::ExpectedString),
    };
    let language = match item.language {
        Some(language) => match language.as_str() {
            Some(language_str) => Some(language_str.to_string()),
            None => None,
        },
        None => None,
    };
    let literal;
    if let (Some(direction), Some(rdf_direction)) = (item.direction, options.rdf_direction.as_ref())
    {
        // 13.1
        let language = language.unwrap_or_else(|| "".to_string());
        let direction = match direction.as_str() {
            Some(direction) => direction,
            None => return Err(Error::ExpectedString),
        };
        match rdf_direction {
            // 13.2
            RdfDirection::I18nDatatype => {
                let datatype_string =
                    "https://www.w3.org/ns/i18n#".to_string() + &language + "_" + direction;
                literal = Literal::Typed {
                    string: StringLiteral(value_string),
                    type_: IRIRef(datatype_string),
                };
            }
            // 13.3
            RdfDirection::CompoundLiteral => {
                // 13.3.1
                let literal_value = blank_node_id_generator.generate(&JsonValue::Null)?;
                let literal_string = match literal_value.as_str() {
                    Some(value) => value.to_string(),
                    None => return Err(Error::ExpectedString),
                };
                literal = Literal::String {
                    string: StringLiteral(literal_string.clone()),
                };
                // 13.3.2
                list_triples.push(Triple {
                    subject: Subject::BlankNodeLabel(BlankNodeLabel(literal_string.clone())),
                    predicate: Predicate::IRIRef(IRIRef(
                        "http://www.w3.org/1999/02/22-rdf-syntax-ns#value".to_string(),
                    )),
                    // TODO: what type is value supposed to be?
                    object: Object::try_from(value.to_string())?,
                });
                // 13.3.3
                if !language.is_empty() {
                    list_triples.push(Triple {
                        subject: Subject::BlankNodeLabel(BlankNodeLabel(literal_string.clone())),
                        predicate: Predicate::IRIRef(IRIRef(
                            "http://www.w3.org/1999/02/22-rdf-syntax-ns#language".to_string(),
                        )),
                        // TODO: is language a literal?
                        object: Object::try_from(language)?,
                    });
                }
                // 13.3.4
                list_triples.push(Triple {
                    subject: Subject::BlankNodeLabel(BlankNodeLabel(literal_string)),
                    predicate: Predicate::IRIRef(IRIRef(
                        "http://www.w3.org/1999/02/22-rdf-syntax-ns#direction".to_string(),
                    )),
                    // TODO: is direction a literal?
                    object: Object::try_from(direction.to_string())?,
                });
            }
        }
    } else {
        let datatype_string = match datatype {
            Some(val) => val.to_string(),
            None => return Err(Error::ExpectedString),
        };
        // 14
        literal = if let Some(language) = language {
            if datatype.is_some() && datatype != Some(LANG_STRING_IRI_STR) {
                return Err(Error::ExpectedLangStringType);
            }
            let lang = Lang::from_str(language.as_str())?;
            Literal::LangTagged {
                string: StringLiteral(value_string),
                lang,
            }
        } else if datatype == Some("http://www.w3.org/2001/XMLSchema#string") {
            Literal::String {
                string: StringLiteral(value_string),
            }
        } else {
            Literal::Typed {
                string: StringLiteral(value_string),
                type_: IRIRef(datatype_string),
            }
        };
    }
    // 15
    Ok(Some(Object::Literal(literal)))
}

/// <https://w3c.github.io/json-ld-api/#dfn-canonical-lexical-form>
pub fn canonicalize_json(value: &JsonValue) -> String {
    // TODO: make sure it follows RFC 8785 (JCS)
    // Converting to serde Value loses the order of keys, and serde_jcs does not provide from_str
    // functions. So we just use serde_jcs for the number serialization.
    match value {
        JsonValue::Null => "null".to_string(),
        JsonValue::Boolean(true) => "true".to_string(),
        JsonValue::Boolean(false) => "false".to_string(),
        JsonValue::Short(short) => canonicalize_json_string(short.as_str()),
        JsonValue::String(string) => canonicalize_json_string(&string),
        JsonValue::Number(_) => canonicalize_json_number(value),
        JsonValue::Array(array) => {
            let mut string = "[".to_string();
            let mut first = true;
            for value in array {
                if first {
                    first = false;
                } else {
                    string.push(',');
                }
                string += &canonicalize_json(value);
            }
            string + "]"
        }
        JsonValue::Object(object) => {
            let mut entries = object.iter().collect::<Vec<(&str, &JsonValue)>>();
            entries.sort_by_cached_key(|(key, _)| key.encode_utf16().collect::<Vec<u16>>());
            let mut string = "{".to_string();
            let mut first = true;
            for (key, value) in entries {
                if first {
                    first = false;
                } else {
                    string.push(',');
                }
                string.push_str(&canonicalize_json_string(&key));
                string.push(':');
                string.push_str(&canonicalize_json(value));
            }
            string.push('}');
            string
        }
    }
}

/// <https://www.w3.org/TR/json-ld11/#the-rdf-json-datatype>
pub fn canonicalize_json_string(string: &str) -> String {
    let mut out = String::with_capacity(string.len() + 6);
    out.push('"');
    for c in string.chars() {
        match c {
            '\t' => out.push_str("\\t"),
            '\x08' => out.push_str("\\b"),
            '\x0c' => out.push_str("\\f"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\x00'..='\x1f' => {
                let bytes: u32 = c.into();
                out.push_str(&format!("\\u{:04x}", bytes))
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

pub fn canonicalize_json_number(num: &JsonValue) -> String {
    // This way seems to involve less of precision that converting to f64 first.
    let num_str = num.dump();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(&num_str) {
        if let Ok(out) = serde_jcs::to_string(&value) {
            return out;
        }
    }
    num_str
}

/// <https://w3c.github.io/json-ld-api/#list-to-rdf-conversion>
pub fn list_to_rdf(
    list: JsonValue,
    list_triples: &mut Vec<Triple>,
    options: Option<&JsonLdOptions>,
    blank_node_id_generator: &mut BlankNodeIdentifierGenerator,
) -> Result<Object, Error> {
    let list = match list {
        JsonValue::Array(array) => array,
        _ => return Err(Error::ExpectedArray),
    };
    if list.is_empty() {
        // 1
        return Ok(Object::IRIRef(IRIRef(
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil".to_string(),
        )));
    }
    // 2
    let bnodes = list
        .iter()
        .map(|_| blank_node_id_generator.generate(&JsonValue::Null))
        .collect::<Result<Vec<JsonValue>, Error>>()?;
    // 3
    let mut bnodes_iter = bnodes.iter().peekable();
    let mut list_iter = list.iter();
    while let (Some(subject), Some(item)) = (bnodes_iter.next(), list_iter.next()) {
        let subject = Subject::try_from(subject.to_string())?;
        // 3.1
        let mut embedded_triples = vec![];
        // 3.2
        let item = ItemObject::try_from(item)?;
        let object = object_to_rdf(
            item,
            &mut embedded_triples,
            options,
            blank_node_id_generator,
        )?;
        // 3.3
        if let Some(object) = object {
            let triple = Triple {
                subject: subject.clone(),
                predicate: Predicate::IRIRef(IRIRef(
                    "http://www.w3.org/1999/02/22-rdf-syntax-ns#first".to_string(),
                )),
                object,
            };
            list_triples.push(triple);
        }
        // 3.4
        let rest = match bnodes_iter.peek() {
            Some(rest) => Object::try_from(rest.to_string())?,
            None => Object::IRIRef(IRIRef(
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil".to_string(),
            )),
        };
        list_triples.push(Triple {
            subject: subject.clone(),
            predicate: Predicate::IRIRef(IRIRef(
                "http://www.w3.org/1999/02/22-rdf-syntax-ns#rest".to_string(),
            )),
            object: rest,
        });
        // 3.5
        list_triples.append(&mut embedded_triples);
    }
    // 4
    let first = match bnodes.first() {
        Some(first) => Object::try_from(first.to_string())?,
        None => Object::IRIRef(IRIRef(
            "http://www.w3.org/1999/02/22-rdf-syntax-ns#nil".to_string(),
        )),
    };
    Ok(first)
}

pub async fn expand_json<T>(
    json: &str,
    more_contexts_json: Option<&String>,
    lax: bool,
    options: Option<&JsonLdOptions>,
    loader: &mut T,
) -> Result<Vec<JsonValue>, Error>
    where
        T: Loader<Document = JsonValue> + std::marker::Send + Sync
{
    let options = options.unwrap_or(&DEFAULT_JSON_LD_OPTIONS);
    let base = match options.base {
        Some(ref iri) => Some(iref::Iri::new(iri)?),
        None => None,
    };
    let mut context: JsonContext = JsonContext::new(base);
    if let Some(ref url) = options.expand_context {
        use json_ld::context::Loader;
        use json_ld::context::Local;
        let iri = IriBuf::new(url).unwrap();
        let local_context = loader.load_context(iri.as_iri()).await?.into_context();
        context = local_context
            .process_with(&context, loader, base, options.into())
            .await?
            .into_inner();
    }
    let mut doc = json::parse(json)?;
    if let Some(more_contexts_json) = more_contexts_json {
        let more_contexts = json::parse(&more_contexts_json)?;
        // Merge additional contexts into document. This is needed for serializing proofs, since
        // they typically inherit the context of the parent credential/presentation rather than
        // including their own.
        // TODO: handle this with the expandContext option instead
        let doc_object = match doc {
            JsonValue::Object(ref mut object) => object,
            _ => return Err(Error::ExpectedObject),
        };
        let mut contexts_merged = Vec::new();
        if let Some(doc_contexts) = doc_object.remove(AT_CONTEXT) {
            for item in JsonValuesIter::from(&doc_contexts) {
                contexts_merged.push(item.clone());
            }
        }
        for item in JsonValuesIter::from(&more_contexts) {
            contexts_merged.push(item.clone());
        }
        doc_object.insert(AT_CONTEXT, JsonValue::Array(contexts_merged));
    }
    let mut expansion_options = json_ld::expansion::Options::from(options);
    expansion_options.strict = !lax;
    expansion_options.ordered = false;
    let expanding = doc.expand_with(base, &context, loader, expansion_options);
    let expanded_doc = expanding.await?;

    let documents = expanded_doc
        .iter()
        .map(|item| item.as_json())
        .collect();

    Ok(documents)
}

/// <https://w3c.github.io/json-ld-api/#dom-jsonldprocessor-tordf>
pub async fn json_to_dataset<T>(
    json: &str,
    more_contexts_json: Option<&String>,
    lax: bool,
    options: Option<&JsonLdOptions>,
    loader: &mut T,
) -> Result<DataSet, Error>
    where
        T: Loader<Document = JsonValue> + std::marker::Send + Sync,
{
    let options = options.unwrap_or(&DEFAULT_JSON_LD_OPTIONS);
    let expanded_doc = expand_json(json, more_contexts_json, lax, Some(&options), loader).await?;
    let mut node_map = Map::new();
    node_map.insert(AT_DEFAULT.to_string(), Map::new());
    let mut blank_node_id_generator = BlankNodeIdentifierGenerator::default();
    for object in expanded_doc {
        generate_node_map(
            object,
            &mut node_map,
            None,
            None,
            None,
            None,
            &mut blank_node_id_generator,
        )?;
    }
    let mut dataset = DataSet::default();
    json_ld_to_rdf(
        &node_map,
        &mut dataset,
        Some(options),
        &mut blank_node_id_generator,
    )?;
    Ok(dataset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use json_ld::FsLoader;

    async fn test_to_rdf(obj: &json::object::Object) -> Result<(), Error> {
        use crate::urdna2015;
        use std::fs;
        use std::path::PathBuf;
        let base1 = "https://w3c.github.io/json-ld-api/tests/".to_string();
        let base = "json-ld-api/tests/";
        let input = obj.get("input").unwrap().as_str().unwrap();
        let input = base.to_string() + input;
        let mut base_iri = "https://w3c.github.io/".to_string() + &input;
        let input_path = PathBuf::from(input);
        let in_str = fs::read_to_string(&input_path).unwrap();
        let mut loader = FsLoader::new();
        loader.mount(
            Iri::new("https://w3c.github.io/json-ld-api").unwrap(),
            "json-ld-api",
        );
        let mut ld_options = DEFAULT_JSON_LD_OPTIONS.clone();
        if let Some(JsonValue::Object(options)) = obj.get("option") {
            if let Some(mode) = options.get("processingMode") {
                let mode_str = match mode.as_str() {
                    Some(mode_str) => mode_str,
                    None => return Err(Error::ExpectedString),
                };
                ld_options.processing_mode = ProcessingMode::try_from(mode_str)
                    .map_err(|_| Error::UnknownProcessingMode(mode_str.to_owned()))?;
            }
            if let Some(mode) = options.get("rdfDirection") {
                ld_options.rdf_direction = Some(RdfDirection::from_str(mode.as_str().unwrap())?);
            }
            if let Some(base) = options.get("base") {
                base_iri = base.as_str().unwrap().to_owned();
            }
            if let Some(ctx) = options.get("expandContext") {
                use iref::IriRef;
                let ctx = ctx.as_str().unwrap();
                let iri_ref = IriRef::new(ctx).unwrap();
                let base1 = Iri::new(&base1).unwrap();
                ld_options.expand_context = Some(iri_ref.resolved(base1).to_string());
            }
        }
        ld_options.base = Some(base_iri);
        // Normalize input and input for comparison
        let result = json_to_dataset(&in_str, None, true, Some(&ld_options), &mut loader)
            .await
            .and_then(|dataset| urdna2015::normalize(&dataset))
            .and_then(|dataset| dataset.to_nquads());
        if let Some(output) = obj.get("expect") {
            let output = output.as_str().unwrap();
            let output_path = PathBuf::from(base.to_string() + output);
            let output_string = fs::read_to_string(&output_path).unwrap();
            let output_dataset = DataSet::from_str(&output_string)?;
            let output_dataset_normalized = urdna2015::normalize(&output_dataset)?;
            let output_string_normalized = output_dataset_normalized.to_nquads()?;
            let nquads = result?;
            if &nquads != &output_string_normalized {
                return Err(Error::ExpectedOutput(output_string_normalized, nquads));
            }
        } else if obj.get("expectErrorCode").is_some() {
            if result.is_ok() {
                return Err(Error::ExpectedFailure);
            }
        } else {
            result?;
        }
        Ok(())
    }

    #[async_std::test]
    /// <https://w3c.github.io/json-ld-api/tests/toRdf-manifest.html>
    async fn to_rdf_test_suite() {
        let manifest_str = include_str!("../json-ld-api/tests/toRdf-manifest.jsonld");
        let manifest = json::parse(manifest_str).unwrap();
        let manifest_obj = match manifest {
            JsonValue::Object(obj) => Ok(obj),
            _ => Err(Error::ExpectedObject),
        }
        .unwrap();
        let case = std::env::args().skip(2).next();
        let sequence = manifest_obj.get("sequence").unwrap();
        let mut passed = 0;
        let mut total = 0;
        for test in sequence.members() {
            let obj = match test {
                JsonValue::Object(obj) => obj,
                _ => panic!("expected object"),
            };
            let id = obj.get(AT_ID).unwrap().as_str().unwrap();
            if let Some(ref case) = case {
                if case != id {
                    continue;
                }
            }
            let skip = match id {
                "#tli12" => {
                    // "Tests list elements expanded to IRIs with a bad @base.",
                    // But the JSON-LD Context Processing Algorithm says to error and aborts processing if @base is invalid. See step 5.7.5:
                    // https://w3c.github.io/json-ld-api/#algorithm
                    // Implemented in json-ld crate:
                    // https://github.com/timothee-haudebourg/json-ld/blob/3d084e5d616eb350918948b3c551f5177b973e9b/src/context/processing.rs#L339
                    true
                }
                "#te111" | "#te112" => {
                    // Why is "#fragment-works": "#fragment-works" not allowed
                    // but "?query=works": "?query=works" is?
                    true
                }
                "#te122" => {
                    // "Processors SHOULD generate a warning and MUST ignore IRIs having the form of a keyword."
                    // This test applies to expansion
                    true
                }
                "#tc037" | "#tc038" => {
                    // "Nesting terms may have property-scoped contexts defined."
                    // Applies to expansion
                    true
                }
                "#t0122" | "#t0123" | "#t0124" | "#t0125" => {
                    // "IRI resolution according to RFC3986."
                    // Applies to expansion and IRI resolution
                    true
                }
                _ => false,
            };
            if skip {
                eprintln!("test {}: skipping", id);
                continue;
            }
            if let Some(requires) = obj.get("requires") {
                if requires.as_str() == Some("GeneralizedRdf") {
                    eprintln!("test {}: skipping: requires Generalized RDF", id);
                    continue;
                }
            }
            if let Some(JsonValue::Object(options)) = obj.get("option") {
                if options.get("normative") == Some(&JsonValue::Boolean(false)) {
                    eprintln!("test {}: skipping: non-normative", id);
                    continue;
                }
                if let Some(spec_version) = options.get("specVersion") {
                    let spec_version = spec_version.as_str().unwrap();
                    if spec_version != "json-ld-1.1" {
                        eprintln!("test {}: skipping: spec version '{}'", id, spec_version);
                        continue;
                    }
                }
            }
            total += 1;
            if let Err(err) = test_to_rdf(&obj).await {
                if let Error::ExpectedOutput(expected, found) = err {
                    let changes = difference::Changeset::new(&found, &expected, "\n");
                    eprintln!("test {}: failed. diff:\n{}", id, changes);
                } else {
                    eprintln!("test {}: failed: {:?}", id, err);
                }
            } else {
                passed += 1;
            }
        }
        assert!(total > 0);
        assert_eq!(passed, total);
    }
}
