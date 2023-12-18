//! # Decentralized Identifier Resolution (DID Resolution)
//!
//! As specified in [Decentralized Identifier Resolution (DID Resolution) v0.2](https://w3c-ccg.github.io/did-resolution/)

use async_trait::async_trait;
use chrono::prelude::{DateTime, Utc};
#[cfg(feature = "http")]
use reqwest::{header, Client, StatusCode, Url};
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use serde_urlencoded;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::convert::TryFrom;

// https://w3c-ccg.github.io/did-resolution/
use crate::error::Error;
use crate::{
    DIDMethod, DIDParameters, Document, PrimaryDIDURL, Resource, ServiceEndpoint,
    VerificationMethod, VerificationMethodMap, VerificationRelationship, DIDURL,
};
use ssi_core::one_or_many::OneOrMany;
use ssi_json_ld::DID_RESOLUTION_V1_CONTEXT;
use ssi_jwk::JWK;

/// Media type for JSON.
pub const TYPE_JSON: &str = "application/json";
/// Media type for JSON-LD.
pub const TYPE_LD_JSON: &str = "application/ld+json";
/// Media type for a [DID Document in JSON
/// representation](https://www.w3.org/TR/did-core/#application-did-json).
pub const TYPE_DID_JSON: &str = "application/did+json";
/// Media type for a [DID Document in JSON-LD
/// representation](https://www.w3.org/TR/did-core/#application-did-ld-json).
pub const TYPE_DID_LD_JSON: &str = "application/did+ld+json";
/// Pseudo-media-type used when returning a URL from [DID URL
/// dereferencing](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm).
pub const TYPE_URL: &str = "text/url";
/// [`invalidDid`](https://www.w3.org/TR/did-spec-registries/#invaliddid) error value for DID
/// Resolution / DID URL Dereferencing.
pub const ERROR_INVALID_DID: &str = "invalidDid";
/// [`invalidDidUrl`](https://www.w3.org/TR/did-spec-registries/#invaliddidurl) error value for DID URL Dereferencing.
pub const ERROR_INVALID_DID_URL: &str = "invalidDidUrl";
/// `unauthorized` error for DID Resolution / DID URL Dereferencing.
pub const ERROR_UNAUTHORIZED: &str = "unauthorized";
/// [`notFound`](https://www.w3.org/TR/did-spec-registries/#notfound) error value for DID URL Dereferencing.
pub const ERROR_NOT_FOUND: &str = "notFound";
/// `methodNotSupported` error value for DID Resolution / DID URL Dereferencing.
pub const ERROR_METHOD_NOT_SUPPORTED: &str = "methodNotSupported";
/// [`representationNotSupported`](https://www.w3.org/TR/did-spec-registries/#representationnotsupported) error value for DID URL Dereferencing.
pub const ERROR_REPRESENTATION_NOT_SUPPORTED: &str = "representationNotSupported";
/// Media type expected for a [DID Resolution Result][ResolutionResult].
pub const TYPE_DID_RESOLUTION: &str =
    "application/ld+json;profile=\"https://w3id.org/did-resolution\";charset=utf-8";

/// Maximum level of recursion when following DID controller links.
pub const MAX_CONTROLLERS: usize = 100;

/// [Metadata structure](https://www.w3.org/TR/did-core/#metadata-structure) "for DID resolution,
/// DID URL dereferencing, and other DID-related processes"
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Metadata {
    /// [String](https://infra.spec.whatwg.org/#string)
    String(String),
    /// A [map](https://infra.spec.whatwg.org/#maps) of properties for a metadata structure.
    Map(HashMap<String, Metadata>),
    /// [List](https://infra.spec.whatwg.org/#list) (array)
    List(Vec<Metadata>),
    /// [Boolean](https://infra.spec.whatwg.org/#boolean)
    Boolean(bool),
    /// [Null](https://infra.spec.whatwg.org/#nulls)
    Null,
}

/// [DID Resolution Options](https://www.w3.org/TR/did-core/#did-resolution-options).
///
/// Formerly known as "DID resolution input metadata".
///
/// Used as input to [DID Resolution][DIDResolver::resolve].
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionInputMetadata {
    /// [`accept`](https://www.w3.org/TR/did-spec-registries/#accept) resolution option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<String>,
    /// [`versionId`](https://www.w3.org/TR/did-spec-registries/#versionId-param) DID Parameter as
    /// DID resolution option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    /// [`versionTime`](https://www.w3.org/TR/did-spec-registries/#versionTime-param) DID Parameter as
    /// DID resolution option.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_time: Option<String>,
    /// `no-cache` resolution option from [DID
    /// Resolution](https://w3c-ccg.github.io/did-resolution/#caching).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_cache: Option<bool>,
    /// Additional options.
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Metadata>>,
}

/// [DID Resolution Metadata](https://www.w3.org/TR/did-core/#did-resolution-metadata)
///
/// in [DID Resolution](https://w3c-ccg.github.io/did-resolution/#output-resolutionmetadata)
///
/// Returned from DID Resolution ([`resolve`][DIDResolver::resolve] / [`resolveRepresentation`][DIDResolver::resolve_representation]).
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionMetadata {
    /// `error` metadata property. Values should be registered in [DID Specification
    /// Registries](https://www.w3.org/TR/did-spec-registries/#error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [`contentType`](https://www.w3.org/TR/did-spec-registries/#contenttype) metadata property.
    pub content_type: Option<String>,
    /// Additional metadata properties.
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Metadata>>,
}

/// [DID document metadata](https://www.w3.org/TR/did-core/#did-document-metadata).
///
/// A [Metadata] structure describing a [DID document][Document] in a [DID Resolution
/// Result][ResolutionResult].
///
/// Specified:
/// - in [DID Core](https://www.w3.org/TR/did-core/#dfn-diddocumentmetadata)
/// - in [DID Resolution](https://w3c-ccg.github.io/did-resolution/#output-documentmetadata)
/// - in [DID Specification
/// Registries](https://www.w3.org/TR/did-spec-registries/#did-document-metadata)
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DocumentMetadata {
    /// [`created`](https://www.w3.org/TR/did-core/#dfn-created) DID document metadata property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    /// [`updated`](https://www.w3.org/TR/did-core/#dfn-updated) DID document metadata property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
    /// [`deactivated`](https://www.w3.org/TR/did-core/#dfn-deactivated) DID document metadata property.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
    /// Additional options.
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Metadata>>,
}

/// [DID URL Dereferencing Options](https://www.w3.org/TR/did-core/#did-url-dereferencing-options)
///
/// Formerly known as dereferencing input metadata.
///
/// Used as input to [DID URL dereferencing][dereference].
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DereferencingInputMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [`accept`](https://www.w3.org/TR/did-spec-registries/#accept) option.
    pub accept: Option<String>,
    /// `service-type` DID parameter mentioned in [DID
    /// Resolution](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    /// `follow-redirect` resolution option, specified in [DID
    /// Resolution](https://w3c-ccg.github.io/did-resolution/#redirect).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follow_redirect: Option<bool>,
    /// Additional options.
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Metadata>>,
}

/// [DID URL dereferencing
/// metadata](https://www.w3.org/TR/did-core/#did-url-dereferencing-metadata).
///
/// Returned from [DID URL dereferencing][dereference].
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DereferencingMetadata {
    /// `error` metadata property. Values should be registered in [DID Specification
    /// Registries](https://www.w3.org/TR/did-spec-registries/#error).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// [`contentType`](https://www.w3.org/TR/did-spec-registries/#contenttype) metadata property.
    pub content_type: Option<String>,
    /// Additional metadata properties.
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Metadata>>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
/// A resource returned by [DID URL dereferencing][dereference]
#[serde(untagged)]
#[allow(clippy::large_enum_variant)]
pub enum Content {
    /// A DID Document
    DIDDocument(Document),
    /// A URL
    URL(String),
    /// A resource (e.g. verification method map)
    Object(Resource),
    /// Binary data (e.g. a DID document representation)
    Data(Vec<u8>),
    /// Null (empty result)
    Null,
}

#[cfg(feature = "http")]
fn get_first_context_uri(value: &Value) -> Option<iref::IriRef> {
    match value.get("@context")? {
        Value::Array(vec) => vec.get(0)?.as_str().and_then(|v| iref::IriRef::new(v).ok()),
        Value::String(string) => iref::IriRef::new(string).ok(),
        _ => None,
    }
}

impl Content {
    /// Serialize as a [Vec].
    pub fn into_vec(self) -> Result<Vec<u8>, Error> {
        if let Content::Data(data) = self {
            Ok(data)
        } else {
            Ok(serde_json::to_vec(&self)?)
        }
    }
}

/// Wrap an Error in a Dereferencing Metadata atructure.
impl From<Error> for DereferencingMetadata {
    fn from(err: Error) -> Self {
        DereferencingMetadata {
            error: Some(err.to_string()),
            ..Default::default()
        }
    }
}

// needed for:
// - https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary Step 2.1
/// Convert DID Resolution Metadata to DID URL Dereferencing metadata.
///
/// Used when returning a resolved DID document for [DID URL dereferencing][dereference].
impl From<ResolutionMetadata> for DereferencingMetadata {
    fn from(res_meta: ResolutionMetadata) -> Self {
        Self {
            error: res_meta.error,
            content_type: res_meta.content_type,
            property_set: res_meta.property_set,
        }
    }
}

// needed for:
// - https://w3c-ccg.github.io/did-resolution/#bindings-https Step 1.10.2.1
/// Convert DID URL Dereferencing metadata to DID Resolution Metadata.
///
/// Used when producing a DID resolution result after [DID URL dereferencing][dereference].
impl From<DereferencingMetadata> for ResolutionMetadata {
    fn from(deref_meta: DereferencingMetadata) -> Self {
        Self {
            error: deref_meta.error,
            content_type: deref_meta.content_type,
            property_set: deref_meta.property_set,
        }
    }
}

/// Construct DID URL Dereferencing Metadata from an error value.
impl DereferencingMetadata {
    pub fn from_error(err: &str) -> Self {
        DereferencingMetadata {
            error: Some(err.to_owned()),
            ..Default::default()
        }
    }
}

/// Construct DID Resolution Metadata from an error value.
impl ResolutionMetadata {
    pub fn from_error(err: &str) -> Self {
        ResolutionMetadata {
            error: Some(err.to_owned()),
            ..Default::default()
        }
    }
}

/// Metadata structure (`contentMetadata`) returned from [DID URL
/// dereferencing](https://www.w3.org/TR/did-core/#did-url-dereferencing) ([`dereference`]).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ContentMetadata {
    /// DID document metadata, for when the `contentStream` returned by DID URL
    /// dereferencing is a DID document.
    DIDDocument(DocumentMetadata),
    /// Metadata for non-DID-Document content.
    Other(HashMap<String, Metadata>),
}

impl Default for ContentMetadata {
    /// Construct an empty content metadata structure.
    fn default() -> Self {
        ContentMetadata::Other(HashMap::new())
    }
}

/// [DID Resolution Result](https://w3c-ccg.github.io/did-resolution/#did-resolution-result) data
/// structure.
///
/// Results from DID resolution and/or DID URL dereferencing.
///
/// Used in the [DID Resolution HTTP(S)
/// Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionResult {
    /// Value for a [`@context`](https://www.w3.org/TR/did-core/#dfn-context) property of a DID
    /// Resolution Result.
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
    /// [DID Document](https://www.w3.org/TR/did-core/#dfn-diddocument).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<Document>,
    /// [DID Resolution Metadata](https://www.w3.org/TR/did-core/#dfn-didresolutionmetadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_resolution_metadata: Option<ResolutionMetadata>,
    /// [DID Document Metadata](https://www.w3.org/TR/did-core/#dfn-diddocumentmetadata).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_metadata: Option<DocumentMetadata>,
    /// Additional properties.
    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, Value>>,
}

/// An empty DID Resolution Result, using the [DID Resolution v1 Context
/// URI][DID_RESOLUTION_V1_CONTEXT]
impl Default for ResolutionResult {
    fn default() -> Self {
        Self {
            context: Some(Value::String(DID_RESOLUTION_V1_CONTEXT.to_string())),
            did_document: None,
            did_resolution_metadata: None,
            did_document_metadata: None,
            property_set: None,
        }
    }
}

/// A [DID resolver](https://www.w3.org/TR/did-core/#dfn-did-resolvers),
/// implementing the [DID Resolution](https://www.w3.org/TR/did-core/#did-resolution)
/// [algorithm](https://w3c-ccg.github.io/did-resolution/#resolving-algorithm) and
/// optionally [DID URL Dereferencing](https://www.w3.org/TR/did-core/#did-url-dereferencing).
///
/// ## Example
///
/// An example of a DID resolver with a static DID document.
///
/// ```
/// use async_trait::async_trait;
/// use ssi_dids::Document;
/// use ssi_dids::did_resolve::{
///     DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata,
///     ERROR_NOT_FOUND
/// };
///
/// pub struct DIDExampleStatic;
///
/// #[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
/// #[cfg_attr(not(target_arch = "wasm32"), async_trait)]
/// impl DIDResolver for DIDExampleStatic {
///     async fn resolve(
///         &self,
///         did: &str,
///         _input_metadata: &ResolutionInputMetadata,
///     ) -> (
///         ResolutionMetadata,
///         Option<Document>,
///         Option<DocumentMetadata>,
///     ) {
///         match did {
///             "did:example:foo" => {
///                 let doc = match Document::from_json(include_str!("../../tests/did-example-foo.json")) {
///                     Ok(doc) => doc,
///                     Err(e) => {
///                         return (
///                             ResolutionMetadata::from_error(&format!(
///                                 "Unable to parse DID document: {:?}",
///                                 e
///                             )),
///                             None,
///                             None,
///                         );
///                     }
///                 };
///                 (
///                     ResolutionMetadata::default(),
///                     Some(doc),
///                     Some(DocumentMetadata::default()),
///                 )
///             }
///             _ => return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None),
///         }
///     }
/// }
/// ```
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DIDResolver: Sync {
    /// [Resolve a DID](https://w3c-ccg.github.io/did-resolution/#resolving-algorithm)
    ///
    /// i.e. the `resolve` function from [DID
    /// Core](https://www.w3.org/TR/did-core/#did-resolution) and [DID
    /// Resolution](https://w3c-ccg.github.io/did-resolution/#resolving).
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    );

    /// [Resolve a DID](https://w3c-ccg.github.io/did-resolution/#resolving-algorithm) in a given
    /// representation
    ///
    /// i.e. the `resolveRepresentation` function from [DID
    /// Core](https://www.w3.org/TR/did-core/#did-resolution) and [DID
    /// Resolution](https://w3c-ccg.github.io/did-resolution/#resolving).
    async fn resolve_representation(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
        // Implement resolveRepresentation in terms of resolve.
        let (mut res_meta, doc, doc_meta) = self.resolve(did, input_metadata).await;
        let doc_representation = match doc {
            None => Vec::new(),
            Some(doc) => match serde_json::to_vec_pretty(&doc) {
                Ok(vec) => vec,
                Err(err) => {
                    res_meta.error =
                        Some("Error serializing JSON: ".to_string() + &err.to_string());
                    Vec::new()
                }
            },
        };
        // Assume JSON-LD DID document
        res_meta.content_type = Some(TYPE_DID_LD_JSON.to_string());
        (res_meta, doc_representation, doc_meta)
    }

    /// Dereference a DID URL.
    ///
    /// DID methods implement this function to support
    /// [dereferencing](https://w3c-ccg.github.io/did-resolution/#dereferencing) DID URLs with
    /// paths and query strings.  Callers should use [`dereference`] instead of this function.
    async fn dereference(
        &self,
        _primary_did_url: &PrimaryDIDURL,
        _did_url_dereferencing_input_metadata: &DereferencingInputMetadata,
    ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
        None
    }

    /// Cast the resolver as a [`DIDMethod`], if possible.
    fn to_did_method(&self) -> Option<&dyn DIDMethod> {
        None
    }
}

/// Dereference a DID URL, according to [DID Core](https://www.w3.org/TR/did-core/#did-url-dereferencing) and [DID Resolution](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm).
pub async fn dereference(
    resolver: &dyn DIDResolver,
    did_url_str: &str,
    did_url_dereferencing_input_metadata: &DereferencingInputMetadata,
) -> (DereferencingMetadata, Content, ContentMetadata) {
    let did_url = match DIDURL::try_from(did_url_str.to_string()) {
        Ok(did_url) => did_url,
        Err(_error) => {
            return (
                DereferencingMetadata::from_error(ERROR_INVALID_DID_URL),
                Content::Null,
                ContentMetadata::default(),
            );
        }
    };
    // 1
    let did_res_input_metadata: ResolutionInputMetadata = match did_url.query.as_ref() {
        Some(query) => match serde_urlencoded::from_str(query) {
            Ok(meta) => meta,
            Err(error) => {
                return (
                    DereferencingMetadata::from(Error::from(error)),
                    Content::Null,
                    ContentMetadata::default(),
                );
            }
        },
        None => ResolutionInputMetadata::default(),
    };

    let (did_doc_res_meta, did_doc_opt, did_doc_meta_opt) = resolver
        .resolve(&did_url.did, &did_res_input_metadata)
        .await;
    if let Some(ref error) = did_doc_res_meta.error {
        return (
            DereferencingMetadata::from_error(error),
            Content::Null,
            ContentMetadata::default(),
        );
    }
    let (did_doc, did_doc_meta) = match (did_doc_opt, did_doc_meta_opt) {
        (Some(doc), Some(meta)) => (doc, meta),
        _ => {
            return (
                DereferencingMetadata::from_error(ERROR_NOT_FOUND),
                Content::Null,
                ContentMetadata::default(),
            );
        }
    };
    // 2
    let (primary_did_url, fragment) = did_url.remove_fragment();
    let (deref_meta, content, content_meta) = dereference_primary_resource(
        resolver,
        &primary_did_url,
        did_url_dereferencing_input_metadata,
        &did_doc_res_meta,
        did_doc,
        &did_doc_meta,
    )
    .await;
    if deref_meta.error.is_some() {
        return (deref_meta, content, content_meta);
    }
    if let Some(fragment) = fragment {
        // 3
        return dereference_secondary_resource(
            resolver,
            primary_did_url,
            fragment,
            did_url_dereferencing_input_metadata,
            deref_meta,
            content,
            content_meta,
        )
        .await;
    }
    (deref_meta, content, content_meta)
}

/// [Dereferencing the Primary Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary) - a subalgorithm of [DID URL dereferencing](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm)
async fn dereference_primary_resource(
    resolver: &dyn DIDResolver,
    primary_did_url: &PrimaryDIDURL,
    did_url_dereferencing_input_metadata: &DereferencingInputMetadata,
    res_meta: &ResolutionMetadata,
    did_doc: Document,
    _did_doc_meta: &DocumentMetadata,
) -> (DereferencingMetadata, Content, ContentMetadata) {
    let parameters: DIDParameters = match primary_did_url.query {
        Some(ref query) => match serde_urlencoded::from_str(query) {
            Ok(params) => params,
            Err(err) => {
                return (
                    DereferencingMetadata::from(Error::from(err)),
                    Content::Null,
                    ContentMetadata::default(),
                );
            }
        },
        None => Default::default(),
    };
    // 1
    if let Some(ref service) = parameters.service {
        // 1.1
        let service = match did_doc.select_service(service) {
            Some(service) => service,
            None => {
                return (
                    DereferencingMetadata::from_error("Service not found"),
                    Content::Null,
                    ContentMetadata::default(),
                );
            }
        };
        // 1.2, 1.2.1
        // TODO: support these other cases?
        let input_service_endpoint_url = match &service.service_endpoint {
            None => {
                return (
                    DereferencingMetadata::from_error("Missing service endpoint"),
                    Content::Null,
                    ContentMetadata::default(),
                );
            }
            Some(OneOrMany::One(ServiceEndpoint::URI(uri))) => uri,
            Some(OneOrMany::One(ServiceEndpoint::Map(_))) => {
                return (
                    DereferencingMetadata::from_error("serviceEndpoint map not supported"),
                    Content::Null,
                    ContentMetadata::default(),
                );
            }
            Some(OneOrMany::Many(_)) => {
                return (
                    DereferencingMetadata::from_error(
                        "Multiple serviceEndpoint properties not supported",
                    ),
                    Content::Null,
                    ContentMetadata::default(),
                );
            }
        };

        // 1.2.2, 1.2.3
        let did_url = DIDURL::from(primary_did_url.clone());
        let output_service_endpoint_url =
            match construct_service_endpoint(&did_url, &parameters, input_service_endpoint_url) {
                Ok(url) => url,
                Err(err) => {
                    return (
                        DereferencingMetadata::from_error(&format!(
                            "Unable to construct service endpoint: {err}"
                        )),
                        Content::Null,
                        ContentMetadata::default(),
                    );
                }
            };
        // 1.3
        return (
            DereferencingMetadata {
                content_type: Some(TYPE_URL.to_string()),
                ..Default::default()
            },
            Content::URL(output_service_endpoint_url),
            ContentMetadata::default(),
        );
    }
    // 2
    if primary_did_url.path.is_none() && primary_did_url.query.is_none() {
        // 2.1
        // Add back contentType, since the resolve function does not include it, but we need
        // it to dereference the secondary resource.
        // TODO: detect non-JSON-LD DID documents
        let deref_meta = DereferencingMetadata {
            content_type: Some(TYPE_DID_LD_JSON.to_string()),
            ..DereferencingMetadata::from(res_meta.clone())
        };
        return (
            deref_meta,
            Content::DIDDocument(did_doc),
            ContentMetadata::default(),
        );
    }
    // 3
    if primary_did_url.path.is_some() || primary_did_url.query.is_some() {
        // 3.1
        if let Some(result) = resolver
            .dereference(primary_did_url, did_url_dereferencing_input_metadata)
            .await
        {
            return result;
        }
        // 3.2
        // TODO: enable the client to dereference the DID URL
    }
    // 4
    #[allow(clippy::let_and_return)]
    let null_result = (
        DereferencingMetadata::default(),
        Content::Null,
        ContentMetadata::default(),
    );
    // 4.1
    null_result
}

/// [Dereferencing the Secondary Resource](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary) - a subalgorithm of [DID URL dereferencing](https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm)
async fn dereference_secondary_resource(
    _resolver: &dyn DIDResolver,
    primary_did_url: PrimaryDIDURL,
    fragment: String,
    _did_url_dereferencing_input_metadata: &DereferencingInputMetadata,
    deref_meta: DereferencingMetadata,
    content: Content,
    content_meta: ContentMetadata,
) -> (DereferencingMetadata, Content, ContentMetadata) {
    let content_type = deref_meta.content_type.as_deref();
    // 1
    match content {
        // https://www.w3.org/TR/did-core/#application-did-json
        //   "Fragment identifiers used with application/did+json are treated according to the
        //   rules defined in § Fragment."
        //   https://www.w3.org/TR/did-core/#fragment
        // TODO: use actual JSON-LD fragment dereferencing
        // https://www.w3.org/TR/did-core/#application-did-ld-json
        //   Fragment identifiers used with application/did+ld+json are treated according to the
        //   rules associated with the JSON-LD 1.1: application/ld+json media type [JSON-LD11].
        Content::DIDDocument(ref doc)
            if content_type == Some(TYPE_DID_LD_JSON) || content_type == Some(TYPE_DID_JSON) =>
        {
            // put the fragment back in the URL
            let did_url = primary_did_url.with_fragment(fragment);
            // 1.1
            let object = match doc.select_object(&did_url) {
                Ok(object) => object,
                Err(error) => {
                    return (
                        DereferencingMetadata::from_error(&format!(
                            "Unable to find object in DID document: {error}"
                        )),
                        Content::Null,
                        ContentMetadata::default(),
                    );
                }
            };
            return (
                DereferencingMetadata {
                    content_type: Some(String::from(if content_type == Some(TYPE_DID_LD_JSON) {
                        TYPE_LD_JSON
                    } else {
                        TYPE_JSON
                    })),
                    ..Default::default()
                },
                Content::Object(object),
                ContentMetadata::default(),
            );
        }
        Content::URL(mut url) => {
            // 2
            // 2.1
            if url.contains('#') {
                // https://w3c-ccg.github.io/did-resolution/#input
                return (
                    DereferencingMetadata::from_error("DID URL and input service endpoint URL MUST NOT both have a fragment component"),
                    Content::Null,
                    ContentMetadata::default()
                );
            }
            url.push('#');
            url.push_str(&fragment);
            return (deref_meta, Content::URL(url), content_meta);
        }
        _ => {}
    }
    // 3
    match content_type {
        None => (
            DereferencingMetadata::from_error("Resource missing content type"),
            Content::Null,
            ContentMetadata::default(),
        ),
        Some(content_type) => (
            DereferencingMetadata::from_error(&format!("Unsupported content type: {content_type}")),
            Content::Null,
            ContentMetadata::default(),
        ),
    }
}

/// <https://w3c-ccg.github.io/did-resolution/#service-endpoint-construction>
fn construct_service_endpoint(
    did_url: &DIDURL,
    did_parameters: &DIDParameters,
    service_endpoint_url: &str,
) -> Result<String, String> {
    // https://w3c-ccg.github.io/did-resolution/#algorithm
    // 1, 2, 3
    let mut parts = service_endpoint_url.splitn(2, '#');
    let service_endpoint_url = parts.next().unwrap();
    let input_service_endpoint_fragment = parts.next();
    if did_url.fragment.is_some() && input_service_endpoint_fragment.is_some() {
        // https://w3c-ccg.github.io/did-resolution/#input
        return Err(
            "DID URL and input service endpoint URL MUST NOT both have a fragment component"
                .to_string(),
        );
    }
    parts = service_endpoint_url.splitn(2, '?');
    let service_endpoint_url = parts.next().unwrap();
    let input_service_endpoint_query = parts.next();

    let did_url_path: String;
    let did_url_query: Option<String>;
    // Work around https://github.com/w3c-ccg/did-resolution/issues/61
    if let Some(ref relative_ref) = did_parameters.relative_ref {
        parts = relative_ref.splitn(2, '?');
        did_url_path = parts.next().unwrap().to_owned();
        if !did_url.path_abempty.is_empty() {
            return Err("DID URL and relativeRef MUST NOT both have a path component".to_string());
        }
        did_url_query = parts.next().map(|q| q.to_owned());
    } else {
        did_url_path = did_url.path_abempty.to_owned();
        did_url_query = did_url.query.to_owned();
        // TODO: do something with the DID URL query that is being ignored in favor of the
        // relativeRef query
    }
    if did_url_query.is_some() && input_service_endpoint_query.is_some() {
        return Err(
            "DID URL and input service endpoint URL MUST NOT both have a query component"
                .to_string(),
        );
    }

    let mut output_url = service_endpoint_url.to_owned();
    // 4
    output_url += &did_url_path;
    // 5
    if let Some(query) = input_service_endpoint_query {
        output_url.push('?');
        output_url.push_str(query);
    }
    // 6
    if let Some(query) = did_url_query {
        output_url.push('?');
        output_url.push_str(&query);
    }
    // 7
    if let Some(fragment) = input_service_endpoint_fragment {
        output_url.push('#');
        output_url.push_str(fragment);
    }
    // 8
    if let Some(fragment) = &did_url.fragment {
        output_url.push('#');
        output_url.push_str(fragment);
    }
    Ok(output_url)
}

/// A DID Resolver implementing a client for the [DID Resolution HTTP(S)
/// Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
#[cfg(feature = "http")]
#[derive(Debug, Clone, Default)]
pub struct HTTPDIDResolver {
    /// HTTP(S) URL for DID resolver HTTP(S) endpoint.
    pub endpoint: String,
}

#[cfg(feature = "http")]
impl HTTPDIDResolver {
    /// Construct a new HTTP DID Resolver with a given [endpoint][HTTPDIDResolver::endpoint] URL.
    pub fn new(url: &str) -> Self {
        Self {
            endpoint: url.to_string(),
        }
    }
}

#[cfg(feature = "http")]
fn transform_resolution_result(
    result: Result<ResolutionResult, serde_json::Error>,
) -> (
    ResolutionMetadata,
    Option<Document>,
    Option<DocumentMetadata>,
) {
    let result: ResolutionResult = match result {
        Ok(result) => result,
        Err(err) => {
            return (
                ResolutionMetadata::from_error(&format!("Error parsing resolution result: {err}")),
                None,
                None,
            )
        }
    };
    let res_meta = if let Some(mut meta) = result.did_resolution_metadata {
        // https://www.w3.org/TR/did-core/#did-resolution-metadata
        // contentType - "MUST NOT be present if the resolve function was called"
        meta.content_type = None;
        meta
    } else {
        ResolutionMetadata::default()
    };
    (res_meta, result.did_document, result.did_document_metadata)
}

#[cfg(feature = "http")]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for HTTPDIDResolver {
    /// Resolve a DID over HTTP(S), using the [DID Resolution HTTP(S) Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let querystring = match serde_urlencoded::to_string(input_metadata) {
            Ok(qs) => qs,
            Err(err) => {
                return (
                    ResolutionMetadata {
                        error: Some(
                            "Unable to serialize input metadata into query string: ".to_string()
                                + &err.to_string(),
                        ),
                        content_type: None,
                        property_set: None,
                    },
                    None,
                    None,
                )
            }
        };
        let did_urlencoded =
            percent_encoding::utf8_percent_encode(did, percent_encoding::CONTROLS).to_string();
        let mut url = self.endpoint.clone() + &did_urlencoded;
        if !querystring.is_empty() {
            url.push('?');
            url.push_str(&querystring);
        }
        let url: Url = match url.parse() {
            Ok(url) => url,
            Err(_) => {
                return (
                    ResolutionMetadata {
                        error: Some(ERROR_INVALID_DID.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    None,
                    None,
                );
            }
        };
        let client = match Client::builder().build() {
            Ok(client) => client,
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(&format!("Error building HTTP client: {err}")),
                    None,
                    None,
                );
            }
        };
        let resp = match client
            .get(url)
            .header("Accept", TYPE_DID_RESOLUTION)
            .header("User-Agent", crate::USER_AGENT)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(&format!("Error sending HTTP request: {err}")),
                    None,
                    None,
                )
            }
        };
        let status = resp.status();
        let content_type = match resp.headers().get(header::CONTENT_TYPE) {
            None => None,
            Some(content_type) => Some(String::from(match content_type.to_str() {
                Ok(content_type) => content_type,
                Err(err) => {
                    return (
                        ResolutionMetadata::from_error(&format!(
                            "Error reading HTTP header: {err}"
                        )),
                        None,
                        None,
                    )
                }
            })),
        }
        .unwrap_or_default();
        let res_result_representation = match resp.bytes().await {
            Ok(bytes) => bytes.to_vec(),
            Err(err) => {
                return (
                    ResolutionMetadata {
                        error: Some("Error reading HTTP response: ".to_string() + &err.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    None,
                    None,
                )
            }
        };

        if content_type == TYPE_DID_RESOLUTION {
            // Handle result using DID Resolution Result media type (JSON-LD)
            return transform_resolution_result(serde_json::from_slice(&res_result_representation));
        }

        if status == StatusCode::NOT_FOUND {
            return (ResolutionMetadata::from_error(ERROR_NOT_FOUND), None, None);
        }

        // Assume the response is JSON(-LD) (DID Document or DID Resolution result)
        let value: Value = match serde_json::from_slice(&res_result_representation) {
            Ok(result) => result,
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(&format!(
                        "Error parsing resolution response: {err}"
                    )),
                    None,
                    None,
                )
            }
        };

        let first_context_uri = get_first_context_uri(&value);
        if first_context_uri == Some(DID_RESOLUTION_V1_CONTEXT.as_iri_ref()) {
            // Detect DID Resolution Result that didn't have specific media type.
            return transform_resolution_result(serde_json::from_value(value));
        }

        // Assume the response is a JSON(-LD) DID Document by default.
        let doc: Document = match serde_json::from_value(value) {
            Ok(doc) => doc,
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(&format!("Error parsing DID document: {err}")),
                    None,
                    None,
                )
            }
        };
        return (ResolutionMetadata::default(), Some(doc), None);
    }

    // Use default resolveRepresentation implementation in terms of resolve,
    // until resolveRepresentation has its own HTTP(S) binding:
    // https://github.com/w3c-ccg/did-resolution/issues/57

    /// Dereference a DID URL over HTTP(S), using the [DID Resolution HTTP(S) Binding](https://w3c-ccg.github.io/did-resolution/#bindings-https).
    async fn dereference(
        &self,
        primary_did_url: &PrimaryDIDURL,
        input_metadata: &DereferencingInputMetadata,
    ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
        let querystring = match serde_urlencoded::to_string(input_metadata) {
            Ok(qs) => qs,
            Err(err) => {
                return Some((
                    DereferencingMetadata::from_error(&format!(
                        "Unable to serialize input metadata into query string: {err}"
                    )),
                    Content::Null,
                    ContentMetadata::default(),
                ))
            }
        };
        let did_url_urlencoded = percent_encoding::utf8_percent_encode(
            &primary_did_url.to_string(),
            percent_encoding::CONTROLS,
        )
        .to_string();
        let mut url = self.endpoint.clone() + &did_url_urlencoded;
        if !querystring.is_empty() {
            url.push('?');
            url.push_str(&querystring);
        }
        let url: Url = match url.parse() {
            Ok(url) => url,
            Err(_) => {
                return Some((
                    DereferencingMetadata::from_error(ERROR_INVALID_DID),
                    Content::Null,
                    ContentMetadata::default(),
                ));
            }
        };
        let client = match Client::builder().build() {
            Ok(client) => client,
            Err(err) => {
                return Some((
                    DereferencingMetadata::from_error(&format!(
                        "Error building HTTP client: {err}"
                    )),
                    Content::Null,
                    ContentMetadata::default(),
                ));
            }
        };
        let resp = match client
            .get(url)
            .header("Accept", TYPE_DID_RESOLUTION)
            .header("User-Agent", crate::USER_AGENT)
            .send()
            .await
        {
            Ok(resp) => resp,
            Err(err) => {
                return Some((
                    DereferencingMetadata::from_error(&format!(
                        "Error sending HTTP request: {err}"
                    )),
                    Content::Null,
                    ContentMetadata::default(),
                ))
            }
        };
        let mut deref_meta = DereferencingMetadata::default();
        let mut content = Content::Null;
        let mut content_meta = ContentMetadata::default();
        deref_meta.error = match resp.status() {
            StatusCode::NOT_FOUND => Some(ERROR_NOT_FOUND.to_string()),
            StatusCode::BAD_REQUEST => Some(ERROR_INVALID_DID.to_string()),
            StatusCode::NOT_ACCEPTABLE => Some(ERROR_REPRESENTATION_NOT_SUPPORTED.to_string()),
            _ => None,
        };
        let content_type = match resp.headers().get(header::CONTENT_TYPE) {
            None => None,
            Some(content_type) => Some(String::from(match content_type.to_str() {
                Ok(content_type) => content_type,
                Err(err) => {
                    return Some((
                        DereferencingMetadata::from_error(&format!(
                            "Error reading HTTP header: {err}"
                        )),
                        Content::Null,
                        ContentMetadata::default(),
                    ))
                }
            })),
        }
        .unwrap_or_default();
        let deref_result_bytes = match resp.bytes().await {
            Ok(bytes) => bytes.to_vec(),
            Err(err) => {
                return Some((
                    DereferencingMetadata::from_error(&format!(
                        "Error reading HTTP response: {err}"
                    )),
                    Content::Null,
                    ContentMetadata::default(),
                ))
            }
        };
        match &content_type[..] {
            TYPE_DID_LD_JSON | TYPE_DID_JSON => {
                let doc: Document = match serde_json::from_slice(&deref_result_bytes) {
                    Ok(result) => result,
                    Err(err) => {
                        return Some((
                            DereferencingMetadata::from_error(&format!(
                                "Error parsing DID document: {err}"
                            )),
                            Content::Null,
                            ContentMetadata::default(),
                        ))
                    }
                };
                content = Content::DIDDocument(doc);
                content_meta = ContentMetadata::DIDDocument(DocumentMetadata::default());
                deref_meta.content_type = Some(TYPE_DID_LD_JSON.to_string());
            }
            TYPE_DID_RESOLUTION => {
                let result: ResolutionResult = match serde_json::from_slice(&deref_result_bytes) {
                    Ok(result) => result,
                    Err(err) => {
                        return Some((
                            DereferencingMetadata::from_error(&format!(
                                "Error parsing DID resolution result: {err}"
                            )),
                            Content::Null,
                            ContentMetadata::default(),
                        ))
                    }
                };
                if let Some(res_meta) = result.did_resolution_metadata {
                    deref_meta = res_meta.into();
                }
                if let Some(doc) = result.did_document {
                    content = Content::DIDDocument(doc);
                }
                content_meta =
                    ContentMetadata::DIDDocument(result.did_document_metadata.unwrap_or_default());
            }
            TYPE_LD_JSON | TYPE_JSON => {
                let object: BTreeMap<String, Value> =
                    match serde_json::from_slice(&deref_result_bytes) {
                        Ok(result) => result,
                        Err(err) => {
                            return Some((
                                DereferencingMetadata::from_error(&format!(
                                    "Error parsing JSON: {err}"
                                )),
                                Content::Null,
                                ContentMetadata::default(),
                            ))
                        }
                    };
                content = Content::Object(Resource::Object(object));
                deref_meta.content_type = Some(content_type);
            }
            _ => {
                deref_meta.content_type = Some(content_type);
                content = Content::Data(deref_result_bytes.to_vec());
            }
        }
        Some((deref_meta, content, content_meta))
    }
}

/// Compose multiple DID resolvers in series.
///
/// Each underlying DID resolver is tried in series until one supports the
/// requested DID method.
#[derive(Clone, Default)]
pub struct SeriesResolver<'a> {
    /// Underlying DID resolvers.
    pub resolvers: Vec<&'a (dyn DIDResolver)>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> DIDResolver for SeriesResolver<'a> {
    /// Resolve a DID using a series of DID resolvers.
    ///
    /// The first DID resolution result that is not a [`methodNotSupported`][ERROR_METHOD_NOT_SUPPORTED] error is returned as the
    /// result.
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        for resolver in &self.resolvers {
            let (res_meta, doc_opt, doc_meta_opt) = resolver.resolve(did, input_metadata).await;
            let method_supported = match res_meta.error {
                None => true,
                Some(ref err) => err != ERROR_METHOD_NOT_SUPPORTED,
            };
            if method_supported {
                return (res_meta, doc_opt, doc_meta_opt);
            }
        }
        (
            ResolutionMetadata::from_error(ERROR_METHOD_NOT_SUPPORTED),
            None,
            None,
        )
    }

    /// Resolve a DID in a representation using a series of DID resolvers.
    async fn resolve_representation(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
        for resolver in &self.resolvers {
            let (res_meta, doc_data, doc_meta_opt) =
                resolver.resolve_representation(did, input_metadata).await;
            let method_supported = match res_meta.error {
                None => true,
                Some(ref err) => err != ERROR_METHOD_NOT_SUPPORTED,
            };
            if method_supported {
                return (res_meta, doc_data, doc_meta_opt);
            }
        }
        (
            ResolutionMetadata::from_error(ERROR_METHOD_NOT_SUPPORTED),
            Vec::new(),
            None,
        )
    }

    /// Dereference a DID URL using a series of DID resolvers (DID URL dereferencers).
    async fn dereference(
        &self,
        primary_did_url: &PrimaryDIDURL,
        input_metadata: &DereferencingInputMetadata,
    ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
        for resolver in &self.resolvers {
            if let Some((deref_meta, content, content_meta)) =
                resolver.dereference(primary_did_url, input_metadata).await
            {
                let method_supported = match deref_meta.error {
                    None => true,
                    Some(ref err) => err != ERROR_METHOD_NOT_SUPPORTED,
                };
                if method_supported {
                    return Some((deref_meta, content, content_meta));
                }
            }
        }
        None
    }
}

// TODO: replace with Try trait implementation once stabilized.
// <https://github.com/rust-lang/rust/issues/84277>
pub async fn easy_resolve(did: &str, resolver: &dyn DIDResolver) -> Result<Document, Error> {
    let (res_meta, doc_opt, _meta) = resolver
        .resolve(did, &ResolutionInputMetadata::default())
        .await;
    if let Some(err) = res_meta.error {
        return Err(Error::UnableToResolve(err));
    }
    let doc = doc_opt
        .ok_or_else(|| Error::UnableToResolve(format!("Missing document for DID: {did}")))?;
    Ok(doc)
}

/// Get the resolved verification method maps for a given DID (including its controllers,
/// recursively) and verification relationship (proof purpose).
///
/// This is a special case of [get_verification_methods_for_all].
pub async fn get_verification_methods(
    did: &str,
    verification_relationship: VerificationRelationship,
    resolver: &dyn DIDResolver,
) -> Result<HashMap<String, VerificationMethodMap>, Error> {
    get_verification_methods_for_all(&[did], verification_relationship, resolver).await
}

/// Get the resolved verification method maps for the given DIDs (including their controllers,
/// recursively) and verification relationship (proof purpose).
pub async fn get_verification_methods_for_all(
    dids: &[&str],
    verification_relationship: VerificationRelationship,
    resolver: &dyn DIDResolver,
) -> Result<HashMap<String, VerificationMethodMap>, Error> {
    // Resolve DIDs, recursing through DID controllers.
    let mut did_docs: HashMap<String, Document> = HashMap::new();
    let mut dids_to_resolve = dids
        .iter()
        .copied()
        .map(|x| x.to_owned())
        .collect::<Vec<String>>(); //vec![did.to_string()];
    while let Some(did) = dids_to_resolve.pop() {
        if !did_docs.contains_key(&did) {
            let doc = easy_resolve(&did, resolver).await?;
            for controller in doc.controller.iter().flatten() {
                dids_to_resolve.push(controller.clone());
            }
            if did_docs.len() > MAX_CONTROLLERS {
                return Err(Error::ControllerLimit);
            }
            did_docs.insert(did, doc);
        }
    }
    let mut vm_ids_for_purpose = HashSet::new();
    let mut vmms_by_id: HashMap<String, VerificationMethodMap> = HashMap::new();
    for (_did, doc) in did_docs {
        // Find verification method ids for this proof purpose.
        let vm_ids = doc
            .get_verification_method_ids(verification_relationship.clone())
            .map_err(|e| {
                Error::UnableToResolve(format!("Unable to get verification method ids: {e:?}"))
            })?;
        for id in vm_ids {
            vm_ids_for_purpose.insert(id); // only insert here
        }
        // Find all verification method maps defined in the resolved DID document.
        for vm in doc
            .verification_method
            .into_iter()
            .chain(doc.public_key.into_iter())
            .chain(doc.authentication.into_iter())
            .chain(doc.assertion_method.into_iter())
            .chain(doc.key_agreement.into_iter())
            .chain(doc.capability_invocation.into_iter())
            .chain(doc.capability_delegation.into_iter())
            .flatten()
        {
            if let VerificationMethod::Map(mut vmm) = vm {
                let vm_id = vmm.get_id(&doc.id);
                crate::merge_context(&mut vmm.context, &doc.context);
                vmms_by_id.insert(vm_id, vmm);
            }
        }
    }

    let mut vmms = HashMap::new();

    for id in vm_ids_for_purpose {
        let vmm = if let Some(vmm) = vmms_by_id.remove(&id) {
            vmm
        } else {
            resolve_vm(&id, resolver).await?
        };
        vmms.insert(id, vmm);
    }
    // TODO: verify VM controller properties.
    Ok(vmms)
}

/// Resolve a verificationMethod to a key
pub async fn resolve_key(
    verification_method: &str,
    resolver: &dyn DIDResolver,
) -> Result<JWK, Error> {
    let vmm = resolve_vm(verification_method, resolver).await?;
    let jwk = vmm.get_jwk()?;
    Ok(jwk)
}

/// Resolve a verificationMethod
pub async fn resolve_vm(
    verification_method: &str,
    resolver: &dyn DIDResolver,
) -> Result<VerificationMethodMap, Error> {
    let (res_meta, object, _meta) = dereference(
        resolver,
        verification_method,
        &DereferencingInputMetadata::default(),
    )
    .await;
    if let Some(error) = res_meta.error {
        return Err(Error::DIDURLDereference(error));
    }
    // ah, found the expectedobject, also could've just searched the code base for this error
    let vm = match object {
        Content::Object(Resource::VerificationMethod(vm)) => vm,
        Content::Null => return Err(Error::ResourceNotFound(verification_method.to_string())),
        _ => return Err(Error::ExpectedObject),
    };
    Ok(vm)
}

#[cfg(test)]
mod tests {
    #[cfg(feature = "http")]
    use hyper::{Body, Response, Server};
    // use std::future::Future;

    use super::*;

    struct ExampleResolver {}

    const EXAMPLE_123_ID: &str = "did:example:123";
    const EXAMPLE_123_JSON: &str = r#"{
        "@context": "https://www.w3.org/ns/did/v1",
        "id": "did:example:123",
        "authentication": [
            {
                "id": "did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:example:123",
                "publicKeyBase58": "AKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf"
            }
        ],
        "capabilityInvocation": [
            {
                "id": "did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:example:123",
                "publicKeyBase58": "4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN"
            }
        ],
        "capabilityDelegation": [
            {
                "id": "did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:example:123",
                "publicKeyBase58": "Hgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL"
            }
        ],
        "assertionMethod": [
            {
                "id": "did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY",
                "type": "Ed25519VerificationKey2018",
                "controller": "did:example:123",
                "publicKeyBase58": "5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA"
            }
        ]
    }"#;
    #[cfg(feature = "http")]
    const DID_KEY_ID: &str = "did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6";
    #[cfg(feature = "http")]
    const DID_KEY_JSON: &str = include_str!("../../tests/did-key-uniresolver-resp.json");

    #[async_trait]
    impl DIDResolver for ExampleResolver {
        async fn resolve(
            &self,
            did: &str,
            _input_metadata: &ResolutionInputMetadata,
        ) -> (
            ResolutionMetadata,
            Option<Document>,
            Option<DocumentMetadata>,
        ) {
            if did == EXAMPLE_123_ID {
                let doc = match Document::from_json(EXAMPLE_123_JSON) {
                    Ok(doc) => doc,
                    Err(err) => {
                        return (
                            ResolutionMetadata {
                                // https://github.com/w3c/did-core/issues/402
                                error: Some("JSON Error: ".to_string() + &err.to_string()),
                                content_type: None,
                                property_set: None,
                            },
                            None,
                            None,
                        );
                    }
                };
                (
                    ResolutionMetadata {
                        content_type: Some(TYPE_DID_LD_JSON.to_string()),
                        ..Default::default()
                    },
                    Some(doc),
                    Some(DocumentMetadata::default()),
                )
            } else {
                (
                    ResolutionMetadata {
                        error: Some(ERROR_NOT_FOUND.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    None,
                    None,
                )
            }
        }

        async fn resolve_representation(
            &self,
            did: &str,
            _input_metadata: &ResolutionInputMetadata,
        ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
            if did == EXAMPLE_123_ID {
                let vec = EXAMPLE_123_JSON.as_bytes().to_vec();
                (
                    ResolutionMetadata {
                        error: None,
                        content_type: Some(TYPE_DID_LD_JSON.to_string()),
                        property_set: None,
                    },
                    vec,
                    Some(DocumentMetadata::default()),
                )
            } else {
                (
                    ResolutionMetadata {
                        error: Some(ERROR_NOT_FOUND.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    Vec::new(),
                    None,
                )
            }
        }
    }

    #[async_std::test]
    async fn resolve() {
        let resolver = ExampleResolver {};
        let (res_meta, doc, doc_meta) = resolver
            .resolve(EXAMPLE_123_ID, &ResolutionInputMetadata::default())
            .await;
        assert_eq!(res_meta.error, None);
        assert!(doc_meta.is_some());
        let doc = doc.unwrap();
        assert_eq!(doc.id, EXAMPLE_123_ID);
    }

    #[async_std::test]
    async fn resolve_representation() {
        let resolver = ExampleResolver {};
        let (res_meta, doc_representation, doc_meta) = resolver
            .resolve_representation(EXAMPLE_123_ID, &ResolutionInputMetadata::default())
            .await;
        assert_eq!(res_meta.error, None);
        assert!(doc_meta.is_some());
        assert_eq!(doc_representation, EXAMPLE_123_JSON.as_bytes());
    }

    #[cfg(feature = "http")]
    fn did_resolver_server() -> Result<(String, impl FnOnce() -> Result<(), ()>), hyper::Error> {
        // @TODO:
        // - handle errors instead of using unwrap
        // - handle `accept` input metadata property
        use hyper::service::{make_service_fn, service_fn};
        let addr = ([127, 0, 0, 1], 0).into();
        let make_svc = make_service_fn(|_| async {
            Ok::<_, hyper::Error>(service_fn(|req| async move {
                let uri = req.uri();
                // skip root "/" to get DID
                let id: String = uri.path().chars().skip(1).collect();
                let res_input_meta: ResolutionInputMetadata =
                    serde_urlencoded::from_str(uri.query().unwrap_or("")).unwrap();

                // fixture response from universal-resolver
                if id == DID_KEY_ID {
                    let body = Body::from(DID_KEY_JSON);
                    let mut response = Response::new(body);
                    response
                        .headers_mut()
                        .insert(header::CONTENT_TYPE, TYPE_DID_RESOLUTION.parse().unwrap());
                    return Ok::<_, hyper::Error>(response);
                }

                // wrap ExampleResolver in a local HTTP server
                let resolver = ExampleResolver {};
                let (res_meta, doc_opt, doc_meta_opt) =
                    resolver.resolve(&id, &res_input_meta).await;
                let (mut parts, _) = Response::<Body>::default().into_parts();
                if res_meta.error == Some(ERROR_NOT_FOUND.to_string()) {
                    parts.status = StatusCode::NOT_FOUND;
                }
                parts
                    .headers
                    .insert(header::CONTENT_TYPE, TYPE_DID_RESOLUTION.parse().unwrap());
                let result = ResolutionResult {
                    did_document: doc_opt,
                    did_resolution_metadata: Some(res_meta),
                    did_document_metadata: doc_meta_opt,
                    ..Default::default()
                };
                let body = Body::from(serde_json::to_vec_pretty(&result).unwrap());
                Ok::<_, hyper::Error>(Response::from_parts(parts, body))
            }))
        });
        let server = Server::try_bind(&addr)?.serve(make_svc);
        let url = "http://".to_string() + &server.local_addr().to_string() + "/";
        let (shutdown_tx, shutdown_rx) = futures::channel::oneshot::channel();
        let graceful = server.with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        });
        tokio::task::spawn(async move {
            graceful.await.ok();
        });
        let shutdown = || shutdown_tx.send(());
        Ok((url, shutdown))
    }

    #[tokio::test]
    #[cfg(feature = "http")]
    async fn http_resolve_representation() {
        use serde_json::Value;
        let (endpoint, shutdown) = did_resolver_server().unwrap();
        let resolver = HTTPDIDResolver { endpoint };
        let (res_meta, doc_representation, doc_meta) = resolver
            .resolve_representation(EXAMPLE_123_ID, &ResolutionInputMetadata::default())
            .await;
        assert_eq!(res_meta.error, None);
        assert!(doc_meta.is_some());
        let doc: Value = serde_json::from_slice(&doc_representation).unwrap();
        let doc_expected: Value = serde_json::from_str(EXAMPLE_123_JSON).unwrap();
        assert_eq!(doc, doc_expected);
        shutdown().ok();
    }

    #[tokio::test]
    #[cfg(feature = "http")]
    async fn http_resolve() {
        let (endpoint, shutdown) = did_resolver_server().unwrap();
        let resolver = HTTPDIDResolver { endpoint };
        let (res_meta, doc, doc_meta) = resolver
            .resolve(EXAMPLE_123_ID, &ResolutionInputMetadata::default())
            .await;
        assert_eq!(res_meta.error, None);
        assert!(doc_meta.is_some());
        let doc = doc.unwrap();
        assert_eq!(doc.id, EXAMPLE_123_ID);
        shutdown().ok();
    }

    #[tokio::test]
    #[cfg(feature = "http")]
    async fn resolve_uniresolver_fixture() {
        let id = DID_KEY_ID;
        let (endpoint, shutdown) = did_resolver_server().unwrap();
        let resolver = HTTPDIDResolver { endpoint };
        let (res_meta, doc, doc_meta) = resolver
            .resolve(id, &ResolutionInputMetadata::default())
            .await;
        eprintln!("res_meta = {:?}", &res_meta);
        eprintln!("doc_meta = {:?}", &doc_meta);
        eprintln!("doc = {:?}", &doc);
        assert_eq!(res_meta.error, None);
        let doc = doc.unwrap();
        assert_eq!(doc.id, id);
        shutdown().ok();
    }

    #[test]
    fn service_endpoint_construction() {
        use std::str::FromStr;
        // https://w3c-ccg.github.io/did-resolution/#example-11
        let input_service_endpoint_url = "https://example.com/messages/8377464";
        // TODO: https://github.com/w3c-ccg/did-resolution/issues/61
        let input_did_url = DIDURL::from_str("did:example:123456789abcdefghi?service=messages&relative-ref=%2Fsome%2Fpath%3Fquery#frag").unwrap();
        let expected_output_service_endpoint_url =
            "https://example.com/messages/8377464/some/path?query#frag";
        let input_did_parameters: DIDParameters =
            serde_urlencoded::from_str(input_did_url.query.as_ref().unwrap()).unwrap();
        let output_service_endpoint_url = construct_service_endpoint(
            &input_did_url,
            &input_did_parameters,
            input_service_endpoint_url,
        )
        .unwrap();
        assert_eq!(
            output_service_endpoint_url,
            expected_output_service_endpoint_url
        );
    }

    // https://w3c-ccg.github.io/did-resolution/#examples
    #[async_std::test]
    async fn dereference_did_url() {
        const DID: &str = "did:example:123456789abcdefghi";
        // https://w3c-ccg.github.io/did-resolution/#example-7
        const DOC_STR: &str = r###"
{
	"@context": "https://www.w3.org/ns/did/v1",
	"id": "did:example:123456789abcdefghi",
	"verificationMethod": [{
		"id": "did:example:123456789abcdefghi#keys-1",
		"type": "Ed25519VerificationKey2018",
		"controller": "did:example:123456789abcdefghi",
		"publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
	}, {
		"id": "#keys-2",
		"type": "Ed25519VerificationKey2018",
		"controller": "did:example:123456789abcdefghi",
		"publicKeyBase58": "4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN"
	}],
	"service": [{
		"id": "did:example:123456789abcdefghi#agent",
		"type": "AgentService",
		"serviceEndpoint": "https://agent.example.com/8377464"
	}, {
		"id": "did:example:123456789abcdefghi#messages",
		"type": "MessagingService",
		"serviceEndpoint": "https://example.com/messages/8377464"
	}]
}
        "###;
        struct DerefExampleResolver;
        #[async_trait]
        impl DIDResolver for DerefExampleResolver {
            async fn resolve(
                &self,
                did: &str,
                _input_metadata: &ResolutionInputMetadata,
            ) -> (
                ResolutionMetadata,
                Option<Document>,
                Option<DocumentMetadata>,
            ) {
                if did != DID {
                    panic!("Unexpected DID: {}", did);
                }
                let doc = Document::from_json(DOC_STR).unwrap();
                (
                    ResolutionMetadata {
                        content_type: Some(TYPE_DID_LD_JSON.to_string()),
                        ..Default::default()
                    },
                    Some(doc),
                    Some(DocumentMetadata::default()),
                )
            }
        }

        // https://w3c-ccg.github.io/did-resolution/#example-6
        let did_url = "did:example:123456789abcdefghi#keys-1";
        // https://w3c-ccg.github.io/did-resolution/#example-8
        let expected_output_resource = r#"
{
	"@context": "https://www.w3.org/ns/did/v1",
	"id": "did:example:123456789abcdefghi#keys-1",
	"type": "Ed25519VerificationKey2018",
	"controller": "did:example:123456789abcdefghi",
	"publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
}
        "#;
        let vm: VerificationMethodMap = serde_json::from_str(expected_output_resource).unwrap();
        let expected_content = Content::Object(Resource::VerificationMethod(vm));
        let (deref_meta, content, content_meta) = dereference(
            &DerefExampleResolver,
            did_url,
            &DereferencingInputMetadata::default(),
        )
        .await;
        assert_eq!(deref_meta.error, None);
        assert_eq!(content, expected_content);
        eprintln!("dereferencing metadata: {:?}", deref_meta);
        eprintln!("content: {:?}", content);
        eprintln!("content metadata: {:?}", content_meta);

        // https://w3c-ccg.github.io/did-resolution/#example-9
        let did_url = "did:example:123456789abcdefghi?service=messages&relative-ref=%2Fsome%2Fpath%3Fquery#frag";
        // https://w3c-ccg.github.io/did-resolution/#example-10
        let expected_output_service_endpoint_url =
            "https://example.com/messages/8377464/some/path?query#frag";
        let expected_content = Content::URL(expected_output_service_endpoint_url.to_string());
        let (deref_meta, content, _content_meta) = dereference(
            &DerefExampleResolver,
            did_url,
            &DereferencingInputMetadata::default(),
        )
        .await;
        assert_eq!(deref_meta.error, None);
        assert_eq!(content, expected_content);

        // Dereference DID URL where id property is a relative IRI
        let (deref_meta, _content, _content_meta) = dereference(
            &DerefExampleResolver,
            "did:example:123456789abcdefghi#keys-2",
            &DereferencingInputMetadata::default(),
        )
        .await;
        assert_eq!(deref_meta.error, None);

        // Dereferencing unknown ID fails
        let (deref_meta, _content, _content_meta) = dereference(
            &DerefExampleResolver,
            "did:example:123456789abcdefghi#nope",
            &DereferencingInputMetadata::default(),
        )
        .await;
        assert_ne!(deref_meta.error, None);
    }
}
