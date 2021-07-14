use async_trait::async_trait;
use chrono::prelude::{DateTime, Utc};
#[cfg(feature = "http-did")]
use hyper::{header, Client, Request, StatusCode, Uri};
#[cfg(feature = "http-did")]
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_json::Value;
use serde_urlencoded;
use std::collections::{BTreeMap, HashMap};
use std::convert::TryFrom;

// https://w3c-ccg.github.io/did-resolution/
use crate::did::{DIDMethod, DIDParameters, Document, Resource, ServiceEndpoint, DIDURL};
use crate::error::Error;
use crate::jsonld::DID_RESOLUTION_V1_CONTEXT;
use crate::one_or_many::OneOrMany;

pub const TYPE_JSON: &str = "application/json";
pub const TYPE_LD_JSON: &str = "application/ld+json";
pub const TYPE_DID_JSON: &str = "application/did+json";
pub const TYPE_DID_LD_JSON: &str = "application/did+ld+json";
pub const TYPE_URL: &str = "text/url";
pub const ERROR_INVALID_DID: &str = "invalidDid";
pub const ERROR_INVALID_DID_URL: &str = "invalidDidUrl";
pub const ERROR_UNAUTHORIZED: &str = "unauthorized";
pub const ERROR_NOT_FOUND: &str = "notFound";
pub const ERROR_METHOD_NOT_SUPPORTED: &str = "methodNotSupported";
pub const ERROR_REPRESENTATION_NOT_SUPPORTED: &str = "representationNotSupported";
pub const TYPE_DID_RESOLUTION: &'static str =
    "application/ld+json;profile=\"https://w3id.org/did-resolution\";charset=utf-8";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Metadata {
    String(String),
    Map(HashMap<String, Metadata>),
    List(Vec<Metadata>),
    Boolean(bool),
    Null,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionInputMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_cache: Option<bool>,
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Metadata>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
/// <https://w3c.github.io/did-core/#did-resolution-metadata-properties>
pub struct ResolutionMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Metadata>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DocumentMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub updated: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deactivated: Option<bool>,
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Metadata>>,
}

/// <https://w3c.github.io/did-core/#did-url-dereferencing-metadata-properties>
/// <https://w3c-ccg.github.io/did-resolution/#dereferencing-input-metadata-properties>
#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
pub struct DereferencingInputMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accept: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub follow_redirect: Option<bool>,
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Metadata>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
#[serde(rename_all = "camelCase")]
/// <https://w3c.github.io/did-core/#did-url-dereferencing-metadata-properties>
pub struct DereferencingMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content_type: Option<String>,
    #[serde(flatten)]
    pub property_set: Option<HashMap<String, Metadata>>,
}

#[derive(Debug, Serialize, Clone, PartialEq)]
/// A resource returned by DID URL dereferencing
#[serde(untagged)]
pub enum Content {
    DIDDocument(Document),
    URL(String),
    Object(Resource),
    Data(Vec<u8>),
    Null,
}

impl Content {
    pub fn into_vec(self) -> Result<Vec<u8>, Error> {
        if let Content::Data(data) = self {
            Ok(data)
        } else {
            Ok(serde_json::to_vec(&self)?)
        }
    }
}

impl From<Error> for DereferencingMetadata {
    fn from(err: Error) -> Self {
        let mut metadata = DereferencingMetadata::default();
        metadata.error = Some(err.to_string());
        metadata
    }
}

// needed for:
// - https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary Step 2.1
//   Returning a resolved DID document for DID URL dereferencing
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
//   Producing DID resolution result after DID URL deferencing.
impl From<DereferencingMetadata> for ResolutionMetadata {
    fn from(deref_meta: DereferencingMetadata) -> Self {
        Self {
            error: deref_meta.error,
            content_type: deref_meta.content_type,
            property_set: deref_meta.property_set,
        }
    }
}

impl DereferencingMetadata {
    pub fn from_error(err: &str) -> Self {
        let mut metadata = DereferencingMetadata::default();
        metadata.error = Some(err.to_owned());
        metadata
    }
}

impl ResolutionMetadata {
    pub fn from_error(err: &str) -> Self {
        let mut metadata = Self::default();
        metadata.error = Some(err.to_owned());
        metadata
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum ContentMetadata {
    DIDDocument(DocumentMetadata),
    Other(HashMap<String, Metadata>),
}

impl Default for ContentMetadata {
    fn default() -> Self {
        ContentMetadata::Other(HashMap::new())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
/// <https://w3c-ccg.github.io/did-resolution/#did-resolution-result>
pub struct ResolutionResult {
    #[serde(rename = "@context")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document: Option<Document>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_resolution_metadata: Option<ResolutionMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub did_document_metadata: Option<DocumentMetadata>,
    #[serde(flatten)]
    pub property_set: Option<BTreeMap<String, Value>>,
}

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

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
pub trait DIDResolver: Sync {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    );

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
    /// DID methods implement this function to support dereferencing DID URLs with paths and query strings.
    /// Callers should use [`dereference`] instead of this function.
    ///
    /// <https://w3c-ccg.github.io/did-resolution/#dereferencing>
    async fn dereference(
        &self,
        _did_url: &DIDURL,
        _did_url_dereferencing_input_metadata: &DereferencingInputMetadata,
    ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
        None
    }

    /// Cast the resolver as a [`DIDMethod`], if possible.
    fn to_did_method(&self) -> Option<&dyn DIDMethod> {
        None
    }
}

/// Dereference a DID URL
///
/// <https://w3c.github.io/did-core/#did-url-dereferencing>
/// <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm>
pub async fn dereference(
    resolver: &dyn DIDResolver,
    did_url_str: &str,
    did_url_dereferencing_input_metadata: &DereferencingInputMetadata,
) -> (DereferencingMetadata, Content, ContentMetadata) {
    let mut did_url = match DIDURL::try_from(did_url_str.to_string()) {
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
            DereferencingMetadata::from_error(&error),
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
    let fragment = did_url.fragment.take();
    let (deref_meta, content, content_meta) = dereference_primary_resource(
        resolver,
        &did_url,
        &did_url_dereferencing_input_metadata,
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
            did_url,
            fragment,
            &did_url_dereferencing_input_metadata,
            deref_meta,
            content,
            content_meta,
        )
        .await;
    }
    (deref_meta, content, content_meta)
}

/// <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-primary>
async fn dereference_primary_resource(
    resolver: &dyn DIDResolver,
    did_url: &DIDURL,
    did_url_dereferencing_input_metadata: &DereferencingInputMetadata,
    res_meta: &ResolutionMetadata,
    did_doc: Document,
    _did_doc_meta: &DocumentMetadata,
) -> (DereferencingMetadata, Content, ContentMetadata) {
    let parameters: DIDParameters = match did_url.query {
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
        let service = match did_doc.select_service(&service) {
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
        let output_service_endpoint_url =
            match construct_service_endpoint(did_url, &parameters, &input_service_endpoint_url) {
                Ok(url) => url,
                Err(err) => {
                    return (
                        DereferencingMetadata::from_error(&format!(
                            "Unable to construct service endpoint: {}",
                            err
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
    if did_url.path_abempty.is_empty() && did_url.query.is_none() {
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
    if !did_url.path_abempty.is_empty() || did_url.query.is_some() {
        // 3.1
        if let Some(result) = resolver
            .dereference(did_url, did_url_dereferencing_input_metadata)
            .await
        {
            return result;
        }
        // 3.2
        // TODO: enable the client to dereference the DID URL
    }
    // 4
    let null_result = (
        DereferencingMetadata::default(),
        Content::Null,
        ContentMetadata::default(),
    );
    // 4.1
    null_result
}

/// <https://w3c-ccg.github.io/did-resolution/#dereferencing-algorithm-secondary>
async fn dereference_secondary_resource(
    _resolver: &dyn DIDResolver,
    mut did_url: DIDURL,
    fragment: String,
    _did_url_dereferencing_input_metadata: &DereferencingInputMetadata,
    deref_meta: DereferencingMetadata,
    content: Content,
    content_meta: ContentMetadata,
) -> (DereferencingMetadata, Content, ContentMetadata) {
    let content_type = deref_meta.content_type.as_ref().map(String::as_str);
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
            did_url.fragment.replace(fragment);
            // 1.1
            let object = match doc.select_object(&did_url) {
                Ok(object) => object,
                Err(error) => {
                    return (
                        DereferencingMetadata::from_error(&format!(
                            "Unable to find object in DID document: {}",
                            error
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
            url.push('#');
            url.push_str(&fragment);
            return (deref_meta, Content::URL(url), content_meta);
        }
        _ => {}
    }
    // 3
    match content_type {
        None => (
            DereferencingMetadata::from_error(&format!("Resource missing content type")),
            Content::Null,
            ContentMetadata::default(),
        ),
        Some(content_type) => (
            DereferencingMetadata::from_error(&format!(
                "Unsupported content type: {}",
                content_type
            )),
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
        return Err(format!(
            "DID URL and input service endpoint URL MUST NOT both have a fragment component"
        ));
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
            return Err(format!(
                "DID URL and relativeRef MUST NOT both have a path component"
            ));
        }
        did_url_query = parts.next().map(|q| q.to_owned());
    } else {
        did_url_path = did_url.path_abempty.to_owned();
        did_url_query = did_url.query.to_owned();
        // TODO: do something with the DID URL query that is being ignored in favor of the
        // relativeRef query
    }
    if did_url_query.is_some() && input_service_endpoint_query.is_some() {
        return Err(format!(
            "DID URL and input service endpoint URL MUST NOT both have a query component"
        ));
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
        output_url.push_str(&fragment);
    }
    Ok(output_url)
}

#[cfg(feature = "http")]
#[derive(Debug, Clone, Default)]
pub struct HTTPDIDResolver {
    pub endpoint: String,
}

#[cfg(feature = "http")]
impl HTTPDIDResolver {
    pub fn new(url: &str) -> Self {
        Self {
            endpoint: url.to_string(),
        }
    }
}

#[cfg(feature = "http")]
#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for HTTPDIDResolver {
    // https://w3c-ccg.github.io/did-resolution/#bindings-https
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
            percent_encoding::utf8_percent_encode(&did, percent_encoding::CONTROLS).to_string();
        let mut url = self.endpoint.clone() + &did_urlencoded;
        if !querystring.is_empty() {
            url.push('?');
            url.push_str(&querystring);
        }
        let uri: Uri = match url.parse() {
            Ok(uri) => uri,
            Err(_) => {
                return (
                    ResolutionMetadata {
                        error: Some(ERROR_INVALID_DID.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    None,
                    None,
                )
            }
        };
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);
        let request = match Request::get(uri)
            .header("Accept", TYPE_DID_RESOLUTION)
            .header("User-Agent", crate::USER_AGENT)
            .body(hyper::Body::default())
        {
            Ok(req) => req,
            Err(err) => {
                return (
                    ResolutionMetadata {
                        error: Some("Error building HTTP request: ".to_string() + &err.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    None,
                    None,
                )
            }
        };
        let mut resp = match client.request(request).await {
            Ok(resp) => resp,
            Err(err) => {
                return (
                    ResolutionMetadata {
                        error: Some("HTTP Error: ".to_string() + &err.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    None,
                    None,
                )
            }
        };
        let res_result_representation = match hyper::body::to_bytes(resp.body_mut()).await {
            Ok(vec) => vec,
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
        let content_type = match resp.headers().get(header::CONTENT_TYPE) {
            None => None,
            Some(content_type) => Some(String::from(match content_type.to_str() {
                Ok(content_type) => content_type,
                Err(err) => {
                    return (
                        ResolutionMetadata::from_error(&format!(
                            "Error reading HTTP header: {}",
                            err
                        )),
                        None,
                        None,
                    )
                }
            })),
        }
        .unwrap_or_else(|| "".to_string());
        let mut res_meta = ResolutionMetadata::default();
        let doc_opt;
        let doc_meta_opt;
        match &content_type[..] {
            TYPE_DID_RESOLUTION => {
                let result: ResolutionResult =
                    match serde_json::from_slice(&res_result_representation) {
                        Ok(result) => result,
                        Err(err) => {
                            return (
                                ResolutionMetadata::from_error(&format!(
                                    "Error parsing resolution result: {}",
                                    err
                                )),
                                None,
                                None,
                            )
                        }
                    };
                if let Some(meta) = result.did_resolution_metadata {
                    res_meta = meta;
                    // https://www.w3.org/TR/did-core/#did-resolution-metadata
                    // contentType - "MUST NOT be present if the resolve function was called"
                    res_meta.content_type = None;
                };
                doc_opt = result.did_document;
                doc_meta_opt = result.did_document_metadata;
            }
            _ => {
                if resp.status() == StatusCode::NOT_FOUND {
                    res_meta.error = Some(ERROR_NOT_FOUND.to_string());
                    doc_opt = None;
                } else {
                    // Assume the response is a JSON-LD DID Document by default.
                    let doc: Document = match serde_json::from_slice(&res_result_representation) {
                        Ok(doc) => doc,
                        Err(err) => {
                            return (
                                ResolutionMetadata::from_error(&format!(
                                    "Error parsing DID document: {}",
                                    err
                                )),
                                None,
                                None,
                            )
                        }
                    };
                    doc_opt = Some(doc);
                }
                doc_meta_opt = None;
            }
        }
        (res_meta, doc_opt, doc_meta_opt)
    }

    // Use default resolveRepresentation implementation in terms of resolve,
    // until resolveRepresentation has its own HTTP(S) binding:
    // https://github.com/w3c-ccg/did-resolution/issues/57

    async fn dereference(
        &self,
        did_url: &DIDURL,
        input_metadata: &DereferencingInputMetadata,
    ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
        let querystring = match serde_urlencoded::to_string(input_metadata) {
            Ok(qs) => qs,
            Err(err) => {
                return Some((
                    DereferencingMetadata::from_error(&format!(
                        "Unable to serialize input metadata into query string: {}",
                        err
                    )),
                    Content::Null,
                    ContentMetadata::default(),
                ))
            }
        };
        let did_url_urlencoded =
            percent_encoding::utf8_percent_encode(&did_url.to_string(), percent_encoding::CONTROLS)
                .to_string();
        let mut url = self.endpoint.clone() + &did_url_urlencoded;
        if !querystring.is_empty() {
            url.push('?');
            url.push_str(&querystring);
        }
        let uri: Uri = match url.parse() {
            Ok(uri) => uri,
            Err(_) => {
                return Some((
                    DereferencingMetadata::from_error(ERROR_INVALID_DID),
                    Content::Null,
                    ContentMetadata::default(),
                ))
            }
        };
        let https = HttpsConnector::new();
        let client = Client::builder().build::<_, hyper::Body>(https);
        let request = match Request::get(uri)
            .header("Accept", TYPE_DID_RESOLUTION)
            .body(hyper::Body::default())
        {
            Ok(req) => req,
            Err(err) => {
                return Some((
                    DereferencingMetadata::from_error(&format!(
                        "Error building HTTP request: {}",
                        err
                    )),
                    Content::Null,
                    ContentMetadata::default(),
                ))
            }
        };
        let mut resp = match client.request(request).await {
            Ok(resp) => resp,
            Err(err) => {
                return Some((
                    DereferencingMetadata::from_error(&format!("HTTP Error: {}", err)),
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
        let deref_result_bytes = match hyper::body::to_bytes(resp.body_mut()).await {
            Ok(vec) => vec,
            Err(err) => {
                return Some((
                    DereferencingMetadata::from_error(&format!(
                        "Error reading HTTP response: {}",
                        err
                    )),
                    Content::Null,
                    ContentMetadata::default(),
                ))
            }
        };
        let content_type = match resp.headers().get(header::CONTENT_TYPE) {
            None => None,
            Some(content_type) => Some(String::from(match content_type.to_str() {
                Ok(content_type) => content_type,
                Err(err) => {
                    return Some((
                        DereferencingMetadata::from_error(&format!(
                            "Error reading HTTP header: {}",
                            err
                        )),
                        Content::Null,
                        ContentMetadata::default(),
                    ))
                }
            })),
        }
        .unwrap_or_else(|| "".to_string());
        match &content_type[..] {
            TYPE_DID_LD_JSON | TYPE_DID_JSON => {
                let doc: Document = match serde_json::from_slice(&deref_result_bytes) {
                    Ok(result) => result,
                    Err(err) => {
                        return Some((
                            DereferencingMetadata::from_error(&format!(
                                "Error parsing DID document: {}",
                                err
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
                                "Error parsing DID resolution result: {}",
                                err
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
                                    "Error parsing JSON: {}",
                                    err
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

/// Compose multiple DID resolvers in series. They are tried in series until one supports the
/// requested DID method.
#[derive(Clone, Default)]
pub struct SeriesResolver<'a> {
    pub resolvers: Vec<&'a (dyn DIDResolver)>,
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl<'a> DIDResolver for SeriesResolver<'a> {
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

    async fn dereference(
        &self,
        did_url: &DIDURL,
        input_metadata: &DereferencingInputMetadata,
    ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
        for resolver in &self.resolvers {
            if let Some((deref_meta, content, content_meta)) =
                resolver.dereference(did_url, input_metadata).await
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

#[cfg(test)]
mod tests {
    #[cfg(feature = "http-did")]
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
    #[cfg(feature = "http-did")]
    const DID_KEY_ID: &'static str = "did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6";
    #[cfg(feature = "http-did")]
    const DID_KEY_JSON: &'static str = include_str!("../tests/did-key-uniresolver-resp.json");

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

    #[cfg(feature = "http-did")]
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
    #[cfg(feature = "http-did")]
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
        let doc_expected: Value = serde_json::from_str(&EXAMPLE_123_JSON).unwrap();
        assert_eq!(doc, doc_expected);
        shutdown().ok();
    }

    #[tokio::test]
    #[cfg(feature = "http-did")]
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
    #[cfg(feature = "http-did")]
    async fn resolve_uniresolver_fixture() {
        let id = DID_KEY_ID;
        let (endpoint, shutdown) = did_resolver_server().unwrap();
        let resolver = HTTPDIDResolver { endpoint };
        let (res_meta, doc, doc_meta) = resolver
            .resolve(&id, &ResolutionInputMetadata::default())
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
        use crate::did::VerificationMethodMap;
        let vm: VerificationMethodMap = serde_json::from_str(&expected_output_resource).unwrap();
        let expected_content = Content::Object(Resource::VerificationMethod(vm));
        let (deref_meta, content, content_meta) = dereference(
            &DerefExampleResolver,
            did_url,
            &DereferencingInputMetadata::default(),
        )
        .await;
        assert_eq!(deref_meta.error, None);
        assert_eq!(content, expected_content);
        eprintln!("deferencing metadata: {:?}", deref_meta);
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
