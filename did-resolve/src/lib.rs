use async_trait::async_trait;
use bytes::Bytes;
use chrono::prelude::{DateTime, Utc};
use hyper::{header, Client, Request, StatusCode, Uri};
use hyper_tls::HttpsConnector;
use serde::{Deserialize, Serialize};
use serde_json;
use serde_urlencoded;
use std::collections::HashMap;
use tokio::stream::StreamExt;
use tokio::stream::{self, Stream};

// https://w3c-ccg.github.io/did-resolution/

use ssi::did::Document;

pub const TYPE_DID_LD_JSON: &str = "application/did+ld+json";
pub const ERROR_INVALID_DID: &str = "invalid-did";
pub const ERROR_UNAUTHORIZED: &str = "unauthorized";
pub const ERROR_NOT_FOUND: &str = "not-found";

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum Metadata {
    String(String),
    Map(HashMap<String, Metadata>),
    List(Vec<Metadata>),
    Boolean(bool),
    Null,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionInputMetadata {
    accept: Option<String>,
    #[serde(flatten)]
    property_set: Option<HashMap<String, Metadata>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "content-type")]
    content_type: Option<String>,
    #[serde(flatten)]
    property_set: Option<HashMap<String, Metadata>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct DocumentMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    created: Option<DateTime<Utc>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    updated: Option<DateTime<Utc>>,
    #[serde(flatten)]
    property_set: Option<HashMap<String, Metadata>>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename_all = "camelCase")]
pub struct ResolutionResult {
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "didDocument")]
    document: Option<Document>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "didResolutionMetadata")]
    resolution_metadata: Option<ResolutionMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "didDocumentMetadata")]
    document_metadata: Option<DocumentMetadata>,
    #[serde(flatten)]
    property_set: Option<HashMap<String, Metadata>>,
}

#[async_trait]
pub trait DIDResolver {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    );
    async fn resolve_stream(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Box<dyn Stream<Item = Result<Bytes, hyper::Error>> + Unpin + Send>,
        Option<DocumentMetadata>,
    );
}

pub struct HTTPDIDResolver {
    pub endpoint: String,
}

#[async_trait]
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
        let url = self.endpoint.clone() + &did_urlencoded + "?" + &querystring;
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
            .header("Accept", "application/json")
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
        let bytes = match resp
            .body_mut()
            .collect::<Result<Bytes, hyper::Error>>()
            .await
        {
            Ok(bytes) => bytes,
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
        let result: ResolutionResult = match serde_json::from_slice(&bytes) {
            Ok(result) => result,
            Err(err) => ResolutionResult {
                document: None,
                resolution_metadata: Some(ResolutionMetadata {
                    error: Some("JSON Error: ".to_string() + &err.to_string()),
                    content_type: None,
                    property_set: None,
                }),
                document_metadata: None,
                property_set: None,
            },
        };
        let mut res_meta = result.resolution_metadata.unwrap_or(ResolutionMetadata {
            error: None,
            content_type: None,
            property_set: None,
        });
        if resp.status() == StatusCode::NOT_FOUND {
            res_meta.error = Some(ERROR_NOT_FOUND.to_string());
        }
        if let Some(content_type) = resp.headers().get(header::CONTENT_TYPE) {
            res_meta.content_type = Some(String::from(match content_type.to_str() {
                Ok(content_type) => content_type,
                Err(err) => {
                    return (
                        ResolutionMetadata {
                            error: Some(
                                "Error reading HTTP header: ".to_string() + &err.to_string(),
                            ),
                            content_type: None,
                            property_set: None,
                        },
                        None,
                        None,
                    )
                }
            }));
        };
        (res_meta, result.document, result.document_metadata)
    }

    async fn resolve_stream(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Box<dyn Stream<Item = Result<Bytes, hyper::Error>> + Unpin + Send>,
        Option<DocumentMetadata>,
    ) {
        // Implement resolveStream in terms of resolve,
        // until resolveStream has its own HTTP(S) binding:
        // https://github.com/w3c-ccg/did-resolution/issues/57
        let (mut res_meta, doc, doc_meta) = self.resolve(did, input_metadata).await;
        let stream: Box<dyn Stream<Item = Result<Bytes, hyper::Error>> + Unpin + Send> = match doc {
            None => Box::new(stream::empty()),
            Some(doc) => match serde_json::to_vec_pretty(&doc) {
                Ok(bytes) => Box::new(stream::iter(vec![Ok(Bytes::from(bytes))])),
                Err(err) => {
                    res_meta.error =
                        Some("Error serializing JSON: ".to_string() + &err.to_string());
                    Box::new(stream::empty())
                }
            },
        };
        (res_meta, stream, doc_meta)
    }
}

#[cfg(test)]
mod tests {
    use hyper::{Body, Response, Server};
    // use std::future::Future;
    use serde_json::Value;
    use tokio::stream;

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
    const DID_KEY_ID: &'static str = "did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6";
    const DID_KEY_TYPE: &'static str =
        "application/ld+json;profile=\"https://w3id.org/did-resolution\";charset=utf-8";
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
                        error: None,
                        content_type: None,
                        property_set: None,
                    },
                    Some(doc),
                    Some(DocumentMetadata {
                        created: None,
                        updated: None,
                        property_set: None,
                    }),
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

        async fn resolve_stream(
            &self,
            did: &str,
            _input_metadata: &ResolutionInputMetadata,
        ) -> (
            ResolutionMetadata,
            Box<dyn Stream<Item = Result<Bytes, hyper::Error>> + Unpin + Send>,
            Option<DocumentMetadata>,
        ) {
            if did == EXAMPLE_123_ID {
                let bytes = Bytes::from_static(EXAMPLE_123_JSON.as_bytes());
                (
                    ResolutionMetadata {
                        error: None,
                        content_type: Some(TYPE_DID_LD_JSON.to_string()),
                        property_set: None,
                    },
                    Box::new(stream::iter(vec![Ok(bytes)])),
                    Some(DocumentMetadata {
                        created: None,
                        updated: None,
                        property_set: None,
                    }),
                )
            } else {
                (
                    ResolutionMetadata {
                        error: Some(ERROR_NOT_FOUND.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    Box::new(stream::empty()),
                    None,
                )
            }
        }
    }

    #[tokio::test]
    async fn resolve() {
        let resolver = ExampleResolver {};
        let (res_meta, doc, doc_meta) = resolver
            .resolve(
                EXAMPLE_123_ID,
                &ResolutionInputMetadata {
                    accept: None,
                    property_set: None,
                },
            )
            .await;
        assert_eq!(res_meta.error, None);
        assert!(doc_meta.is_some());
        let doc = doc.unwrap();
        assert_eq!(doc.id, EXAMPLE_123_ID);
    }

    #[tokio::test]
    async fn resolve_stream() {
        let resolver = ExampleResolver {};
        let (res_meta, stream, doc_meta) = resolver
            .resolve_stream(
                EXAMPLE_123_ID,
                &ResolutionInputMetadata {
                    accept: None,
                    property_set: None,
                },
            )
            .await;
        assert_eq!(res_meta.error, None);
        assert!(doc_meta.is_some());
        let bytes = stream
            .collect::<Result<Bytes, hyper::Error>>()
            .await
            .unwrap();
        assert_eq!(bytes, EXAMPLE_123_JSON);
    }

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
                        .insert(header::CONTENT_TYPE, DID_KEY_TYPE.parse().unwrap());
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
                if let Some(ref content_type) = res_meta.content_type {
                    parts
                        .headers
                        .insert(header::CONTENT_TYPE, content_type.parse().unwrap());
                }
                let result = ResolutionResult {
                    document: doc_opt,
                    resolution_metadata: Some(res_meta),
                    document_metadata: doc_meta_opt,
                    property_set: None,
                };
                let body = Body::from(serde_json::to_vec_pretty(&result).unwrap());
                Ok::<_, hyper::Error>(Response::from_parts(parts, body))
            }))
        });
        let server = Server::try_bind(&addr)?.serve(make_svc);
        let url = "http://".to_string() + &server.local_addr().to_string() + "/";
        let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
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
    async fn http_resolve_stream() {
        let (endpoint, shutdown) = did_resolver_server().unwrap();
        let resolver = HTTPDIDResolver { endpoint };
        let (res_meta, stream, doc_meta) = resolver
            .resolve_stream(
                EXAMPLE_123_ID,
                &ResolutionInputMetadata {
                    accept: None,
                    property_set: None,
                },
            )
            .await;
        assert_eq!(res_meta.error, None);
        assert!(doc_meta.is_some());
        let bytes = stream
            .collect::<Result<Bytes, hyper::Error>>()
            .await
            .unwrap();
        let doc: Value = serde_json::from_slice(&bytes).unwrap();
        let doc_expected: Value = serde_json::from_str(&EXAMPLE_123_JSON).unwrap();
        assert_eq!(doc, doc_expected);
        shutdown().ok();
    }

    #[tokio::test]
    async fn http_resolve() {
        let (endpoint, shutdown) = did_resolver_server().unwrap();
        let resolver = HTTPDIDResolver { endpoint };
        let (res_meta, doc, doc_meta) = resolver
            .resolve(
                EXAMPLE_123_ID,
                &ResolutionInputMetadata {
                    accept: None,
                    property_set: None,
                },
            )
            .await;
        assert_eq!(res_meta.error, None);
        assert!(doc_meta.is_some());
        let doc = doc.unwrap();
        assert_eq!(doc.id, EXAMPLE_123_ID);
        shutdown().ok();
    }

    #[tokio::test]
    async fn resolve_uniresolver_fixture() {
        let id = DID_KEY_ID;
        let (endpoint, shutdown) = did_resolver_server().unwrap();
        let resolver = HTTPDIDResolver { endpoint };
        let (res_meta, doc, doc_meta) = resolver
            .resolve(
                &id,
                &ResolutionInputMetadata {
                    accept: None,
                    property_set: None,
                },
            )
            .await;
        eprintln!("res_meta = {:?}", &res_meta);
        eprintln!("doc_meta = {:?}", &doc_meta);
        eprintln!("doc = {:?}", &doc);
        assert_eq!(res_meta.error, None);
        let doc = doc.unwrap();
        assert_eq!(doc.id, id);
        shutdown().ok();
    }
}
