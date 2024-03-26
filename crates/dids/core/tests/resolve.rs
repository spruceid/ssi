// #[cfg(test)]
// mod tests {
//     #[cfg(feature = "http")]
//     use hyper::{Body, Response, Server};
//     // use std::future::Future;

//     use super::*;

//     struct ExampleResolver {}

//     const EXAMPLE_123_ID: &str = "did:example:123";
//     const EXAMPLE_123_JSON: &str = r#"{
//         "@context": "https://www.w3.org/ns/did/v1",
//         "id": "did:example:123",
//         "authentication": [
//             {
//                 "id": "did:example:123#z6MkecaLyHuYWkayBDLw5ihndj3T1m6zKTGqau3A51G7RBf3",
//                 "type": "Ed25519VerificationKey2018",
//                 "controller": "did:example:123",
//                 "publicKeyBase58": "AKJP3f7BD6W4iWEQ9jwndVTCBq8ua2Utt8EEjJ6Vxsf"
//             }
//         ],
//         "capabilityInvocation": [
//             {
//                 "id": "did:example:123#z6MkhdmzFu659ZJ4XKj31vtEDmjvsi5yDZG5L7Caz63oP39k",
//                 "type": "Ed25519VerificationKey2018",
//                 "controller": "did:example:123",
//                 "publicKeyBase58": "4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN"
//             }
//         ],
//         "capabilityDelegation": [
//             {
//                 "id": "did:example:123#z6Mkw94ByR26zMSkNdCUi6FNRsWnc2DFEeDXyBGJ5KTzSWyi",
//                 "type": "Ed25519VerificationKey2018",
//                 "controller": "did:example:123",
//                 "publicKeyBase58": "Hgo9PAmfeoxHG8Mn2XHXamxnnSwPpkyBHAMNF3VyXJCL"
//             }
//         ],
//         "assertionMethod": [
//             {
//                 "id": "did:example:123#z6MkiukuAuQAE8ozxvmahnQGzApvtW7KT5XXKfojjwbdEomY",
//                 "type": "Ed25519VerificationKey2018",
//                 "controller": "did:example:123",
//                 "publicKeyBase58": "5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA"
//             }
//         ]
//     }"#;
//     #[cfg(feature = "http")]
//     const DID_KEY_ID: &str = "did:key:z6Mkfriq1MqLBoPWecGoDLjguo1sB9brj6wT3qZ5BxkKpuP6";
//     #[cfg(feature = "http")]
//     const DID_KEY_JSON: &str = include_str!("../../tests/did-key-uniresolver-resp.json");

//     #[async_trait]
//     impl DIDResolver for ExampleResolver {
//         async fn resolve(
//             &self,
//             did: &str,
//             _input_metadata: &ResolutionInputMetadata,
//         ) -> (
//             ResolutionMetadata,
//             Option<Document>,
//             Option<DocumentMetadata>,
//         ) {
//             if did == EXAMPLE_123_ID {
//                 let doc = match Document::from_json(EXAMPLE_123_JSON) {
//                     Ok(doc) => doc,
//                     Err(err) => {
//                         return (
//                             ResolutionMetadata {
//                                 // https://github.com/w3c/did-core/issues/402
//                                 error: Some("JSON Error: ".to_string() + &err.to_string()),
//                                 content_type: None,
//                                 property_set: None,
//                             },
//                             None,
//                             None,
//                         );
//                     }
//                 };
//                 (
//                     ResolutionMetadata {
//                         content_type: Some(TYPE_DID_LD_JSON.to_string()),
//                         ..Default::default()
//                     },
//                     Some(doc),
//                     Some(DocumentMetadata::default()),
//                 )
//             } else {
//                 (
//                     ResolutionMetadata {
//                         error: Some(ERROR_NOT_FOUND.to_string()),
//                         content_type: None,
//                         property_set: None,
//                     },
//                     None,
//                     None,
//                 )
//             }
//         }

//         async fn resolve_representation(
//             &self,
//             did: &str,
//             _input_metadata: &ResolutionInputMetadata,
//         ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
//             if did == EXAMPLE_123_ID {
//                 let vec = EXAMPLE_123_JSON.as_bytes().to_vec();
//                 (
//                     ResolutionMetadata {
//                         error: None,
//                         content_type: Some(TYPE_DID_LD_JSON.to_string()),
//                         property_set: None,
//                     },
//                     vec,
//                     Some(DocumentMetadata::default()),
//                 )
//             } else {
//                 (
//                     ResolutionMetadata {
//                         error: Some(ERROR_NOT_FOUND.to_string()),
//                         content_type: None,
//                         property_set: None,
//                     },
//                     Vec::new(),
//                     None,
//                 )
//             }
//         }
//     }

//     #[async_std::test]
//     async fn resolve() {
//         let resolver = ExampleResolver {};
//         let (res_meta, doc, doc_meta) = resolver
//             .resolve(EXAMPLE_123_ID, &ResolutionInputMetadata::default())
//             .await;
//         assert_eq!(res_meta.error, None);
//         assert!(doc_meta.is_some());
//         let doc = doc.unwrap();
//         assert_eq!(doc.id, EXAMPLE_123_ID);
//     }

//     #[async_std::test]
//     async fn resolve_representation() {
//         let resolver = ExampleResolver {};
//         let (res_meta, doc_representation, doc_meta) = resolver
//             .resolve_representation(EXAMPLE_123_ID, &ResolutionInputMetadata::default())
//             .await;
//         assert_eq!(res_meta.error, None);
//         assert!(doc_meta.is_some());
//         assert_eq!(doc_representation, EXAMPLE_123_JSON.as_bytes());
//     }

//     #[cfg(feature = "http")]
//     fn did_resolver_server() -> Result<(String, impl FnOnce() -> Result<(), ()>), hyper::Error> {
//         // @TODO:
//         // - handle errors instead of using unwrap
//         // - handle `accept` input metadata property
//         use hyper::service::{make_service_fn, service_fn};
//         let addr = ([127, 0, 0, 1], 0).into();
//         let make_svc = make_service_fn(|_| async {
//             Ok::<_, hyper::Error>(service_fn(|req| async move {
//                 let uri = req.uri();
//                 // skip root "/" to get DID
//                 let id: String = uri.path().chars().skip(1).collect();
//                 let res_input_meta: ResolutionInputMetadata =
//                     serde_urlencoded::from_str(uri.query().unwrap_or("")).unwrap();

//                 // fixture response from universal-resolver
//                 if id == DID_KEY_ID {
//                     let body = Body::from(DID_KEY_JSON);
//                     let mut response = Response::new(body);
//                     response
//                         .headers_mut()
//                         .insert(header::CONTENT_TYPE, TYPE_DID_RESOLUTION.parse().unwrap());
//                     return Ok::<_, hyper::Error>(response);
//                 }

//                 // wrap ExampleResolver in a local HTTP server
//                 let resolver = ExampleResolver {};
//                 let (res_meta, doc_opt, doc_meta_opt) =
//                     resolver.resolve(&id, &res_input_meta).await;
//                 let (mut parts, _) = Response::<Body>::default().into_parts();
//                 if res_meta.error == Some(ERROR_NOT_FOUND.to_string()) {
//                     parts.status = StatusCode::NOT_FOUND;
//                 }
//                 parts
//                     .headers
//                     .insert(header::CONTENT_TYPE, TYPE_DID_RESOLUTION.parse().unwrap());
//                 let result = ResolutionResult {
//                     did_document: doc_opt,
//                     did_resolution_metadata: Some(res_meta),
//                     did_document_metadata: doc_meta_opt,
//                     ..Default::default()
//                 };
//                 let body = Body::from(serde_json::to_vec_pretty(&result).unwrap());
//                 Ok::<_, hyper::Error>(Response::from_parts(parts, body))
//             }))
//         });
//         let server = Server::try_bind(&addr)?.serve(make_svc);
//         let url = "http://".to_string() + &server.local_addr().to_string() + "/";
//         let (shutdown_tx, shutdown_rx) = futures::channel::oneshot::channel();
//         let graceful = server.with_graceful_shutdown(async {
//             shutdown_rx.await.ok();
//         });
//         tokio::task::spawn(async move {
//             graceful.await.ok();
//         });
//         let shutdown = || shutdown_tx.send(());
//         Ok((url, shutdown))
//     }

//     #[tokio::test]
//     #[cfg(feature = "http")]
//     async fn http_resolve_representation() {
//         use serde_json::Value;
//         let (endpoint, shutdown) = did_resolver_server().unwrap();
//         let resolver = HTTPDIDResolver { endpoint };
//         let (res_meta, doc_representation, doc_meta) = resolver
//             .resolve_representation(EXAMPLE_123_ID, &ResolutionInputMetadata::default())
//             .await;
//         assert_eq!(res_meta.error, None);
//         assert!(doc_meta.is_some());
//         let doc: Value = serde_json::from_slice(&doc_representation).unwrap();
//         let doc_expected: Value = serde_json::from_str(EXAMPLE_123_JSON).unwrap();
//         assert_eq!(doc, doc_expected);
//         shutdown().ok();
//     }

//     #[tokio::test]
//     #[cfg(feature = "http")]
//     async fn http_resolve() {
//         let (endpoint, shutdown) = did_resolver_server().unwrap();
//         let resolver = HTTPDIDResolver { endpoint };
//         let (res_meta, doc, doc_meta) = resolver
//             .resolve(EXAMPLE_123_ID, &ResolutionInputMetadata::default())
//             .await;
//         assert_eq!(res_meta.error, None);
//         assert!(doc_meta.is_some());
//         let doc = doc.unwrap();
//         assert_eq!(doc.id, EXAMPLE_123_ID);
//         shutdown().ok();
//     }

//     #[tokio::test]
//     #[cfg(feature = "http")]
//     async fn resolve_uniresolver_fixture() {
//         let id = DID_KEY_ID;
//         let (endpoint, shutdown) = did_resolver_server().unwrap();
//         let resolver = HTTPDIDResolver { endpoint };
//         let (res_meta, doc, doc_meta) = resolver
//             .resolve(id, &ResolutionInputMetadata::default())
//             .await;
//         eprintln!("res_meta = {:?}", &res_meta);
//         eprintln!("doc_meta = {:?}", &doc_meta);
//         eprintln!("doc = {:?}", &doc);
//         assert_eq!(res_meta.error, None);
//         let doc = doc.unwrap();
//         assert_eq!(doc.id, id);
//         shutdown().ok();
//     }

//     #[test]
//     fn service_endpoint_construction() {
//         use std::str::FromStr;
//         // https://w3c-ccg.github.io/did-resolution/#example-11
//         let input_service_endpoint_url = "https://example.com/messages/8377464";
//         // TODO: https://github.com/w3c-ccg/did-resolution/issues/61
//         let input_did_url = DIDURL::from_str("did:example:123456789abcdefghi?service=messages&relative-ref=%2Fsome%2Fpath%3Fquery#frag").unwrap();
//         let expected_output_service_endpoint_url =
//             "https://example.com/messages/8377464/some/path?query#frag";
//         let input_did_parameters: DIDParameters =
//             serde_urlencoded::from_str(input_did_url.query.as_ref().unwrap()).unwrap();
//         let output_service_endpoint_url = construct_service_endpoint(
//             &input_did_url,
//             &input_did_parameters,
//             input_service_endpoint_url,
//         )
//         .unwrap();
//         assert_eq!(
//             output_service_endpoint_url,
//             expected_output_service_endpoint_url
//         );
//     }

//     // https://w3c-ccg.github.io/did-resolution/#examples
//     #[async_std::test]
//     async fn dereference_did_url() {
//         const DID: &str = "did:example:123456789abcdefghi";
//         // https://w3c-ccg.github.io/did-resolution/#example-7
//         const DOC_STR: &str = r###"
// {
// 	"@context": "https://www.w3.org/ns/did/v1",
// 	"id": "did:example:123456789abcdefghi",
// 	"verificationMethod": [{
// 		"id": "did:example:123456789abcdefghi#keys-1",
// 		"type": "Ed25519VerificationKey2018",
// 		"controller": "did:example:123456789abcdefghi",
// 		"publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
// 	}, {
// 		"id": "#keys-2",
// 		"type": "Ed25519VerificationKey2018",
// 		"controller": "did:example:123456789abcdefghi",
// 		"publicKeyBase58": "4BWwfeqdp1obQptLLMvPNgBw48p7og1ie6Hf9p5nTpNN"
// 	}],
// 	"service": [{
// 		"id": "did:example:123456789abcdefghi#agent",
// 		"type": "AgentService",
// 		"serviceEndpoint": "https://agent.example.com/8377464"
// 	}, {
// 		"id": "did:example:123456789abcdefghi#messages",
// 		"type": "MessagingService",
// 		"serviceEndpoint": "https://example.com/messages/8377464"
// 	}]
// }
//         "###;
//         struct DerefExampleResolver;
//         #[async_trait]
//         impl DIDResolver for DerefExampleResolver {
//             async fn resolve(
//                 &self,
//                 did: &str,
//                 _input_metadata: &ResolutionInputMetadata,
//             ) -> (
//                 ResolutionMetadata,
//                 Option<Document>,
//                 Option<DocumentMetadata>,
//             ) {
//                 if did != DID {
//                     panic!("Unexpected DID: {}", did);
//                 }
//                 let doc = Document::from_json(DOC_STR).unwrap();
//                 (
//                     ResolutionMetadata {
//                         content_type: Some(TYPE_DID_LD_JSON.to_string()),
//                         ..Default::default()
//                     },
//                     Some(doc),
//                     Some(DocumentMetadata::default()),
//                 )
//             }
//         }

//         // https://w3c-ccg.github.io/did-resolution/#example-6
//         let did_url = "did:example:123456789abcdefghi#keys-1";
//         // https://w3c-ccg.github.io/did-resolution/#example-8
//         let expected_output_resource = r#"
// {
// 	"@context": "https://www.w3.org/ns/did/v1",
// 	"id": "did:example:123456789abcdefghi#keys-1",
// 	"type": "Ed25519VerificationKey2018",
// 	"controller": "did:example:123456789abcdefghi",
// 	"publicKeyBase58": "H3C2AVvLMv6gmMNam3uVAjZpfkcJCwDwnZn6z3wXmqPV"
// }
//         "#;
//         let vm: VerificationMethodMap = serde_json::from_str(expected_output_resource).unwrap();
//         let expected_content = Content::Object(Resource::VerificationMethod(vm));
//         let (deref_meta, content, content_meta) = dereference(
//             &DerefExampleResolver,
//             did_url,
//             &DereferencingInputMetadata::default(),
//         )
//         .await;
//         assert_eq!(deref_meta.error, None);
//         assert_eq!(content, expected_content);
//         eprintln!("dereferencing metadata: {:?}", deref_meta);
//         eprintln!("content: {:?}", content);
//         eprintln!("content metadata: {:?}", content_meta);

//         // https://w3c-ccg.github.io/did-resolution/#example-9
//         let did_url = "did:example:123456789abcdefghi?service=messages&relative-ref=%2Fsome%2Fpath%3Fquery#frag";
//         // https://w3c-ccg.github.io/did-resolution/#example-10
//         let expected_output_service_endpoint_url =
//             "https://example.com/messages/8377464/some/path?query#frag";
//         let expected_content = Content::URL(expected_output_service_endpoint_url.to_string());
//         let (deref_meta, content, _content_meta) = dereference(
//             &DerefExampleResolver,
//             did_url,
//             &DereferencingInputMetadata::default(),
//         )
//         .await;
//         assert_eq!(deref_meta.error, None);
//         assert_eq!(content, expected_content);

//         // Dereference DID URL where id property is a relative IRI
//         let (deref_meta, _content, _content_meta) = dereference(
//             &DerefExampleResolver,
//             "did:example:123456789abcdefghi#keys-2",
//             &DereferencingInputMetadata::default(),
//         )
//         .await;
//         assert_eq!(deref_meta.error, None);

//         // Dereferencing unknown ID fails
//         let (deref_meta, _content, _content_meta) = dereference(
//             &DerefExampleResolver,
//             "did:example:123456789abcdefghi#nope",
//             &DereferencingInputMetadata::default(),
//         )
//         .await;
//         assert_ne!(deref_meta.error, None);
//     }
// }
