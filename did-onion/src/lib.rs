use async_trait::async_trait;
use std::default::Default;

use ssi_dids::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    TYPE_DID_LD_JSON,
};
use ssi_dids::{DIDMethod, Document};
pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

const TOR_SOCKS_PORT: usize = 9050;

/// did:onion Method
///
/// [Specification](https://blockchaincommons.github.io/did-method-onion/)
#[non_exhaustive]
#[derive(Clone)]
pub struct DIDOnion {
    pub proxy_url: String,
}

impl DIDOnion {
    fn with_port(port: usize) -> Self {
        Self {
            proxy_url: format!("socks5h://127.0.0.1:{port}"),
        }
    }
}

impl Default for DIDOnion {
    fn default() -> Self {
        Self::with_port(TOR_SOCKS_PORT)
    }
}

fn did_onion_url(did: &str) -> Result<String, ResolutionMetadata> {
    let mut parts = did.split(':').peekable();
    let onion_address = match (parts.next(), parts.next(), parts.next()) {
        (Some("did"), Some("onion"), Some(domain_name)) => domain_name,
        _ => {
            return Err(ResolutionMetadata::from_error(ERROR_INVALID_DID));
        }
    };
    for c in onion_address.chars() {
        // "The method specific identifier ... MUST NOT include IP addresses or port numbers"
        if c == '.' || c == ':' {
            return Err(ResolutionMetadata::from_error(ERROR_INVALID_DID));
        }
    }
    let path = match parts.peek() {
        Some(_) => parts.collect::<Vec<&str>>().join("/"),
        None => ".well-known".to_string(),
    };
    let url = format!("http://{onion_address}.onion/{path}/did.json");
    Ok(url)
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDOnion {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let (mut res_meta, doc_data, doc_meta_opt) =
            self.resolve_representation(did, input_metadata).await;
        let doc_opt = if doc_data.is_empty() {
            None
        } else {
            match serde_json::from_slice(&doc_data) {
                Ok(doc) => doc,
                Err(err) => {
                    return (
                        ResolutionMetadata::from_error(
                            &("JSON Error: ".to_string() + &err.to_string()),
                        ),
                        None,
                        None,
                    )
                }
            }
        };
        // https://www.w3.org/TR/did-core/#did-resolution-metadata
        // contentType - "MUST NOT be present if the resolve function was called"
        res_meta.content_type = None;
        (res_meta, doc_opt, doc_meta_opt)
    }

    async fn resolve_representation(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
        let url = match did_onion_url(did) {
            Err(meta) => return (meta, Vec::new(), None),
            Ok(url) => url,
        };

        let mut headers = reqwest::header::HeaderMap::new();
        headers.insert(
            reqwest::header::USER_AGENT,
            reqwest::header::HeaderValue::from_static(USER_AGENT),
        );

        let client_builder = reqwest::Client::builder().default_headers(headers);
        #[cfg(not(target_arch = "wasm32"))]
        let client_builder = match reqwest::Proxy::all(&self.proxy_url) {
            Ok(proxy) => client_builder.proxy(proxy),
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(&format!("Error constructing proxy: {err}")),
                    Vec::new(),
                    None,
                )
            }
        };
        let client = match client_builder.build() {
            Ok(c) => c,
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(&format!("Error building HTTP client: {err}")),
                    Vec::new(),
                    None,
                )
            }
        };
        let accept = input_metadata
            .accept
            .clone()
            .unwrap_or_else(|| "application/json".to_string());
        let resp = match client.get(&url).header("Accept", accept).send().await {
            Ok(req) => req,
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(&format!("Error sending HTTP request: {err}")),
                    Vec::new(),
                    None,
                )
            }
        };
        match resp.error_for_status_ref() {
            Ok(_) => (),
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(&err.to_string()),
                    Vec::new(),
                    Some(DocumentMetadata::default()),
                )
            }
        };
        let doc_representation = match resp.bytes().await {
            Ok(bytes) => bytes.to_vec(),
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(
                        &("Error reading HTTP response: ".to_string() + &err.to_string()),
                    ),
                    Vec::new(),
                    None,
                )
            }
        };
        // TODO: set document created/updated metadata from HTTP headers?
        (
            ResolutionMetadata {
                error: None,
                content_type: Some(TYPE_DID_LD_JSON.to_string()),
                property_set: None,
            },
            doc_representation,
            Some(DocumentMetadata::default()),
        )
    }
}

impl DIDMethod for DIDOnion {
    fn name(&self) -> &'static str {
        "onion"
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn parse_did_onion() {
        assert_eq!(
            did_onion_url("did:onion:fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid").unwrap(),
            "http://fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid.onion/.well-known/did.json"
        );
        assert_eq!(
            did_onion_url("did:onion:fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid:user:alice").unwrap(),
            "http://fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid.onion/user/alice/did.json"
        );
        assert_eq!(
            did_onion_url(
                "did:onion:fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid:u:bob"
            )
            .unwrap(),
            "http://fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid.onion/u/bob/did.json"
        );
    }

    const TORGAP_DEMO_DID: &str =
        "did:onion:fscst5exmlmr262byztwz4kzhggjlzumvc2ndvgytzoucr2tkgxf7mid";

    #[tokio::test]
    #[ignore]
    async fn did_onion_resolve_live() {
        let (res_meta, doc_opt, _doc_meta) = DIDOnion::default()
            .resolve(TORGAP_DEMO_DID, &ResolutionInputMetadata::default())
            .await;
        assert_eq!(res_meta.error, None);
        assert!(doc_opt.is_some());
    }

    /*
     * TODO: test with local proxy and local web server
     * https://github.com/spruceid/ssi/issues/162

    // localhost web server for serving did:onion DID documents.
    // Based on the one in did-web's tests.
    use std::net::SocketAddr;
    fn web_server() -> Result<(String, impl FnOnce() -> Result<(), ()>), hyper::Error> {
        use http::header::{HeaderValue, CONTENT_TYPE};
        use hyper::service::{make_service_fn, service_fn};
        use hyper::{Body, Response, Server};
        let addr = ([127, 0, 0, 1], 0).into();
        let make_svc = make_service_fn(|_| async move {
            Ok::<_, hyper::Error>(service_fn(|req| async move {
                let uri = req.uri();
                // Skip leading slash
                let proxied_url: String = uri.path().chars().skip(1).collect();
                if proxied_url == DID_URL {
                    let body = Body::from(DID_JSON);
                    let mut response = Response::new(body);
                    response
                        .headers_mut()
                        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
                    return Ok::<_, hyper::Error>(response);
                }

                let (mut parts, body) = Response::<Body>::default().into_parts();
                parts.status = hyper::StatusCode::NOT_FOUND;
                let response = Response::from_parts(parts, body);
                return Ok::<_, hyper::Error>(response);
            }))
        });
        let server = Server::try_bind(&addr)?.serve(make_svc);
        let addr: SocketAddr = server.local_addr().parse()?;
        let (shutdown_tx, shutdown_rx) = futures::channel::oneshot::channel();
        let graceful = server.with_graceful_shutdown(async {
            shutdown_rx.await.ok();
        });
        tokio::task::spawn(async move {
            graceful.await.ok();
        });
        let shutdown = || shutdown_tx.send(());
        Ok((addr, shutdown))
    }

    #[tokio::test]
    async fn did_onion_resolve() {
        use socks5_async::SocksServer;
        let mut socks5 = SocksServer::new(
            addr,
            true,
            Box::new(move |username, password| {
                //
            }),
        )
        .await;
        socks5.server().await;

        let (res_meta, doc_opt, _doc_meta) = DIDOnion::default()
            .resolve(TORGAP_DEMO_DID, &ResolutionInputMetadata::default())
            .await;
        assert_eq!(res_meta.error, None);
        assert!(doc_opt.is_some());
    }
    */
}
