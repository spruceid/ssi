use http::header;
use ssi_dids_core::{
    document::representation::MediaType,
    resolution::{self, DIDMethodResolver, Error, Output},
    DIDMethod,
};

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

// For testing, enable handling requests at localhost.
#[cfg(test)]
use std::cell::RefCell;

#[cfg(test)]
thread_local! {
  static PROXY: RefCell<Option<String>> = RefCell::new(None);
}

#[derive(Debug, thiserror::Error)]
pub enum InternalError {
    #[error("Error building HTTP client: {0}")]
    Client(reqwest::Error),

    #[error("Error sending HTTP request ({0}): {1}")]
    Request(String, reqwest::Error),

    #[error("Server error: {0}")]
    Server(String),

    #[error("Error reading HTTP response: {0}")]
    Response(reqwest::Error),
}

/// did:web Method
///
/// [Specification](https://w3c-ccg.github.io/did-method-web/)
pub struct DIDWeb;

fn did_web_url(id: &str) -> Result<String, Error> {
    let mut parts = id.split(':').peekable();
    let domain_name = parts
        .next()
        .ok_or_else(|| Error::InvalidMethodSpecificId(id.to_owned()))?;

    // TODO:
    // - Validate domain name: alphanumeric, hyphen, dot. no IP address.
    // - Ensure domain name matches TLS certificate common name
    // - Support punycode?
    // - Support query strings?
    let path = match parts.peek() {
        Some(_) => parts.collect::<Vec<&str>>().join("/"),
        None => ".well-known".to_string(),
    };

    // Use http for localhost, for testing purposes.
    let proto = if domain_name.starts_with("localhost") {
        "http"
    } else {
        "https"
    };

    #[allow(unused_mut)]
    let mut url = format!(
        "{proto}://{}/{path}/did.json",
        domain_name.replacen("%3A", ":", 1)
    );

    #[cfg(test)]
    PROXY.with(|proxy| {
        if let Some(ref proxy) = *proxy.borrow() {
            url = proxy.clone() + &url;
        }
    });

    Ok(url)
}

impl DIDMethod for DIDWeb {
    const DID_METHOD_NAME: &'static str = "web";
}

/// <https://w3c-ccg.github.io/did-method-web/#read-resolve>
impl DIDMethodResolver for DIDWeb {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: resolution::Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        // let did = DIDBuf::new(format!("did:web:{method_specific_id}")).unwrap();

        let url = did_web_url(method_specific_id)?;
        // TODO: https://w3c-ccg.github.io/did-method-web/#in-transit-security

        let mut headers = reqwest::header::HeaderMap::new();

        headers.insert(
            "User-Agent",
            reqwest::header::HeaderValue::from_static(USER_AGENT),
        );

        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| Error::internal(InternalError::Client(e)))?;

        let accept = options.accept.unwrap_or(MediaType::Json);

        let resp = client
            .get(&url)
            .header(header::ACCEPT, accept.to_string())
            .send()
            .await
            .map_err(|e| Error::internal(InternalError::Request(url.to_owned(), e)))?;

        resp.error_for_status_ref().map_err(|err| {
            if err.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                Error::NotFound
            } else {
                Error::internal(InternalError::Server(err.to_string()))
            }
        })?;

        let document = resp
            .bytes()
            .await
            .map_err(|e| Error::internal(InternalError::Response(e)))?;

        // TODO: set document created/updated metadata from HTTP headers?
        Ok(Output {
            document: document.into(),
            document_metadata: ssi_dids_core::document::Metadata::default(),
            metadata: resolution::Metadata::from_content_type(Some(MediaType::JsonLd.to_string())),
        })
    }
}

#[cfg(test)]
mod tests {
    use ssi_claims::{
        data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
        vc::{syntax::NonEmptyVec, v1::JsonCredential},
        VerificationParameters,
    };
    use ssi_dids_core::{did, DIDResolver, Document, VerificationMethodDIDResolver};
    use ssi_jwk::JWK;
    use ssi_verification_methods_core::{ProofPurpose, SingleSecretSigner};
    use static_iref::{iri, uri};

    use super::*;

    #[tokio::test]
    async fn parse_did_web() {
        // https://w3c-ccg.github.io/did-method-web/#example-3-creating-the-did
        assert_eq!(
            did_web_url(did!("did:web:w3c-ccg.github.io").method_specific_id()).unwrap(),
            "https://w3c-ccg.github.io/.well-known/did.json"
        );
        // https://w3c-ccg.github.io/did-method-web/#example-4-creating-the-did-with-optional-path
        assert_eq!(
            did_web_url(did!("did:web:w3c-ccg.github.io:user:alice").method_specific_id()).unwrap(),
            "https://w3c-ccg.github.io/user/alice/did.json"
        );
        // https://w3c-ccg.github.io/did-method-web/#optional-path-considerations
        assert_eq!(
            did_web_url(did!("did:web:example.com:u:bob").method_specific_id()).unwrap(),
            "https://example.com/u/bob/did.json"
        );
        // https://w3c-ccg.github.io/did-method-web/#example-creating-the-did-with-optional-path-and-port
        assert_eq!(
            did_web_url(did!("did:web:example.com%3A443:u:bob").method_specific_id()).unwrap(),
            "https://example.com:443/u/bob/did.json"
        );
    }

    const DID_URL: &str = "http://localhost/.well-known/did.json";
    const DID_JSON: &str = r#"{
      "@context": "https://www.w3.org/ns/did/v1",
      "id": "did:web:localhost",
      "verificationMethod": [{
         "id": "did:web:localhost#key1",
         "type": "Ed25519VerificationKey2018",
         "controller": "did:web:localhost",
         "publicKeyBase58": "2sXRz2VfrpySNEL6xmXJWQg6iY94qwNp1qrJJFBuPWmH"
      }],
      "assertionMethod": ["did:web:localhost#key1"]
    }"#;

    // localhost web server for serving did:web DID documents.
    // TODO: pass arguments here instead of using const
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
                Ok::<_, hyper::Error>(response)
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
    async fn from_did_key() {
        let (url, shutdown) = web_server().unwrap();
        PROXY.with(|proxy| {
            proxy.replace(Some(url));
        });
        let doc = DIDWeb.resolve(did!("did:web:localhost")).await.unwrap();
        let doc_expected = Document::from_bytes(MediaType::JsonLd, DID_JSON.as_bytes()).unwrap();
        assert_eq!(doc.document.document(), doc_expected.document());
        PROXY.with(|proxy| {
            proxy.replace(None);
        });
        shutdown().ok();
    }

    #[tokio::test]
    async fn credential_prove_verify_did_web() {
        let didweb = VerificationMethodDIDResolver::new(DIDWeb);
        let params = VerificationParameters::from_resolver(&didweb);

        let (url, shutdown) = web_server().unwrap();
        PROXY.with(|proxy| {
            proxy.replace(Some(url));
        });

        let cred = JsonCredential::new(
            None,
            did!("did:web:localhost").to_owned().into_uri().into(),
            "2021-01-26T16:57:27Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:web:localhost"
            })),
        );

        let key: JWK = include_str!("../../../../../tests/ed25519-2020-10-18.json")
            .parse()
            .unwrap();
        let verification_method = iri!("did:web:localhost#key1").to_owned().into();
        let suite = AnySuite::pick(&key, Some(&verification_method)).unwrap();
        let issue_options = ProofOptions::new(
            "2021-01-26T16:57:27Z".parse().unwrap(),
            verification_method,
            ProofPurpose::Assertion,
            Default::default(),
        );
        let signer = SingleSecretSigner::new(key).into_local();
        let vc = suite
            .sign(cred, &didweb, &signer, issue_options)
            .await
            .unwrap();

        println!(
            "proof: {}",
            serde_json::to_string_pretty(&vc.proofs).unwrap()
        );
        assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..BCvVb4jz-yVaTeoP24Wz0cOtiHKXCdPcmFQD_pxgsMU6aCAj1AIu3cqHyoViU93nPmzqMLswOAqZUlMyVnmzDw");
        assert!(vc.verify(&params).await.unwrap().is_ok());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();
        // It should fail.
        assert!(vc_bad_issuer.verify(params).await.unwrap().is_err());

        PROXY.with(|proxy| {
            proxy.replace(None);
        });
        shutdown().ok();
    }
}
