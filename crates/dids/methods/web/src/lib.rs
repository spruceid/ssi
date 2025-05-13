use http::header;
use iref::{uri::AuthorityBuf, UriBuf};
use ssi_dids_core::{
    document::representation::MediaType,
    resolution::{self, DIDMethodResolver, Error, Output},
    DIDMethod,
};

pub const USER_AGENT: &str = concat!(env!("CARGO_PKG_NAME"), "/", env!("CARGO_PKG_VERSION"));

// For testing, enable handling requests at localhost.
#[cfg(test)]
use std::cell::RefCell;
use std::{net::Ipv4Addr, str::FromStr};

#[cfg(test)]
thread_local! {
  static PROXY: RefCell<Option<String>> = const { RefCell::new(None) };
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

fn did_web_url(id: &str) -> Result<UriBuf, Error> {
    let mut parts = id.split(':').peekable();

    // Extract the authority, with an optional port colon percent-encoded.
    let encoded_authority = parts
        .next()
        .ok_or_else(|| Error::InvalidMethodSpecificId(id.to_owned()))?;

    // Decoded authority.
    let authority: AuthorityBuf = match encoded_authority.rsplit_once("%3A") {
        Some((host, port)) => AuthorityBuf::new(format!("{host}:{port}").into_bytes())
            .map_err(|_| Error::InvalidMethodSpecificId(id.to_owned()))?,
        None => encoded_authority
            .parse()
            .map_err(|_| Error::InvalidMethodSpecificId(id.to_owned()))?,
    };

    // Decide what scheme to use.
    let host = authority.host().as_str();
    let scheme = if host == "localhost" {
        "http"
    } else {
        match Ipv4Addr::from_str(host) {
            Ok(ip) if ip.is_private() || ip.is_loopback() => "http",
            Ok(_) => return Err(Error::InvalidMethodSpecificId(id.to_owned())),
            _ => "https",
        }
    };

    // TODO:
    // - Validate domain name: alphanumeric, hyphen, dot.
    // - Ensure domain name matches TLS certificate common name
    // - Support punycode?
    // - Support query strings?
    let path = match parts.peek() {
        Some(_) => parts.collect::<Vec<&str>>().join("/"),
        None => ".well-known".to_string(),
    };

    #[allow(unused_mut)]
    let mut url = format!("{scheme}://{}/{path}/did.json", authority);

    #[cfg(test)]
    PROXY.with(|proxy| {
        if let Some(ref proxy) = *proxy.borrow() {
            url = proxy.clone() + &url;
        }
    });

    UriBuf::new(url.into_bytes()).map_err(|_| Error::InvalidMethodSpecificId(id.to_owned()))
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

        #[cfg(target_os = "android")]
        let client = reqwest::Client::builder()
            .use_rustls_tls()
            .default_headers(headers)
            .build()
            .map_err(|e| Error::internal(InternalError::Client(e)))?;

        #[cfg(not(target_os = "android"))]
        let client = reqwest::Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| Error::internal(InternalError::Client(e)))?;

        let accept = options.accept.unwrap_or(MediaType::Json);

        let resp = client
            .get(url.as_str())
            .header(header::ACCEPT, accept.to_string())
            .send()
            .await
            .map_err(|e| Error::internal(InternalError::Request(url.to_string(), e)))?;

        resp.error_for_status_ref().map_err(|err| {
            if err.status() == Some(reqwest::StatusCode::NOT_FOUND) {
                Error::NotFound
            } else {
                Error::internal(InternalError::Server(err.to_string()))
            }
        })?;

        let media_type = resp
            .headers()
            .get(header::CONTENT_TYPE)
            .map(|value| match value.as_bytes() {
                b"application/json" => Ok(MediaType::Json),
                b"application/json; charset=utf-8" => Ok(MediaType::Json),
                other => MediaType::from_bytes(other),
            })
            .transpose()?
            .unwrap_or(MediaType::Json);

        let document = resp
            .bytes()
            .await
            .map_err(|e| Error::internal(InternalError::Response(e)))?;

        // TODO: set document created/updated metadata from HTTP headers?
        Ok(Output {
            document: document.into(),
            document_metadata: ssi_dids_core::document::Metadata::default(),
            metadata: resolution::Metadata::from_content_type(Some(media_type.to_string())),
        })
    }
}

#[cfg(test)]
mod tests {
    use iref::Uri;
    use ssi_claims::{
        data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
        vc::{syntax::NonEmptyVec, v1::JsonCredential},
        VerificationParameters,
    };
    use ssi_dids_core::{did, DIDResolver, Document, VerificationMethodDIDResolver, DID};
    use ssi_jwk::JWK;
    use ssi_verification_methods_core::{ProofPurpose, SingleSecretSigner};
    use static_iref::{iri, uri};

    use super::*;

    #[tokio::test]
    async fn parse_did_web() {
        let test_vectors: [(&DID, &Uri); 7] = [
            (
                // https://w3c-ccg.github.io/did-method-web/#example-3-creating-the-did
                did!("did:web:w3c-ccg.github.io"),
                uri!("https://w3c-ccg.github.io/.well-known/did.json"),
            ),
            (
                // https://w3c-ccg.github.io/did-method-web/#example-4-creating-the-did-with-optional-path
                did!("did:web:w3c-ccg.github.io:user:alice"),
                uri!("https://w3c-ccg.github.io/user/alice/did.json"),
            ),
            (
                // https://w3c-ccg.github.io/did-method-web/#optional-path-considerations
                did!("did:web:example.com:u:bob"),
                uri!("https://example.com/u/bob/did.json"),
            ),
            (
                // https://w3c-ccg.github.io/did-method-web/#example-creating-the-did-with-optional-path-and-port
                did!("did:web:example.com%3A443:u:bob"),
                uri!("https://example.com:443/u/bob/did.json"),
            ),
            (
                // localhost
                did!("did:web:localhost:u:alice"),
                uri!("http://localhost/u/alice/did.json"),
            ),
            (
                // Private IPv4.
                did!("did:web:192.168.0.1:u:alice"),
                uri!("http://192.168.0.1/u/alice/did.json"),
            ),
            (
                // Private IPv4 with port.
                did!("did:web:192.168.0.1%3A3003:u:alice"),
                uri!("http://192.168.0.1:3003/u/alice/did.json"),
            ),
        ];

        for (did, url) in test_vectors {
            assert_eq!(did_web_url(did.method_specific_id()).unwrap(), url);
        }
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
        let doc_expected = Document::from_bytes(MediaType::Json, DID_JSON.as_bytes()).unwrap();
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
