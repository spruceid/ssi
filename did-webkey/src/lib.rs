use core::str::FromStr;

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

use sshkeys::PublicKeyKind;
use ssi::did::{DIDMethod, Document, VerificationMethod, VerificationMethodMap, DIDURL};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    TYPE_DID_LD_JSON,
};
use ssi::ssh::ssh_pkk_to_jwk;

// For testing, enable handling requests at localhost.
#[cfg(test)]
use std::cell::RefCell;
#[cfg(test)]
thread_local! {
    static PROXY: RefCell<Option<String>> = RefCell::new(None);
}

/// did:webkey Method
pub struct DIDWebKey;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
enum DIDWebKeyType {
    SSH,
    GPG,
}

impl FromStr for DIDWebKeyType {
    type Err = ResolutionMetadata;
    fn from_str(type_: &str) -> Result<Self, Self::Err> {
        match type_ {
            "ssh" => Ok(DIDWebKeyType::SSH),
            "gpg" => Ok(DIDWebKeyType::GPG),
            _ => Err(ResolutionMetadata::from_error(&ERROR_INVALID_DID)),
        }
    }
}

fn parse_pubkeys_gpg(
    _did: &str,
    _bytes: Vec<u8>,
) -> Result<(Vec<VerificationMethodMap>, Vec<DIDURL>), String> {
    // TODO
    Err(String::from("GPG Key Type Not Implemented"))
}

fn pk_to_vm_ed25519(
    did: &str,
    pk: sshkeys::Ed25519PublicKey,
) -> Result<(VerificationMethodMap, DIDURL), String> {
    let jwk = match ssh_pkk_to_jwk(&PublicKeyKind::Ed25519(pk)) {
        Err(err) => return Err(format!("Unable to convert SSH key to JWK: {}", err)),
        Ok(jwk) => jwk,
    };
    let thumbprint = match jwk.thumbprint() {
        Err(err) => return Err(format!("Unable to calculate JWK thumbprint: {}", err)),
        Ok(t) => t,
    };
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some(thumbprint),
        ..Default::default()
    };
    let vm_map = VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "Ed25519VerificationKey2018".to_string(),
        public_key_jwk: Some(jwk.clone()),
        controller: did.to_string(),
        ..Default::default()
    };
    Ok((vm_map, vm_url))
}

fn pk_to_vm_ecdsa(
    did: &str,
    pk: sshkeys::EcdsaPublicKey,
) -> Result<(VerificationMethodMap, DIDURL), String> {
    let jwk = match ssh_pkk_to_jwk(&PublicKeyKind::Ecdsa(pk)) {
        Err(err) => return Err(format!("Unable to convert SSH key to JWK: {}", err)),
        Ok(jwk) => jwk,
    };
    let thumbprint = match jwk.thumbprint() {
        Err(err) => return Err(format!("Unable to calculate JWK thumbprint: {}", err)),
        Ok(t) => t,
    };
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some(thumbprint),
        ..Default::default()
    };
    let vm_map = VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "EcdsaSecp256r1VerificationKey2019".to_string(),
        public_key_jwk: Some(jwk.clone()),
        controller: did.to_string(),
        ..Default::default()
    };
    Ok((vm_map, vm_url))
}

fn pk_to_vm_rsa(
    did: &str,
    pk: sshkeys::RsaPublicKey,
) -> Result<(VerificationMethodMap, DIDURL), String> {
    let jwk = match ssh_pkk_to_jwk(&PublicKeyKind::Rsa(pk)) {
        Err(err) => return Err(format!("Unable to convert SSH key to JWK: {}", err)),
        Ok(jwk) => jwk,
    };
    let thumbprint = match jwk.thumbprint() {
        Err(err) => return Err(format!("Unable to calculate JWK thumbprint: {}", err)),
        Ok(t) => t,
    };
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some(thumbprint),
        ..Default::default()
    };
    let vm_map = VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "RsaVerificationKey2018".to_string(),
        public_key_jwk: Some(jwk.clone()),
        controller: did.to_string(),
        ..Default::default()
    };
    Ok((vm_map, vm_url))
}

fn pk_to_vm_dsa(
    _did: &str,
    _pk: sshkeys::DsaPublicKey,
) -> Result<(VerificationMethodMap, DIDURL), String> {
    Err(String::from("Unsupported DSA Key"))
}

fn pk_to_vm(did: &str, pk: sshkeys::PublicKey) -> Result<(VerificationMethodMap, DIDURL), String> {
    match pk.kind {
        PublicKeyKind::Rsa(pk) => pk_to_vm_rsa(did, pk),
        PublicKeyKind::Dsa(pk) => pk_to_vm_dsa(did, pk),
        PublicKeyKind::Ecdsa(pk) => pk_to_vm_ecdsa(did, pk),
        PublicKeyKind::Ed25519(pk) => pk_to_vm_ed25519(did, pk),
    }
}

fn parse_pubkeys_ssh(
    did: &str,
    bytes: Vec<u8>,
) -> Result<(Vec<VerificationMethodMap>, Vec<DIDURL>), String> {
    let lines = match String::from_utf8(bytes) {
        Ok(string) => string,
        Err(err) => return Err(format!("Unable to parse SSH keys: {}", err)),
    };
    let mut did_urls = Vec::new();
    let mut vm_maps = Vec::new();
    let lines = lines.trim().split("\n");
    for line in lines {
        let pk = match sshkeys::PublicKey::from_string(line) {
            Ok(pk) => pk,
            Err(err) => return Err(format!("Unable to parse SSH key: {}", err)),
        };
        let (vm_map, did_url) = match pk_to_vm(did, pk) {
            Ok(pk) => pk,
            Err(err) => {
                return Err(format!(
                    "Unable to convert SSH public key to verification method: {}",
                    err
                ))
            }
        };
        vm_maps.push(vm_map);
        did_urls.push(did_url);
    }
    Ok((vm_maps, did_urls))
}

fn parse_pubkeys(
    did: &str,
    type_: DIDWebKeyType,
    bytes: Vec<u8>,
) -> Result<(Vec<VerificationMethodMap>, Vec<DIDURL>), String> {
    match type_ {
        DIDWebKeyType::GPG => parse_pubkeys_gpg(did, bytes),
        DIDWebKeyType::SSH => parse_pubkeys_ssh(did, bytes),
    }
}

fn parse_did_webkey_url(did: &str) -> Result<(DIDWebKeyType, String), ResolutionMetadata> {
    let mut parts = did.split(":").peekable();
    let (type_, domain_name) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
        (Some("did"), Some("webkey"), Some(type_), Some(domain_name)) => {
            (type_.parse()?, domain_name)
        }
        _ => {
            return Err(ResolutionMetadata::from_error(ERROR_INVALID_DID));
        }
    };
    let path = match parts.peek() {
        Some(_) => parts.collect::<Vec<&str>>().join("/"),
        None => {
            // TODO: use .well-known?
            return Err(ResolutionMetadata::from_error(ERROR_INVALID_DID));
        }
    };
    #[allow(unused_mut)]
    let mut url = format!("https://{}/{}", domain_name, path);
    #[cfg(test)]
    PROXY.with(|proxy| {
        if let Some(ref proxy) = *proxy.borrow() {
            url = proxy.clone() + &url;
        }
    });
    Ok((type_, url))
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDWebKey {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let (type_, url) = match parse_did_webkey_url(did) {
            Err(meta) => return (meta, None, None),
            Ok(url) => url,
        };
        // TODO: https://w3c-ccg.github.io/did-method-web/#in-transit-security
        let client = match reqwest::Client::builder().build() {
            Ok(c) => c,
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(&format!(
                        "Error building HTTP client: {}",
                        err.to_string()
                    )),
                    None,
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
                    ResolutionMetadata::from_error(&format!(
                        "Error sending HTTP request : {}",
                        err.to_string()
                    )),
                    None,
                    None,
                )
            }
        };
        match resp.error_for_status_ref() {
            Ok(_) => (),
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(&err.to_string()),
                    None,
                    Some(DocumentMetadata::default()),
                )
            }
        };
        let bytes = match resp.bytes().await {
            Ok(bytes) => bytes.to_vec(),
            Err(err) => {
                return (
                    ResolutionMetadata::from_error(
                        &("Error reading HTTP response: ".to_string() + &err.to_string()),
                    ),
                    None,
                    None,
                )
            }
        };
        let (vm_maps, vm_urls): (Vec<VerificationMethod>, Vec<VerificationMethod>) =
            match parse_pubkeys(did, type_, bytes) {
                Ok((maps, urls)) => (
                    maps.into_iter().map(VerificationMethod::Map).collect(),
                    urls.into_iter().map(VerificationMethod::DIDURL).collect(),
                ),
                Err(err) => {
                    return (
                        ResolutionMetadata::from_error(
                            &("Error parsing keys: ".to_string() + &err.to_string()),
                        ),
                        None,
                        None,
                    )
                }
            };
        let doc = Document {
            context: ssi::did::Contexts::One(ssi::did::Context::URI(
                ssi::did::DEFAULT_CONTEXT.to_string(),
            )),
            id: did.to_string(),
            verification_method: Some(vm_maps),
            authentication: Some(vm_urls.clone()),
            assertion_method: Some(vm_urls),
            ..Default::default()
        };
        // TODO: set document created/updated metadata from HTTP headers?
        (
            ResolutionMetadata {
                error: None,
                content_type: Some(TYPE_DID_LD_JSON.to_string()),
                property_set: None,
            },
            Some(doc),
            Some(DocumentMetadata::default()),
        )
    }
}

impl DIDMethod for DIDWebKey {
    fn name(&self) -> &'static str {
        return "webkey";
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[async_std::test]
    async fn parse_did_webkey() {
        assert_eq!(
            parse_did_webkey_url("did:webkey:ssh:example.org:user.keys").unwrap(),
            (
                DIDWebKeyType::SSH,
                "https://example.org/user.keys".to_string()
            )
        );
        assert_eq!(
            parse_did_webkey_url("did:webkey:gpg:example.org:user.gpg").unwrap(),
            (
                DIDWebKeyType::GPG,
                "https://example.org/user.gpg".to_string()
            )
        );
    }

    // TODO: use JWK fingerprint
    const DID_URL: &str = "https://localhost/user.keys";
    const PUBKEYS: &str = include_str!("../tests/ssh_keys");
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
                    let body = Body::from(PUBKEYS);
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
    async fn from_did_webkey() {
        let (url, shutdown) = web_server().unwrap();
        PROXY.with(|proxy| {
            proxy.replace(Some(url));
        });
        let (res_meta, doc_opt, _doc_meta) = DIDWebKey
            .resolve(
                "did:webkey:ssh:localhost:user.keys",
                &ResolutionInputMetadata::default(),
            )
            .await;
        assert_eq!(res_meta.error, None);
        let value_expected = json!({
          "@context": "https://www.w3.org/ns/did/v1",
          "assertionMethod": [
            "did:webkey:ssh:localhost:user.keys#UgSgEP0VYvWxHUqK_RKifG5eZB-61optu51mu-XNO-w",
            "did:webkey:ssh:localhost:user.keys#AbXY44NRrppCuX0olBDjpfNjdEiitV-W1jVTqy2ixnE",
            "did:webkey:ssh:localhost:user.keys#uqnr0fDZhtGue_7PgMJrRrrtf5M508uKm7yJCdISMyA"
          ],
          "authentication": [
            "did:webkey:ssh:localhost:user.keys#UgSgEP0VYvWxHUqK_RKifG5eZB-61optu51mu-XNO-w",
            "did:webkey:ssh:localhost:user.keys#AbXY44NRrppCuX0olBDjpfNjdEiitV-W1jVTqy2ixnE",
            "did:webkey:ssh:localhost:user.keys#uqnr0fDZhtGue_7PgMJrRrrtf5M508uKm7yJCdISMyA"
          ],
          "id": "did:webkey:ssh:localhost:user.keys",
          "verificationMethod": [
            {
              "controller": "did:webkey:ssh:localhost:user.keys",
              "id": "did:webkey:ssh:localhost:user.keys#UgSgEP0VYvWxHUqK_RKifG5eZB-61optu51mu-XNO-w",
              "publicKeyJwk": {
                "crv": "Ed25519",
                "kty": "OKP",
                "x": "82ecCx4s9pTDh_tFeG6SlKMl6DuhSORCwgMnR7azq0k"
              },
              "type": "Ed25519VerificationKey2018"
            },
            {
              "controller": "did:webkey:ssh:localhost:user.keys",
              "id": "did:webkey:ssh:localhost:user.keys#AbXY44NRrppCuX0olBDjpfNjdEiitV-W1jVTqy2ixnE",
              "publicKeyJwk": {
                "e": "AQAB",
                "kty": "RSA",
                "n": "qy52x0R83O2uqWUWdcqZuWLbBhhyHeZld72Yrl_EOob1LPkPzoQPn6BWWYwpv2arBeXX90PiGN0EvCnQdoYcUNTjWdArgsE3XUWeJeeEvhvx0RHMnU4Mtd9FwTJ2iJIGrGcQ-wRcHb_BE5jEu9yF6qjnnoQcYVJZUCEnwkHMhyQdbGTBfkaKiDgV7kqfnAjc8xwW5sUz9ylZb-7_mniVBSwdeTRUIzROfDF9lXYSBGWMZIvP2bqY39y18olYd9FMnLUKJpxYvF195mw-2mWuNKJFZCoi_RSixAQZpMsRkFyD3Z1UynMXYeI9j0qGCtdxCuyfkmyXZlM7MV57PrOUCta4zvam8-zhTmO4fU9HHgqHfd-6MZ7rt5be5WJcqalPoBnJhJaYb_AuobhaYmxwDVlNySKN66nGAud25xT5i7KBFIHESn1kI3dtvs1meihYT8_oEtLfVnXdWVIob0eDTMMiMRrYsGZH3xvzHLeQY3WDEP2Xs_yZxWO3x2jcu17t"
              },
              "type": "RsaVerificationKey2018"
            },
            {
              "controller": "did:webkey:ssh:localhost:user.keys",
              "id": "did:webkey:ssh:localhost:user.keys#uqnr0fDZhtGue_7PgMJrRrrtf5M508uKm7yJCdISMyA",
              "publicKeyJwk": {
                "crv": "P-256",
                "kty": "EC",
                "x": "Ek29l7abGDIyzyk1lSLjXy0XWMLtXNTMgz3qDT2d7zo",
                "y": "QTtJ7iCkbV8jT7nk48Qusi7ZQxgnJqu18F-rkOBIlzk"
              },
              "type": "EcdsaSecp256r1VerificationKey2019"
            }
          ]
        });
        let doc = doc_opt.unwrap();
        let doc_value = serde_json::to_value(doc).unwrap();
        eprintln!("doc {}", serde_json::to_string_pretty(&doc_value).unwrap());
        assert_eq!(doc_value, value_expected);
        PROXY.with(|proxy| {
            proxy.replace(None);
        });
        shutdown().ok();
    }
}
