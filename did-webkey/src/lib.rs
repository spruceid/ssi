use anyhow::{anyhow, Context, Result};
use async_trait::async_trait;
use core::str::FromStr;
use pgp::{types::KeyTrait, Deserializable, SignedPublicKey};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, io::Cursor};

use sshkeys::PublicKeyKind;
use ssi_dids::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
};
use ssi_dids::{DIDMethod, Document, VerificationMethod, VerificationMethodMap, DIDURL};
use ssi_ssh::ssh_pkk_to_jwk;

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
    Ssh,
    Gpg,
}

impl FromStr for DIDWebKeyType {
    type Err = ResolutionMetadata;
    fn from_str(type_: &str) -> Result<Self, Self::Err> {
        match type_ {
            "ssh" => Ok(DIDWebKeyType::Ssh),
            "gpg" => Ok(DIDWebKeyType::Gpg),
            _ => Err(ResolutionMetadata::from_error(ERROR_INVALID_DID)),
        }
    }
}

fn parse_pubkeys_gpg(
    did: &str,
    bytes: Vec<u8>,
) -> Result<(Vec<VerificationMethodMap>, Vec<DIDURL>)> {
    let mut did_urls = Vec::new();
    let mut vm_maps = Vec::new();

    let pks = SignedPublicKey::from_armor_many(Cursor::new(bytes))?
        .0
        .collect::<Result<Vec<_>, _>>()?;
    for pk in pks {
        let (vm_map, did_url) = gpg_pk_to_vm(did, pk)?;
        vm_maps.push(vm_map);
        did_urls.push(did_url);
    }

    Ok((vm_maps, did_urls))
}

fn gpg_pk_to_vm(did: &str, pk: SignedPublicKey) -> Result<(VerificationMethodMap, DIDURL)> {
    let fingerprint = pk
        .fingerprint()
        .iter()
        .fold(String::new(), |acc, &x| format!("{acc}{x:02X}"));
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some(fingerprint.clone()),
        ..Default::default()
    };

    // For compatibility with sequoia-openpgp
    // Note that the output still won't be identical because sequoia uses the new style of CTB whilst rpgp doesn't
    let mut header = {
        let mut res = String::new();
        let l = fingerprint.len();
        for (i, b) in fingerprint.chars().enumerate() {
            if i > 0 && i % 4 == 0 {
                res.push(' ');
                if i * 2 == l {
                    res.push(' ');
                }
            }
            res.push(b);
        }
        res
    };
    if let Some(user) = pk.details.users.get(0) {
        // Workaround to have the same key multiple times (`Comment`)
        header = format!("{}\nComment: {}", header, user.id.id());
    }
    let headers = BTreeMap::from([("Comment".to_string(), header)]);
    let armored_pgp = pk.to_armored_string(Some(&headers))?;

    let vm_map = VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "PgpVerificationKey2021".to_string(),
        public_key_pgp: Some(armored_pgp),
        controller: did.to_string(),
        ..Default::default()
    };
    Ok((vm_map, vm_url))
}

fn pk_to_vm_ed25519(
    did: &str,
    pk: sshkeys::Ed25519PublicKey,
) -> Result<(VerificationMethodMap, DIDURL)> {
    let jwk = ssh_pkk_to_jwk(&PublicKeyKind::Ed25519(pk))?;
    let thumbprint = jwk
        .thumbprint()
        .context("Unable to calculate JWK thumbprint")?;
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some(thumbprint),
        ..Default::default()
    };
    let vm_map = VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "Ed25519VerificationKey2018".to_string(),
        public_key_jwk: Some(jwk),
        controller: did.to_string(),
        ..Default::default()
    };
    Ok((vm_map, vm_url))
}

fn pk_to_vm_ecdsa(
    did: &str,
    pk: sshkeys::EcdsaPublicKey,
) -> Result<(VerificationMethodMap, DIDURL)> {
    let jwk = ssh_pkk_to_jwk(&PublicKeyKind::Ecdsa(pk))?;
    let thumbprint = jwk
        .thumbprint()
        .context("Unable to calculate JWK thumbprint")?;
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some(thumbprint),
        ..Default::default()
    };
    let vm_map = VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "EcdsaSecp256r1VerificationKey2019".to_string(),
        public_key_jwk: Some(jwk),
        controller: did.to_string(),
        ..Default::default()
    };
    Ok((vm_map, vm_url))
}

fn pk_to_vm_rsa(did: &str, pk: sshkeys::RsaPublicKey) -> Result<(VerificationMethodMap, DIDURL)> {
    let jwk = ssh_pkk_to_jwk(&PublicKeyKind::Rsa(pk))?;
    let thumbprint = jwk
        .thumbprint()
        .context("Unable to calculate JWK thumbprint")?;
    let vm_url = DIDURL {
        did: did.to_string(),
        fragment: Some(thumbprint),
        ..Default::default()
    };
    let vm_map = VerificationMethodMap {
        id: vm_url.to_string(),
        type_: "RsaVerificationKey2018".to_string(),
        public_key_jwk: Some(jwk),
        controller: did.to_string(),
        ..Default::default()
    };
    Ok((vm_map, vm_url))
}

fn pk_to_vm_dsa(_did: &str, _pk: sshkeys::DsaPublicKey) -> Result<(VerificationMethodMap, DIDURL)> {
    Err(anyhow!("Unsupported DSA Key"))
}

fn pk_to_vm(did: &str, pk: sshkeys::PublicKey) -> Result<(VerificationMethodMap, DIDURL)> {
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
) -> Result<(Vec<VerificationMethodMap>, Vec<DIDURL>)> {
    let lines = String::from_utf8(bytes)?;
    let mut did_urls = Vec::new();
    let mut vm_maps = Vec::new();
    let lines = lines.trim().split('\n');
    for line in lines {
        let pk = sshkeys::PublicKey::from_string(line)?;
        let (vm_map, did_url) = pk_to_vm(did, pk)?;
        vm_maps.push(vm_map);
        did_urls.push(did_url);
    }
    Ok((vm_maps, did_urls))
}

fn parse_pubkeys(
    did: &str,
    type_: DIDWebKeyType,
    bytes: Vec<u8>,
) -> Result<(Vec<VerificationMethodMap>, Vec<DIDURL>)> {
    match type_ {
        DIDWebKeyType::Gpg => parse_pubkeys_gpg(did, bytes),
        DIDWebKeyType::Ssh => parse_pubkeys_ssh(did, bytes),
    }
}

fn parse_did_webkey_url(did: &str) -> Result<(DIDWebKeyType, String), ResolutionMetadata> {
    let mut parts = did.split(':').peekable();
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
    let mut url = format!("https://{domain_name}/{path}");
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
                    ResolutionMetadata::from_error(&format!("Error building HTTP client: {err}")),
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
                    ResolutionMetadata::from_error(&format!("Error sending HTTP request : {err}")),
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
                        ResolutionMetadata::from_error(&format!("Error parsing keys: {err}")),
                        None,
                        None,
                    )
                }
            };
        let doc = Document {
            context: ssi_dids::Contexts::One(ssi_dids::Context::URI(
                ssi_dids::DEFAULT_CONTEXT.into(),
            )),
            id: did.to_string(),
            verification_method: Some(vm_maps),
            authentication: Some(vm_urls.clone()),
            assertion_method: Some(vm_urls),
            ..Default::default()
        };
        // TODO: set document created/updated metadata from HTTP headers?
        (
            ResolutionMetadata::default(),
            Some(doc),
            Some(DocumentMetadata::default()),
        )
    }
}

impl DIDMethod for DIDWebKey {
    fn name(&self) -> &'static str {
        "webkey"
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
                DIDWebKeyType::Ssh,
                "https://example.org/user.keys".to_string()
            )
        );
        assert_eq!(
            parse_did_webkey_url("did:webkey:gpg:example.org:user.gpg").unwrap(),
            (
                DIDWebKeyType::Gpg,
                "https://example.org/user.gpg".to_string()
            )
        );
    }

    // localhost web server for serving did:web DID documents.
    fn web_server(
        did_url: &'static str,
        pubkeys: &'static str,
    ) -> Result<(String, impl FnOnce() -> Result<(), ()>), hyper::Error> {
        use http::header::{HeaderValue, CONTENT_TYPE};
        use hyper::service::{make_service_fn, service_fn};
        use hyper::{Body, Response, Server};
        let addr = ([127, 0, 0, 1], 0).into();
        let make_svc = make_service_fn(move |_| async move {
            Ok::<_, hyper::Error>(service_fn(move |req| async move {
                let uri = req.uri();
                // Skip leading slash
                let proxied_url: String = uri.path().chars().skip(1).collect();
                if proxied_url == did_url {
                    let body = Body::from(pubkeys);
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
    async fn from_did_webkey_ssh() {
        // TODO: use JWK fingerprint
        let did_url: &str = "https://localhost/user.keys";
        let pubkeys: &str = include_str!("../tests/ssh_keys");

        let (url, shutdown) = web_server(did_url, pubkeys).unwrap();
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

    #[test_log::test(tokio::test)]
    async fn from_did_webkey_gpg() {
        let did_url: &str = "https://localhost/user.gpg";
        let pubkeys: &str = include_str!("../tests/user.gpg");

        let (url, shutdown) = web_server(did_url, pubkeys).unwrap();
        PROXY.with(|proxy| {
            proxy.replace(Some(url));
        });
        let (res_meta, doc_opt, _doc_meta) = DIDWebKey
            .resolve(
                "did:webkey:gpg:localhost:user.gpg",
                &ResolutionInputMetadata::default(),
            )
            .await;
        assert_eq!(res_meta.error, None);

        let value_expected = json!({
          "@context": "https://www.w3.org/ns/did/v1",
          "assertionMethod": [
            "did:webkey:gpg:localhost:user.gpg#0CEE8B84B25C0A3C554A9EC1F8FEE972E2A1D935",
            "did:webkey:gpg:localhost:user.gpg#6BABBD68A84D5FE3CEEB986EB77927AE619B8EB6",
            "did:webkey:gpg:localhost:user.gpg#DCB1FF1899328C0EBB5DF07BD41BBBD1FE58006E"
          ],
          "authentication": [
            "did:webkey:gpg:localhost:user.gpg#0CEE8B84B25C0A3C554A9EC1F8FEE972E2A1D935",
            "did:webkey:gpg:localhost:user.gpg#6BABBD68A84D5FE3CEEB986EB77927AE619B8EB6",
            "did:webkey:gpg:localhost:user.gpg#DCB1FF1899328C0EBB5DF07BD41BBBD1FE58006E"
          ],
          "id": "did:webkey:gpg:localhost:user.gpg",
          "verificationMethod": [
            {
              "controller": "did:webkey:gpg:localhost:user.gpg",
              "id": "did:webkey:gpg:localhost:user.gpg#0CEE8B84B25C0A3C554A9EC1F8FEE972E2A1D935",
              "publicKeyPgp": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: 0CEE 8B84 B25C 0A3C 554A  9EC1 F8FE E972 E2A1 D935\nComment: Foobar <foobar@example.org>\n\n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\n2YdBRVOAnw==\n=A/sJ\n-----END PGP PUBLIC KEY BLOCK-----\n",
              "type": "PgpVerificationKey2021"
            },
            {
              "controller": "did:webkey:gpg:localhost:user.gpg",
              "id": "did:webkey:gpg:localhost:user.gpg#6BABBD68A84D5FE3CEEB986EB77927AE619B8EB6",
              "publicKeyPgp": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: 6BAB BD68 A84D 5FE3 CEEB  986E B779 27AE 619B 8EB6\nComment: Foobar <foobar@example.org>\n\nmFIEYd3nnBMIKoZIzj0DAQcCAwRhnJmDiD35LzJXstn4zBMfpavUCSkYzyJKIYHe\nOwW4BFe+AF/ZdczzJnx8O1xndvYOFccVNAz7HMb7xPB7MDcEtBtGb29iYXIgPGZv\nb2JhckBleGFtcGxlLm9yZz6IkAQTEwgAOBYhBGurvWioTV/jzuuYbrd5J65hm462\nBQJh3eecAhsDBQsJCAcCBhUKCQgLAgQWAgMBAh4BAheAAAoJELd5J65hm462BNgB\nAKzxt0M3BpEGlAGjz4czrWX8zRdo6XiKeby5yeORfKDEAP4uOuIwE9ics9XICXUg\n1IZhOVNB2cUS6p7Q5ApaqwE3WbhWBGHd55wSCCqGSM49AwEHAgMEN0OVHjy6Pwyp\nfTci+EKIc486T1EGeYBs/1FErq3bB44Vqr3EsOcdscSqyj3dcxXb47d0kOkiDPKm\nKTy/6ZPWsAMBCAeIeAQYEwgAIBYhBGurvWioTV/jzuuYbrd5J65hm462BQJh3eec\nAhsMAAoJELd5J65hm462KTsA/3vbivQARQMsZfGKptW/SVaKwszMQm2SE+jOESoH\ntk3MAQCjUD7O3CzMX2rCDgLBLh6hwgB3zjn8uaHM1zO9Z48HhQ==\n=97RS\n-----END PGP PUBLIC KEY BLOCK-----\n",
              "type": "PgpVerificationKey2021"
            },
            {
              "controller": "did:webkey:gpg:localhost:user.gpg",
              "id": "did:webkey:gpg:localhost:user.gpg#DCB1FF1899328C0EBB5DF07BD41BBBD1FE58006E",
              "publicKeyPgp": "-----BEGIN PGP PUBLIC KEY BLOCK-----\nComment: DCB1 FF18 9932 8C0E BB5D  F07B D41B BBD1 FE58 006E\nComment: Foobar <foobar@example.org>\n\nmDMEYd3nyxYJKwYBBAHaRw8BAQdAp756gWZbZB66yTjjn52DyUvCxUgFG7aSKqYY\n7KG2KvC0G0Zvb2JhciA8Zm9vYmFyQGV4YW1wbGUub3JnPoiQBBMWCAA4FiEE3LH/\nGJkyjA67XfB71Bu70f5YAG4FAmHd58sCGwMFCwkIBwIGFQoJCAsCBBYCAwECHgEC\nF4AACgkQ1Bu70f5YAG7IMQD7BEg3vAqinv1wllBpXfQov7b4+haxcADWXgmc+06D\nx1QBAMWd6Oa71iKafJKKL3Vgk5q/Sns5+xDvMJmcGbMemckMuDgEYd3nyxIKKwYB\nBAGXVQEFAQEHQECEkuj4GJuUKC0nKvyXoEA1DxJPnASFt2GPC0trMcMoAwEIB4h4\nBBgWCAAgFiEE3LH/GJkyjA67XfB71Bu70f5YAG4FAmHd58sCGwwACgkQ1Bu70f5Y\nAG6eUAEA8vwHBMR4ownA069pQ2EqGhueMoU7YQX0IQBosDf7NrMBAJCoLmuc2dGQ\nT4/C2SFSd3mgOqJXpumOyBFj6hoYkyAI\n=gMz4\n-----END PGP PUBLIC KEY BLOCK-----\n",
              "type": "PgpVerificationKey2021"
            }
          ]
        });

        let doc = doc_opt.unwrap();
        let doc_value = serde_json::to_value(doc).unwrap();
        pretty_assertions::assert_eq!(doc_value, value_expected);
        PROXY.with(|proxy| {
            proxy.replace(None);
        });
        shutdown().ok();
    }
}
