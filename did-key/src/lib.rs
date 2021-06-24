use async_trait::async_trait;
use serde_json::Value;
use std::collections::BTreeMap;
use thiserror::Error;

use ssi::did::{
    Context, Contexts, DIDMethod, Document, Source, VerificationMethod, VerificationMethodMap,
    DEFAULT_CONTEXT, DIDURL,
};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    ERROR_NOT_FOUND, TYPE_DID_LD_JSON,
};
#[cfg(feature = "secp256r1")]
use ssi::jwk::p256_parse;
#[cfg(feature = "secp256k1")]
use ssi::jwk::secp256k1_parse;
use ssi::jwk::{Base64urlUInt, OctetParams, Params, JWK};

const DID_KEY_ED25519_PREFIX: [u8; 2] = [0xed, 0x01];
const DID_KEY_SECP256K1_PREFIX: [u8; 2] = [0xe7, 0x01];
const DID_KEY_P256_PREFIX: [u8; 2] = [0x80, 0x24];

#[derive(Error, Debug)]
pub enum DIDKeyError {
    #[error("Unsupported key type")]
    UnsupportedKeyType,
    #[error("Unsupported curve: {0}")]
    UnsupportedCurve(String),
    #[error("Unsupported source")]
    UnsupportedSource,
}

pub struct DIDKey;

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDKey {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let vm_type;
        let vm_type_iri;
        if !did.starts_with("did:key:") {
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
        let method_specific_id = &did[8..];
        let (_base, data) = match multibase::decode(method_specific_id) {
            Ok((base, data)) => (base, data),
            Err(_err) => {
                // TODO: pass through these errors somehow
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
        if data.len() < 2 {
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
        let mut context = BTreeMap::new();
        context.insert(
            "publicKeyJwk".to_string(),
            serde_json::json!({
                "@id": "https://w3id.org/security#publicKeyJwk",
                "@type": "@json"
            }),
        );

        let jwk = if data[0] == DID_KEY_ED25519_PREFIX[0] && data[1] == DID_KEY_ED25519_PREFIX[1] {
            if data.len() - 2 != 32 {
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
            vm_type = "Ed25519VerificationKey2018".to_string();
            vm_type_iri = "https://w3id.org/security#Ed25519VerificationKey2018".to_string();
            JWK {
                params: Params::OKP(OctetParams {
                    curve: "Ed25519".to_string(),
                    public_key: Base64urlUInt(data[2..].to_vec()),
                    private_key: None,
                }),
                public_key_use: None,
                key_operations: None,
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_certificate_chain: None,
                x509_thumbprint_sha1: None,
                x509_thumbprint_sha256: None,
            }
        } else if data[0] == DID_KEY_SECP256K1_PREFIX[0] && data[1] == DID_KEY_SECP256K1_PREFIX[1] {
            if data.len() - 2 != 33 {
                return (
                    ResolutionMetadata::from_error(ERROR_INVALID_DID),
                    None,
                    None,
                );
            }
            #[cfg(feature = "secp256k1")]
            match secp256k1_parse(&data[2..]) {
                Ok(jwk) => {
                    vm_type = "EcdsaSecp256k1VerificationKey2019".to_string();
                    vm_type_iri =
                        "https://w3id.org/security#EcdsaSecp256k1VerificationKey2019".to_string();
                    jwk
                }
                Err(err) => return (ResolutionMetadata::from_error(&err), None, None),
            }
            #[cfg(not(feature = "secp256k1"))]
            return (
                ResolutionMetadata::from_error("did:key type secp256k1 not supported"),
                None,
                None,
            );
        } else if data[0] == DID_KEY_P256_PREFIX[0] && data[1] == DID_KEY_P256_PREFIX[1] {
            #[cfg(feature = "secp256r1")]
            match p256_parse(&data[2..]) {
                Ok(jwk) => {
                    vm_type = "EcdsaSecp256r1VerificationKey2019".to_string();
                    vm_type_iri =
                        "https://w3id.org/security#EcdsaSecp256r1VerificationKey2019".to_string();
                    jwk
                }
                Err(err) => return (ResolutionMetadata::from_error(&err.to_string()), None, None),
            }
            #[cfg(not(feature = "secp256r1"))]
            return (
                ResolutionMetadata::from_error("did:key type P-256 not supported"),
                None,
                None,
            );
        } else {
            return (
                ResolutionMetadata {
                    error: Some(ERROR_NOT_FOUND.to_string()),
                    content_type: None,
                    property_set: None,
                },
                None,
                None,
            );
        };
        context.insert(vm_type.to_string(), Value::String(vm_type_iri));
        let vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some(method_specific_id.to_string()),
            ..Default::default()
        };
        let doc = Document {
            context: Contexts::Many(vec![
                Context::URI(DEFAULT_CONTEXT.to_string()),
                Context::Object(context),
            ]),
            id: did.to_string(),
            verification_method: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: did.to_string() + &"#" + method_specific_id,
                type_: vm_type,
                controller: did.to_string(),
                public_key_jwk: Some(jwk),
                ..Default::default()
            })]),
            authentication: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            assertion_method: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            ..Default::default()
        };
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

impl DIDMethod for DIDKey {
    fn name(&self) -> &'static str {
        return "key";
    }

    fn generate(&self, source: &Source) -> Option<String> {
        let jwk = match source {
            Source::Key(jwk) => jwk,
            Source::KeyAndPattern(jwk, pattern) => {
                if !pattern.is_empty() {
                    // pattern not supported
                    return None;
                }
                jwk
            }
            _ => return None,
        };
        let did = match jwk.params {
            Params::OKP(ref params) => {
                match &params.curve[..] {
                    "Ed25519" => {
                        "did:key:".to_string()
                            + &multibase::encode(
                                multibase::Base::Base58Btc,
                                [DID_KEY_ED25519_PREFIX.to_vec(), params.public_key.0.clone()]
                                    .concat(),
                            )
                    }
                    //_ => return Some(Err(DIDKeyError::UnsupportedCurve(params.curve.clone()))),
                    _ => return None,
                }
            }
            Params::EC(ref params) => {
                let curve = match params.curve {
                    Some(ref curve) => curve,
                    None => return None,
                };
                match &curve[..] {
                    #[cfg(feature = "secp256k1")]
                    "secp256k1" => {
                        use k256::elliptic_curve::sec1::ToEncodedPoint;
                        use std::convert::TryFrom;
                        let pk = match k256::PublicKey::try_from(params) {
                            Ok(pk) => pk,
                            Err(_err) => return None,
                        };
                        "did:key:".to_string()
                            + &multibase::encode(
                                multibase::Base::Base58Btc,
                                [
                                    DID_KEY_SECP256K1_PREFIX.to_vec(),
                                    pk.to_encoded_point(true).as_bytes().to_vec(),
                                ]
                                .concat(),
                            )
                    }
                    #[cfg(feature = "secp256r1")]
                    "P-256" => {
                        use p256::elliptic_curve::sec1::ToEncodedPoint;
                        use std::convert::TryFrom;
                        let pk = match p256::PublicKey::try_from(params) {
                            Ok(pk) => pk,
                            Err(_err) => return None,
                        };
                        "did:key:".to_string()
                            + &multibase::encode(
                                multibase::Base::Base58Btc,
                                [
                                    DID_KEY_P256_PREFIX.to_vec(),
                                    pk.to_encoded_point(true).as_bytes().to_vec(),
                                ]
                                .concat(),
                            )
                    }
                    //_ => return Some(Err(DIDKeyError::UnsupportedCurve(params.curve.clone()))),
                    _ => return None,
                }
            }
            _ => return None, // _ => return Some(Err(DIDKeyError::UnsupportedKeyType)),
        };
        Some(did)
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ssi::did::Resource;
    use ssi::did_resolve::{dereference, Content, DereferencingInputMetadata};

    #[async_std::test]
    async fn from_did_key() {
        let vm = "did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH";
        let (res_meta, object, _meta) =
            dereference(&DIDKey, &vm, &DereferencingInputMetadata::default()).await;
        assert_eq!(res_meta.error, None);
        let vm = match object {
            Content::Object(Resource::VerificationMethod(vm)) => vm,
            _ => unreachable!(),
        };
        vm.public_key_jwk.unwrap();
    }

    #[async_std::test]
    #[cfg(feature = "secp256k1")]
    async fn from_did_key_secp256k1() {
        let did = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
        let (res_meta, _doc, _doc_meta) = DIDKey
            .resolve(did, &ResolutionInputMetadata::default())
            .await;
        assert_eq!(res_meta.error, None);

        let vm = "did:key:zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme#zQ3shokFTS3brHcDQrn82RUDfCZESWL1ZdCEJwekUDPQiYBme";
        let (res_meta, object, _meta) =
            dereference(&DIDKey, &vm, &DereferencingInputMetadata::default()).await;
        assert_eq!(res_meta.error, None);
        let vm = match object {
            Content::Object(Resource::VerificationMethod(vm)) => vm,
            _ => unreachable!(),
        };
        let key = vm.public_key_jwk.unwrap();

        // convert back to DID from JWK
        let did1 = DIDKey.generate(&Source::Key(&key)).unwrap();
        assert_eq!(did1, did);
    }

    #[cfg(feature = "secp256r1")]
    #[async_std::test]
    async fn from_did_key_p256() {
        // https://w3c-ccg.github.io/did-method-key/#p-256
        let did = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
        let (res_meta, _doc, _doc_meta) = DIDKey
            .resolve(did, &ResolutionInputMetadata::default())
            .await;
        assert_eq!(res_meta.error, None);

        let vm = "did:key:zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169#zDnaerDaTF5BXEavCrfRZEk316dpbLsfPDZ3WJ5hRTPFU2169";
        let (res_meta, object, _meta) =
            dereference(&DIDKey, &vm, &DereferencingInputMetadata::default()).await;
        assert_eq!(res_meta.error, None);
        let vm = match object {
            Content::Object(Resource::VerificationMethod(vm)) => vm,
            _ => unreachable!(),
        };
        let key = vm.public_key_jwk.unwrap();
        eprintln!("key {}", serde_json::to_string_pretty(&key).unwrap());

        // https://github.com/w3c-ccg/did-method-key/blob/master/test-vectors/nist-curves.json#L64-L69
        let key_expected: JWK = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "fyNYMN0976ci7xqiSdag3buk-ZCwgXU4kz9XNkBlNUI",
            "y": "hW2ojTNfH7Jbi8--CJUo3OCbH3y5n91g-IMA9MLMbTU"
        }))
        .unwrap();
        assert_eq!(key, key_expected);

        let did1 = DIDKey.generate(&Source::Key(&key)).unwrap();
        assert_eq!(did1, did);
    }

    #[async_std::test]
    async fn credential_prove_verify_did_key() {
        use ssi::vc::{get_verification_method, Credential, Issuer, LinkedDataProofOptions, URI};
        let vc_str = r###"{
            "@context": "https://www.w3.org/2018/credentials/v1",
            "id": "http://example.org/credentials/3731",
            "type": ["VerifiableCredential"],
            "issuer": "did:example:30e07a529f32d234f6181736bd3",
            "issuanceDate": "2020-08-19T21:41:50Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();

        let key = JWK::generate_ed25519().unwrap();
        let did = DIDKey.generate(&Source::Key(&key)).unwrap();
        let verification_method = get_verification_method(&did, &DIDKey).await.unwrap();
        let mut issue_options = LinkedDataProofOptions::default();
        vc.issuer = Some(Issuer::URI(URI::String(did.clone())));
        issue_options.verification_method = Some(verification_method);
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDKey).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer is verified
        vc.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(vc.verify(None, &DIDKey).await.errors.len() > 0);
    }

    #[async_std::test]
    #[cfg(feature = "secp256k1")]
    async fn credential_prove_verify_did_key_secp256k1() {
        use serde_json::json;
        use ssi::vc::{get_verification_method, Credential, Issuer, LinkedDataProofOptions, URI};
        let key = JWK::generate_secp256k1().unwrap();
        let did = DIDKey.generate(&Source::Key(&key)).unwrap();
        let mut vc: Credential = serde_json::from_value(json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": ["VerifiableCredential"],
            "issuer": did.clone(),
            "issuanceDate": "2021-02-18T20:17:46Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }))
        .unwrap();
        vc.validate_unsigned().unwrap();

        let verification_method = get_verification_method(&did, &DIDKey).await.unwrap();
        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some(verification_method);
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDKey).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer is verified
        vc.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(vc.verify(None, &DIDKey).await.errors.len() > 0);
    }

    #[async_std::test]
    #[cfg(feature = "secp256r1")]
    async fn credential_prove_verify_did_key_p256() {
        use serde_json::json;
        use ssi::vc::{get_verification_method, Credential, Issuer, LinkedDataProofOptions, URI};
        let key = JWK::generate_p256().unwrap();
        let did = DIDKey.generate(&Source::Key(&key)).unwrap();
        let mut vc: Credential = serde_json::from_value(json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": ["VerifiableCredential"],
            "issuer": did.clone(),
            "issuanceDate": "2021-02-18T20:17:46Z",
            "credentialSubject": {
                "id": "did:example:d23dd687a7dc6787646f2eb98d0"
            }
        }))
        .unwrap();
        vc.validate_unsigned().unwrap();

        let verification_method = get_verification_method(&did, &DIDKey).await.unwrap();
        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some(verification_method);
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDKey).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer is verified
        vc.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(vc.verify(None, &DIDKey).await.errors.len() > 0);
    }
}
