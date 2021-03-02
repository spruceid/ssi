use ssi::blakesig::hash_public_key;
use ssi::did::{
    Context, Contexts, DIDMethod, Document, Service, Source, VerificationMethod,
    VerificationMethodMap, DEFAULT_CONTEXT, DIDURL,
};
use ssi::did_resolve::Metadata;
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    TYPE_DID_LD_JSON,
};
use ssi::jwk::{Base64urlUInt, ECParams, OctetParams, Params, JWK};
use ssi::jws::decode_verify;

mod explorer;
use anyhow::{anyhow, Result};
use async_trait::async_trait;
use chrono::prelude::*;
use json_patch::patch;
use serde::Deserialize;
use tezedge_client::{crypto::FromBase58Check, PublicKey};

/// did:tz DID Method
///
/// [Specification](https://github.com/spruceid/did-tezos/)
pub struct DIDTz;

#[async_trait]
impl DIDResolver for DIDTz {
    async fn resolve(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let (network, address) = match did.split(':').collect::<Vec<&str>>().as_slice() {
            ["did", "tz", address] if address.len() == 36 => {
                ("mainnet".to_string(), address.to_string())
            }
            ["did", "tz", network, address] if address.len() == 36 => {
                (network.to_string(), address.to_string())
            }
            _ => {
                return (
                    ResolutionMetadata::from_error(&ERROR_INVALID_DID),
                    None,
                    None,
                )
            }
        };

        let prefix = &address[0..3];
        let (_curve, proof_type) = match prefix_to_curve_type(prefix) {
            Some(addr) => addr,
            None => {
                return (
                    ResolutionMetadata::from_error(&ERROR_INVALID_DID),
                    None,
                    None,
                )
            }
        };

        let vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some("blockchainAccountId".to_string()),
            ..Default::default()
        };

        let mut doc = DIDTz::tier1_derivation(did, &vm_didurl, proof_type, &address, &network);

        let service = match DIDTz::tier2_resolution(did, &address, &network).await {
            Ok(s) => s,
            Err(e) => {
                return (
                    ResolutionMetadata {
                        error: Some(e.to_string()),
                        ..Default::default()
                    },
                    Some(doc),
                    None,
                )
            }
        };
        doc.service = Some(vec![service]);

        if let Some(s) = &input_metadata.property_set {
            let public_key = match s.get("public_key") {
                Some(pk) => match pk {
                    Metadata::String(pks) => Some(pks.clone()),
                    _ => {
                        return (
                            ResolutionMetadata {
                                error: Some("Public key is not a string.".to_string()),
                                ..Default::default()
                            },
                            Some(doc),
                            None,
                        );
                    }
                },
                None => None,
            };

            if let Some(updates_metadata) = s.get("updates") {
                let updates: Updates = match serde_json::to_value(updates_metadata) {
                    Ok(u) => match serde_json::from_value(u) {
                        Ok(uu) => uu,
                        Err(e) => {
                            return (
                                ResolutionMetadata {
                                    error: Some(e.to_string()),
                                    ..Default::default()
                                },
                                Some(doc),
                                None,
                            );
                        }
                    },
                    Err(e) => {
                        return (
                            ResolutionMetadata {
                                error: Some(e.to_string()),
                                ..Default::default()
                            },
                            Some(doc),
                            None,
                        );
                    }
                };
                if let Err(e) = self
                    .tier3_updates(prefix, &mut doc, updates, public_key)
                    .await
                {
                    return (
                        ResolutionMetadata {
                            error: Some(e.to_string()),
                            ..Default::default()
                        },
                        Some(doc),
                        None,
                    );
                }
            }
        }

        let res_meta = ResolutionMetadata {
            content_type: Some(TYPE_DID_LD_JSON.to_string()),
            ..Default::default()
        };

        let doc_meta = DocumentMetadata {
            created: Some(Utc::now()),
            ..Default::default()
        };

        (res_meta, Some(doc), Some(doc_meta))
    }

    fn to_did_method(&self) -> Option<&dyn DIDMethod> {
        Some(self)
    }
}

// addr must be at least 4 bytes
fn prefix_to_curve_type(prefix: &str) -> Option<(&'static str, &'static str)> {
    let curve_type = match prefix {
        "tz1" => (
            "Ed25519",
            "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
        ),
        "tz2" => ("secp256k1", "EcdsaSecp256k1RecoveryMethod2020"),
        // "tz3" => ("P-256", "TODO"),
        _ => return None,
    };
    Some(curve_type)
}

impl DIDMethod for DIDTz {
    fn name(&self) -> &'static str {
        return "tz";
    }

    fn generate(&self, source: &Source) -> Option<String> {
        let jwk = match source {
            Source::Key(jwk) => jwk,
            _ => return None,
        };
        let hash = match hash_public_key(jwk) {
            Ok(hash) => hash,
            _ => return None,
        };
        let did = "did:tz:".to_string() + &hash;
        Some(did)
    }

    fn to_resolver(&self) -> &dyn DIDResolver {
        self
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
struct SignedIetfJsonPatchPayload {
    ietf_json_patch: serde_json::Value,
}

#[derive(Deserialize)]
#[serde(rename_all = "kebab-case")]
#[serde(tag = "type", content = "value")]
enum Updates {
    SignedIetfJsonPatch(Vec<String>),
}

impl DIDTz {
    fn tier1_derivation(
        did: &str,
        vm_didurl: &DIDURL,
        proof_type: &str,
        address: &str,
        network: &str,
    ) -> Document {
        Document {
            context: Contexts::One(Context::URI(DEFAULT_CONTEXT.to_string())),
            id: did.to_string(),
            authentication: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            assertion_method: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            verification_method: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: String::from(vm_didurl.clone()),
                type_: proof_type.to_string(),
                controller: did.to_string(),
                blockchain_account_id: Some(format!("{}@tezos:{}", address.to_string(), network)),
                ..Default::default()
            })]),
            ..Default::default()
        }
    }

    async fn tier2_resolution(did: &str, address: &str, network: &str) -> Result<Service> {
        let did_manager = explorer::retrieve_did_manager(address, network).await?;
        Ok(explorer::execute_service_view(did, &did_manager, network).await?)
    }

    async fn tier3_updates(
        &self,
        prefix: &str,
        doc: &mut Document,
        updates: Updates,
        public_key: Option<String>,
    ) -> Result<()> {
        match updates {
            Updates::SignedIetfJsonPatch(patches) => {
                for jws in patches {
                    let mut doc_json = serde_json::to_value(&mut *doc)?;
                    let curve = prefix_to_curve_type(prefix)
                        .ok_or(anyhow!("Unsupported curve."))?
                        .0
                        .to_string();
                    let jwk = match prefix {
                        "tz1" => {
                            let pk = match public_key {
                                Some(ref p) => {
                                    PublicKey::from_base58check(&p.clone()).unwrap().as_ref()[..]
                                        .to_vec()
                                }
                                None => return Err(anyhow!("Need public key for signed patches")),
                            };
                            JWK {
                                params: Params::OKP(OctetParams {
                                    curve,
                                    public_key: Base64urlUInt(pk),
                                    private_key: None,
                                }),
                                public_key_use: None,
                                key_operations: None,
                                algorithm: None,
                                key_id: None,
                                x509_url: None,
                                x509_thumbprint_sha1: None,
                                x509_certificate_chain: None,
                                x509_thumbprint_sha256: None,
                            }
                        }
                        "tz2" => {
                            // TODO use tezedge_client when it handles tz2
                            let pk = match public_key {
                                Some(ref p) => p.from_base58check().unwrap()[4..].to_vec(),
                                None => return Err(anyhow!("Need public key for signed patches")),
                            };
                            JWK {
                                // TODO I don't think the coordinates mean anything in compressed
                                // form
                                params: Params::EC(ECParams {
                                    curve: Some("secp256k1".to_string()),
                                    x_coordinate: Some(Base64urlUInt(pk[0..17].to_vec())),
                                    y_coordinate: Some(Base64urlUInt(pk[17..33].to_vec())),
                                    ecc_private_key: None,
                                }),
                                public_key_use: None,
                                key_operations: None,
                                algorithm: None,
                                key_id: None,
                                x509_url: None,
                                x509_thumbprint_sha1: None,
                                x509_certificate_chain: None,
                                x509_thumbprint_sha256: None,
                            }
                        }
                        p => return Err(anyhow!("{} not supported yet.", p)),
                    };
                    let (_, patch_) = decode_verify(&jws, &jwk)?;
                    patch(
                        &mut doc_json,
                        &serde_json::from_slice(
                            &serde_json::from_slice::<SignedIetfJsonPatchPayload>(&patch_)?
                                .ietf_json_patch
                                .to_string()
                                .as_bytes(),
                        )?,
                    )?;
                    *doc = serde_json::from_value(doc_json)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi::did::ServiceEndpoint;
    use ssi::did_resolve::ResolutionInputMetadata;
    use ssi::jwk::JWK;
    use ssi::jws::encode_sign;
    use ssi::one_or_many::OneOrMany;
    use std::collections::BTreeMap as Map;
    use tezedge_client::PrivateKey;

    const TZ1: &'static str = "did:tz:tz1VFda3KmzRecjsYptDq5bJh1M1NyAqgBJf";
    const TZ1_JSON: &'static str = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"GvidwVqGgicuL68BRM89OOtDzK1gjs8IqUXFkjKkm8Iwg18slw==\",\"d\":\"K44dAtJ-MMl-JKuOupfcGRPI5n3ZVH_Gk65c6Rcgn_IV28987PMw_b6paCafNOBOi5u-FZMgGJd3mc5MkfxfwjCrXQM-\"}";

    const LIVE_TZ1: &str = "tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq";
    const LIVE_NETWORK: &str = "delphinet";
    const JSON_PATCH: &str = r#"{"ietf-json-patch": [
                                        {
                                            "op": "add",
                                            "path": "/service/1",
                                            "value": {
                                                "id": "test_service_id",
                                                "type": "test_service",
                                                "serviceEndpoint": "test_service_endpoint"
                                            }
                                        }
                                    ]}"#;

    #[test]
    fn jwk_to_did_tezos() {
        // TODO: add tz2 and tz3 test cases
        let jwk: JWK = serde_json::from_str(&TZ1_JSON).unwrap();
        let tz1 = DIDTz.generate(&Source::Key(&jwk)).unwrap();
        assert_eq!(tz1, TZ1);
    }

    #[tokio::test]
    async fn test_derivation() {
        let (res_meta, doc_opt, _meta_opt) = DIDTz
            .resolve(
                "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
                &ResolutionInputMetadata::default(),
            )
            .await;
        // assert_eq!(res_meta.error, None);
        let doc = doc_opt.unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            json!({
              "@context": "https://www.w3.org/ns/did/v1",
              "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
              "verificationMethod": [{
                "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId",
                "type": "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                "controller": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
                "blockchainAccountId": "tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8@tezos:mainnet"
              }],
              "authentication": [
                "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId"
              ],
              "assertionMethod": [
                "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId"
              ]
            })
        );
    }

    #[tokio::test]
    async fn test_derivation_tz2() {
        let (res_meta, doc_opt, _meta_opt) = DIDTz
            .resolve(
                "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
                &ResolutionInputMetadata::default(),
            )
            .await;
        // assert_eq!(res_meta.error, None);
        let doc = doc_opt.unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            json!({
              "@context": "https://www.w3.org/ns/did/v1",
              "id": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
              "verificationMethod": [{
                "id": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId",
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
                "blockchainAccountId": "tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq@tezos:mainnet"
              }],
              "authentication": [
                "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId"
              ],
              "assertionMethod": [
                "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId"
              ]
            })
        );
    }

    #[tokio::test]
    async fn credential_prove_verify_did_tz1() {
        use ssi::vc::{Credential, Issuer, LinkedDataProofOptions, URI};

        let vc_str = r###"{
            "@context": [
              "https://www.w3.org/2018/credentials/v1"
            ],
            "type": ["VerifiableCredential"],
            "issuer": "did:tz:tz1iY7Am8EqrewptzQXYRZDPKvYnFLzWRgBK",
            "issuanceDate": "2021-01-27T16:39:07Z",
            "credentialSubject": {
                "id": "did:example:foo"
            }
        }"###;
        let mut vc: Credential = Credential::from_json_unsigned(vc_str).unwrap();

        let key_str = include_str!("../../tests/ed25519-2020-10-18.json");
        let key: JWK = serde_json::from_str(key_str).unwrap();
        let did = DIDTz.generate(&Source::Key(&key)).unwrap();
        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some(did.to_string() + "#blockchainAccountId");
        eprintln!("vm {:?}", issue_options.verification_method);
        let vc_no_proof = vc.clone();
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDTz).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(vc_bad_issuer.verify(None, &DIDTz).await.errors.len() > 0);

        // Check that proof JWK must match proof verificationMethod
        let mut vc_wrong_key = vc_no_proof.clone();
        let other_key = JWK::generate_ed25519().unwrap();
        use ssi::ldp::ProofSuite;
        let proof_bad = ssi::ldp::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021::sign(
            &vc_no_proof,
            &issue_options,
            &other_key,
        )
        .await
        .unwrap();
        vc_wrong_key.add_proof(proof_bad);
        vc_wrong_key.validate().unwrap();
        assert!(vc_wrong_key.verify(None, &DIDTz).await.errors.len() > 0);

        // Make it into a VP
        use ssi::one_or_many::OneOrMany;
        use ssi::vc::{CredentialOrJWT, Presentation, ProofPurpose, DEFAULT_CONTEXT};
        let mut vp = Presentation {
            context: ssi::vc::Contexts::Many(vec![ssi::vc::Context::URI(ssi::vc::URI::String(
                DEFAULT_CONTEXT.to_string(),
            ))]),

            id: Some(URI::String(
                "http://example.org/presentations/3731".to_string(),
            )),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: None,
            property_set: None,
        };
        let mut vp_issue_options = LinkedDataProofOptions::default();
        vp.holder = Some(URI::String(did.to_string()));
        vp_issue_options.verification_method = Some(did.to_string() + "#blockchainAccountId");
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        eprintln!("vp: {}", serde_json::to_string_pretty(&vp).unwrap());
        let vp_proof = vp.generate_proof(&key, &vp_issue_options).await.unwrap();
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp.verify(Some(vp_issue_options.clone()), &DIDTz).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.is_empty());

        // mess with the VP proof to make verify fail
        let mut vp1 = vp.clone();
        match vp1.proof {
            Some(OneOrMany::One(ref mut proof)) => match proof.jws {
                Some(ref mut jws) => {
                    jws.insert(0, 'x');
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        let vp_verification_result = vp1.verify(Some(vp_issue_options), &DIDTz).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);

        // test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:example:bad".to_string()));
        assert!(vp2.verify(None, &DIDTz).await.errors.len() > 0);
    }

    #[tokio::test]
    #[cfg(feature = "libsecp256k1")]
    async fn credential_prove_verify_did_tz2() {
        use ssi::jwk::Algorithm;
        use ssi::vc::{Credential, Issuer, LinkedDataProofOptions, URI};

        let mut key = JWK::generate_secp256k1().unwrap();
        // mark this key as being for use with key recovery
        key.algorithm = Some(Algorithm::ES256KR);
        let did = DIDTz.generate(&Source::Key(&key)).unwrap();
        let mut vc: Credential = serde_json::from_value(json!({
            "@context": "https://www.w3.org/2018/credentials/v1",
            "type": "VerifiableCredential",
            "issuer": did.clone(),
            "issuanceDate": "2021-02-18T20:23:13Z",
            "credentialSubject": {
                "id": "did:example:foo"
            }
        }))
        .unwrap();
        vc.validate_unsigned().unwrap();
        let mut issue_options = LinkedDataProofOptions::default();
        issue_options.verification_method = Some(did.to_string() + "#blockchainAccountId");
        eprintln!("vm {:?}", issue_options.verification_method);
        let vc_no_proof = vc.clone();
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDTz).await;
        println!("{:#?}", verification_result);
        // assert!(verification_result.errors.is_empty());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(vc_bad_issuer.verify(None, &DIDTz).await.errors.len() > 0);

        // Check that proof JWK must match proof verificationMethod
        let mut vc_wrong_key = vc_no_proof.clone();
        let other_key = JWK::generate_ed25519().unwrap();
        use ssi::ldp::ProofSuite;
        let proof_bad = ssi::ldp::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021::sign(
            &vc_no_proof,
            &issue_options,
            &other_key,
        )
        .await
        .unwrap();
        vc_wrong_key.add_proof(proof_bad);
        vc_wrong_key.validate().unwrap();
        assert!(vc_wrong_key.verify(None, &DIDTz).await.errors.len() > 0);

        // Make it into a VP
        use ssi::one_or_many::OneOrMany;
        use ssi::vc::{CredentialOrJWT, Presentation, ProofPurpose, DEFAULT_CONTEXT};
        let mut vp = Presentation {
            context: ssi::vc::Contexts::Many(vec![ssi::vc::Context::URI(ssi::vc::URI::String(
                DEFAULT_CONTEXT.to_string(),
            ))]),

            id: Some(URI::String(
                "http://example.org/presentations/3731".to_string(),
            )),
            type_: OneOrMany::One("VerifiablePresentation".to_string()),
            verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
            proof: None,
            holder: None,
            property_set: None,
        };
        let mut vp_issue_options = LinkedDataProofOptions::default();
        vp.holder = Some(URI::String(did.to_string()));
        vp_issue_options.verification_method = Some(did.to_string() + "#blockchainAccountId");
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        eprintln!("vp: {}", serde_json::to_string_pretty(&vp).unwrap());
        let vp_proof = vp.generate_proof(&key, &vp_issue_options).await.unwrap();
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp.verify(Some(vp_issue_options.clone()), &DIDTz).await;
        println!("{:#?}", vp_verification_result);
        // assert!(vp_verification_result.errors.is_empty());

        // mess with the VP proof to make verify fail
        let mut vp1 = vp.clone();
        match vp1.proof {
            Some(OneOrMany::One(ref mut proof)) => match proof.jws {
                Some(ref mut jws) => {
                    jws.insert(0, 'x');
                }
                _ => unreachable!(),
            },
            _ => unreachable!(),
        }
        let vp_verification_result = vp1.verify(Some(vp_issue_options), &DIDTz).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);

        // test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:example:bad".to_string()));
        assert!(vp2.verify(None, &DIDTz).await.errors.len() > 0);
    }

    #[tokio::test]
    async fn test_json_patch_tz1() {
        let address = "tz1VSUr8wwNhLAzempoch5d6hLRiTh8Cjcjb";
        let pk = "edpkvGfYw3LyB1UcCahKQk4rF2tvbMUk8GFiTuMjL75uGXrpvKXhjn";
        let sk = "edsk3QoqBuvdamxouPhin7swCvkQNgq4jP5KZPbwWNnwdZpSpJiEbq";
        let did = format!("did:tz:{}:{}", "sandbox", address);
        let mut doc: Document = serde_json::from_value(json!({
          "@context": "https://www.w3.org/ns/did/v1",
          "id": did,
          "authentication": [{
            "id": format!("{}#blockchainAccountId", did),
            "type": "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
            "controller": did,
            "blockchainAccountId": format!("{}@tezos:{}", address, "sandbox")
          }],
          "service": [{
            "id": format!("{}#discovery", did),
            "type": "TezosDiscoveryService",
            "serviceEndpoint": "test_service"
          }]
        }))
        .unwrap();
        let public_key = PublicKey::from_base58check(pk).unwrap();
        let private_key = PrivateKey::from_base58check(sk).unwrap();
        let key = ssi::jwk::JWK {
            params: ssi::jwk::Params::OKP(ssi::jwk::OctetParams {
                curve: "Ed25519".to_string(),
                public_key: ssi::jwk::Base64urlUInt(public_key.as_ref()[..].into()),
                private_key: Some(ssi::jwk::Base64urlUInt(private_key.as_ref()[..].into())),
            }),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        let jws = encode_sign(ssi::jwk::Algorithm::EdDSA, JSON_PATCH, &key).unwrap();
        let json_update = Updates::SignedIetfJsonPatch(vec![jws.clone()]);
        DIDTz
            .tier3_updates("tz1", &mut doc, json_update, Some(pk.to_string()))
            .await
            .unwrap();
        assert_eq!(
            doc.service.unwrap()[1],
            Service {
                id: "test_service_id".to_string(),
                type_: OneOrMany::One("test_service".to_string()),
                service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
                    "test_service_endpoint".to_string()
                ))),
                property_set: Some(Map::new()) // TODO should be None
            }
        );
    }

    #[tokio::test]
    #[cfg(feature = "libsecp256k1")]
    async fn test_json_patch_tz2() {
        let address = "tz2RZoj9oqoA8bDeUoAKLjf8nLPQKmYjaj6Q";
        let pk = "sppk7bRNbJ2n9PNQo295UJiYQ8iMma8ysRH9mCRFB14yhzLCwdGay9y";
        let sk = "spsk1Uc5MDutpZmwPVeSLL2BbtCAqfrG8zbMs6dwoaeXX8kw35S474";
        let did = format!("did:tz:{}:{}", "sandbox", address);
        let mut doc: Document = serde_json::from_value(json!({
          "@context": "https://www.w3.org/ns/did/v1",
          "id": did,
          "authentication": [{
            "id": format!("{}#blockchainAccountId", did),
            "type": "EcdsaSecp256k1RecoveryMethod2020",
            "controller": did,
            "blockchainAccountId": format!("{}@tezos:{}", address, "sandbox")
          }],
          "service": [{
            "id": format!("{}#discovery", did),
            "type": "TezosDiscoveryService",
            "serviceEndpoint": "test_service"
          }]
        }))
        .unwrap();
        // let public_key = pk.from_base58check().unwrap()[4..].to_vec();
        let private_key = sk.from_base58check().unwrap()[4..].to_vec();
        let key = ssi::jwk::JWK {
            params: ssi::jwk::Params::EC(ECParams {
                curve: Some("secp256k1".to_string()),
                x_coordinate: None,
                y_coordinate: None,
                ecc_private_key: Some(Base64urlUInt(private_key)),
            }),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        let jws = encode_sign(ssi::jwk::Algorithm::ES256KR, JSON_PATCH, &key).unwrap();
        let json_update = Updates::SignedIetfJsonPatch(vec![jws.clone()]);
        DIDTz
            .tier3_updates("tz2", &mut doc, json_update, Some(pk.to_string()))
            .await
            .unwrap();
        assert_eq!(
            doc.service.unwrap()[1],
            Service {
                id: "test_service_id".to_string(),
                type_: OneOrMany::One("test_service".to_string()),
                service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
                    "test_service_endpoint".to_string()
                ))),
                property_set: Some(Map::new()) // TODO should be None
            }
        );
    }

    #[tokio::test]
    async fn test_full_resolution() {
        let jws = "eyJhbGciOiJFZERTQSJ9.eyJpZXRmLWpzb24tcGF0Y2giOiBbCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIm9wIjogImFkZCIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInBhdGgiOiAiL3NlcnZpY2UvMSIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInZhbHVlIjogewogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAiaWQiOiAidGVzdF9zZXJ2aWNlX2lkIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInR5cGUiOiAidGVzdF9zZXJ2aWNlIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInNlcnZpY2VFbmRwb2ludCI6ICJ0ZXN0X3NlcnZpY2VfZW5kcG9pbnQiCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICBdfQ.tEUMFJzH557aHuD3UgXU7Wf1vcEI-ASdt1KeAYiejpa-FURWJ5aUjbfR3PAJfv4BTykcdYuwyM-3cJAsg4g-Cw".to_string();
        let input_metadata: ResolutionInputMetadata = serde_json::from_value(
            json!({"updates": {"type": "signed-ietf-json-patch", "value": [jws]},
                   "public_key": "edpkthtzpq4e8AhtjZ6BPK63iLfqpH7rzjDVbjxjbTuv3kMoGQi26A"}),
        )
        .unwrap();
        let live_did = format!("did:tz:{}:{}", LIVE_NETWORK, LIVE_TZ1);
        let (res_meta, res_doc, _res_doc_meta) = DIDTz.resolve(&live_did, &input_metadata).await;
        assert_eq!(res_meta.error, None);
        let d = res_doc.unwrap();
        let expected = Document {
            id: live_did.clone(),
            verification_method: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: format!("{}#blockchainAccountId", live_did),
                type_: "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021".to_string(),
                blockchain_account_id: Some(format!("{}@tezos:{}", LIVE_TZ1, LIVE_NETWORK)),
                controller: live_did.clone(),
                property_set: Some(Map::new()), // TODO should be None
                ..Default::default()
            })]),
            service: Some(vec![
                Service {
                    id: format!("{}#discovery", live_did),
                    type_: OneOrMany::One("TezosDiscoveryService".to_string()),
                    service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
                        "test_service2".to_string(),
                    ))),
                    property_set: Some(Map::new()), // TODO should be None
                },
                Service {
                    id: "test_service_id".to_string(),
                    type_: OneOrMany::One("test_service".to_string()),
                    service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
                        "test_service_endpoint".to_string(),
                    ))),
                    property_set: Some(Map::new()),
                },
            ]),
            ..Default::default()
        };
        assert_eq!(d.id, expected.id);
        assert_eq!(d.controller, expected.controller);
        assert_eq!(d.verification_method, expected.verification_method);
        assert_eq!(d.service, expected.service);
        // assert_eq!(d, expected);
    }
}
