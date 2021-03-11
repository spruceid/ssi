use async_trait::async_trait;
use chrono::prelude::*;

use ssi::caip10::BlockchainAccountId;
use ssi::did::{
    Context, Contexts, DIDMethod, Document, Source, VerificationMethod, VerificationMethodMap,
    DEFAULT_CONTEXT, DIDURL,
};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    TYPE_DID_LD_JSON,
};
use ssi::jwk::{Base64urlUInt, OctetParams, Params, JWK};

/// did:sol DID Method
pub struct DIDSol;

fn parse_did(did: &str) -> Option<(String, Vec<u8>)> {
    let address = match did.split(':').collect::<Vec<&str>>().as_slice() {
        ["did", "sol", address] => address.to_string(),
        _ => return None,
    };
    let bytes = match bs58::decode(&address).into_vec() {
        Ok(bytes) => bytes,
        Err(_) => return None,
    };
    if bytes.len() != 32 {
        return None;
    }
    Some((address, bytes))
}

#[cfg_attr(target_arch = "wasm32", async_trait(?Send))]
#[cfg_attr(not(target_arch = "wasm32"), async_trait)]
impl DIDResolver for DIDSol {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let (address, public_key_bytes) = match parse_did(did) {
            Some(parsed) => parsed,
            None => {
                return (
                    ResolutionMetadata::from_error(&ERROR_INVALID_DID),
                    None,
                    None,
                )
            }
        };
        let blockchain_account_id = BlockchainAccountId {
            account_address: address,
            chain_id: "solana".to_string(), // TODO: standardize
        };
        let vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some("controller".to_string()),
            ..Default::default()
        };
        let solvm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some("SolanaMethod2021".to_string()),
            ..Default::default()
        };
        let pk_jwk = JWK {
            params: Params::OKP(OctetParams {
                curve: "Ed25519".to_string(),
                public_key: Base64urlUInt(public_key_bytes),
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
        };
        let vm = VerificationMethod::Map(VerificationMethodMap {
            id: vm_didurl.to_string(),
            type_: "Ed25519VerificationKey2018".to_string(),
            public_key_jwk: Some(pk_jwk.clone()),
            controller: did.to_string(),
            blockchain_account_id: Some(blockchain_account_id.to_string()),
            ..Default::default()
        });
        let solvm = VerificationMethod::Map(VerificationMethodMap {
            id: solvm_didurl.to_string(),
            type_: "SolanaMethod2021".to_string(),
            public_key_jwk: Some(pk_jwk.clone()),
            controller: did.to_string(),
            blockchain_account_id: Some(blockchain_account_id.to_string()),
            ..Default::default()
        });

        let doc = Document {
            context: Contexts::One(Context::URI(DEFAULT_CONTEXT.to_string())),
            id: did.to_string(),
            authentication: Some(vec![
                VerificationMethod::DIDURL(vm_didurl.clone()),
                VerificationMethod::DIDURL(solvm_didurl.clone()),
            ]),
            assertion_method: Some(vec![
                VerificationMethod::DIDURL(vm_didurl.clone()),
                VerificationMethod::DIDURL(solvm_didurl.clone()),
            ]),
            // TODO: authentication/assertion_method?
            verification_method: Some(vec![vm, solvm]),
            ..Default::default()
        };

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

impl DIDMethod for DIDSol {
    fn name(&self) -> &'static str {
        return "sol";
    }

    fn generate(&self, source: &Source) -> Option<String> {
        let jwk = match source {
            Source::Key(jwk) => jwk,
            _ => return None,
        };
        let did = match jwk.params {
            Params::OKP(ref params) if params.curve == "Ed25519" => {
                let addr = bs58::encode(&params.public_key.0).into_string();
                format!("did:sol:{}", addr)
            }
            _ => {
                dbg!(&jwk.params);
                return None;
            }
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
    use serde_json::json;
    use ssi::did_resolve::ResolutionInputMetadata;
    use ssi::jwk::JWK;

    #[test]
    fn key_to_did_sol() {
        let jwk: JWK = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "qDkywhH-S6nNxQhA6SHKsoFW7A2gX-X0b3TtwVBMHm8"
        }))
        .unwrap();
        let did = DIDSol.generate(&Source::Key(&jwk)).unwrap();
        assert_eq!(did, "did:sol:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev");
    }

    #[tokio::test]
    async fn resolve_did_sol() {
        let (res_meta, doc_opt, _meta_opt) = DIDSol
            .resolve(
                "did:sol:CKg5d12Jhpej1JqtmxLJgaFqqeYjxgPqToJ4LBdvG9Ev",
                &ResolutionInputMetadata::default(),
            )
            .await;
        assert_eq!(res_meta.error, None);
        let doc = doc_opt.unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        let doc_expected: Document =
            serde_json::from_str(include_str!("../tests/did.jsonld")).unwrap();
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            serde_json::to_value(doc_expected).unwrap()
        );
    }

    #[tokio::test]
    async fn credential_prove_verify_did_sol() {
        eprintln!("with Ed25519VerificationKey2018...");
        credential_prove_verify_did_sol_1(false).await;
        eprintln!("with SolanaMethod2021...");
        credential_prove_verify_did_sol_1(true).await;
    }

    async fn credential_prove_verify_did_sol_1(solvm: bool) {
        use ssi::vc::{Credential, Issuer, LinkedDataProofOptions, URI};

        let key: JWK = serde_json::from_value(json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "YwT3Ce5YqSjXK_bmI35kPEmzZT2WtUSE6XTllrLUGbQ",
            "d": "ybizk5eZVSZiUtWURVdp-dx9JWtiP9uJaWfLupGU2ZU"
        }))
        .unwrap();
        let did = DIDSol.generate(&Source::Key(&key)).unwrap();
        eprintln!("did: {}", did);
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
        if solvm {
            issue_options.verification_method = Some(did.to_string() + "#SolanaMethod2021");
        } else {
            issue_options.verification_method = Some(did.to_string() + "#controller");
        }
        eprintln!("vm {:?}", issue_options.verification_method);
        let vc_no_proof = vc.clone();
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDSol).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(vc_bad_issuer.verify(None, &DIDSol).await.errors.len() > 0);

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
        assert!(vc_wrong_key.verify(None, &DIDSol).await.errors.len() > 0);

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
        vp_issue_options.verification_method = Some(did.to_string() + "#controller");
        vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
        let vp_proof = vp.generate_proof(&key, &vp_issue_options).await.unwrap();
        vp.add_proof(vp_proof);
        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        vp.validate().unwrap();
        let vp_verification_result = vp.verify(Some(vp_issue_options.clone()), &DIDSol).await;
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
        let vp_verification_result = vp1.verify(Some(vp_issue_options), &DIDSol).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);

        // test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:example:bad".to_string()));
        assert!(vp2.verify(None, &DIDSol).await.errors.len() > 0);
    }

    /*
    #[tokio::test]
    async fn credential_verify_eip712vm() {
        use ssi::vc::Credential;
        let vc: Credential = serde_json::from_str(include_str!("../tests/vc.jsonld")).unwrap();
        eprintln!("vc {:?}", vc);
        let verification_result = vc.verify(None, &DIDSol).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }
    */
}
