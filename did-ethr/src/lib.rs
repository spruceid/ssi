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

/// did:ethr DID Method
///
/// [Specification](https://github.com/decentralized-identity/ethr-did-resolver/)
pub struct DIDEthr;

fn parse_did(did: &str) -> Option<(i64, String)> {
    let (network, address) = match did.split(':').collect::<Vec<&str>>().as_slice() {
        ["did", "ethr", address] => ("mainnet".to_string(), address.to_string()),
        ["did", "ethr", network, address] => (network.to_string(), address.to_string()),
        _ => return None,
    };
    if address.len() != 42 {
        return None;
    }
    let chain_id = match &network[..] {
        "mainnet" => 1,
        "morden" => 2,
        "ropsten" => 3,
        "rinkeby" => 4,
        "goerli" => 5,
        "kovan" => 42,
        network_chain_id if network_chain_id.starts_with("0x") => {
            match i64::from_str_radix(&network_chain_id[2..], 16) {
                Ok(chain_id) => chain_id,
                Err(_) => return None,
            }
        }
        _ => {
            return None;
        }
    };
    Some((chain_id, address))
}

#[async_trait]
impl DIDResolver for DIDEthr {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let (chain_id, address) = match parse_did(did) {
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
            chain_id: format!("eip155:{}", chain_id),
        };
        let vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some("controller".to_string()),
            ..Default::default()
        };
        let eip712vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some("Eip712Method2021".to_string()),
            ..Default::default()
        };
        let vm = VerificationMethod::Map(VerificationMethodMap {
            id: vm_didurl.to_string(),
            type_: "EcdsaSecp256k1RecoveryMethod2020".to_string(),
            controller: did.to_string(),
            blockchain_account_id: Some(blockchain_account_id.to_string()),
            ..Default::default()
        });
        let eip712vm = VerificationMethod::Map(VerificationMethodMap {
            id: eip712vm_didurl.to_string(),
            type_: "Eip712Method2021".to_string(),
            controller: did.to_string(),
            blockchain_account_id: Some(blockchain_account_id.to_string()),
            ..Default::default()
        });

        let doc = Document {
            context: Contexts::One(Context::URI(DEFAULT_CONTEXT.to_string())),
            id: did.to_string(),
            authentication: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            assertion_method: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            // TODO: authentication/assertion_method?
            verification_method: Some(vec![vm, eip712vm]),
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

impl DIDMethod for DIDEthr {
    fn name(&self) -> &'static str {
        return "ethr";
    }

    fn generate(&self, source: &Source) -> Option<String> {
        let jwk = match source {
            Source::Key(jwk) => jwk,
            _ => return None,
        };
        let hash = match ssi::keccak_hash::hash_public_key(jwk) {
            Ok(hash) => hash,
            _ => return None,
        };
        let did = format!("did:ethr:{}", hash);
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
    fn jwk_to_did_ethr() {
        let jwk: JWK = serde_json::from_value(json!({
            "alg": "ES256K-R",
            "kty": "EC",
            "crv": "secp256k1",
            "x": "yclqMZ0MtyVkKm1eBh2AyaUtsqT0l5RJM3g4SzRT96A",
            "y": "yQzUwKnftWCJPGs-faGaHiYi1sxA6fGJVw2Px_LCNe8",
        }))
        .unwrap();
        let did = DIDEthr.generate(&Source::Key(&jwk)).unwrap();
        assert_eq!(did, "did:ethr:0x2fbf1be19d90a29aea9363f4ef0b6bf1c4ff0758");
    }

    #[tokio::test]
    async fn resolve_did_ethr() {
        // https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#create-register
        let (res_meta, doc_opt, _meta_opt) = DIDEthr
            .resolve(
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                &ResolutionInputMetadata::default(),
            )
            .await;
        assert_eq!(res_meta.error, None);
        let doc = doc_opt.unwrap();
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            json!({
              "@context": "https://www.w3.org/ns/did/v1",
              "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
              "verificationMethod": [{
                "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                "blockchainAccountId": "0xb9c5714089478a327f09197987f16f9e5d936e8a@eip155:1"
              }, {
                "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#Eip712Method2021",
                "type": "Eip712Method2021",
                "controller": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                "blockchainAccountId": "0xb9c5714089478a327f09197987f16f9e5d936e8a@eip155:1"
              }],
              "authentication": [
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller"
              ],
              "assertionMethod": [
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller"
              ]
            })
        );
    }

    #[tokio::test]
    async fn credential_prove_verify_did_ethr() {
        eprintln!("with EcdsaSecp256k1RecoveryMethod2020...");
        credential_prove_verify_did_ethr2(false).await;
        eprintln!("with Eip712Method2021...");
        credential_prove_verify_did_ethr2(true).await;
    }

    async fn credential_prove_verify_did_ethr2(eip712: bool) {
        use ssi::vc::{Credential, Issuer, LinkedDataProofOptions, URI};

        let key: JWK = serde_json::from_value(json!({
            "alg": "ES256K-R",
            "kty": "EC",
            "crv": "secp256k1",
            "x": "yclqMZ0MtyVkKm1eBh2AyaUtsqT0l5RJM3g4SzRT96A",
            "y": "yQzUwKnftWCJPGs-faGaHiYi1sxA6fGJVw2Px_LCNe8",
            "d": "meTmccmR_6ZsOa2YuTTkKkJ4ZPYsKdAH1Wx_RRf2j_E"
        }))
        .unwrap();
        let did = DIDEthr.generate(&Source::Key(&key)).unwrap();
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
        if eip712 {
            issue_options.verification_method = Some(did.to_string() + "#Eip712Method2021");
        } else {
            issue_options.verification_method = Some(did.to_string() + "#controller");
        }
        eprintln!("vm {:?}", issue_options.verification_method);
        let vc_no_proof = vc.clone();
        let proof = vc.generate_proof(&key, &issue_options).await.unwrap();
        println!("{}", serde_json::to_string_pretty(&proof).unwrap());
        vc.add_proof(proof);
        vc.validate().unwrap();
        let verification_result = vc.verify(None, &DIDEthr).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
        assert!(vc_bad_issuer.verify(None, &DIDEthr).await.errors.len() > 0);

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
        assert!(vc_wrong_key.verify(None, &DIDEthr).await.errors.len() > 0);

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
        let vp_verification_result = vp.verify(Some(vp_issue_options.clone()), &DIDEthr).await;
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
        let vp_verification_result = vp1.verify(Some(vp_issue_options), &DIDEthr).await;
        println!("{:#?}", vp_verification_result);
        assert!(vp_verification_result.errors.len() >= 1);

        // test that holder is verified
        let mut vp2 = vp.clone();
        vp2.holder = Some(URI::String("did:example:bad".to_string()));
        assert!(vp2.verify(None, &DIDEthr).await.errors.len() > 0);
    }

    #[tokio::test]
    async fn credential_verify_eip712vm() {
        use ssi::vc::Credential;
        let vc: Credential = serde_json::from_str(include_str!("../tests/vc.jsonld")).unwrap();
        eprintln!("vc {:?}", vc);
        let verification_result = vc.verify(None, &DIDEthr).await;
        println!("{:#?}", verification_result);
        assert!(verification_result.errors.is_empty());
    }
}
