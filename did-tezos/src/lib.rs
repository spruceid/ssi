use ssi::blakesig::hash_public_key;
use ssi::did::{
    Context, Contexts, DIDMethod, Document, Source, VerificationMethod, VerificationMethodMap,
    DEFAULT_CONTEXT, DIDURL,
};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, ERROR_INVALID_DID,
    TYPE_DID_LD_JSON,
};

use async_trait::async_trait;
use chrono::prelude::*;
use serde_json;
use std::collections::BTreeMap;

/// did:tz DID Method
///
/// [Specification](https://github.com/spruceid/did-tezos/)
pub struct DIDTz;

#[async_trait]
impl DIDResolver for DIDTz {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
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

        let (_curve, proof_type) = match prefix_to_curve_type(&address[0..3]) {
            Some(addr) => addr,
            None => {
                return (
                    ResolutionMetadata::from_error(&ERROR_INVALID_DID),
                    None,
                    None,
                )
            }
        };

        let mut property_set = BTreeMap::new();
        property_set.insert(
            "blockchainAccountId".to_string(),
            serde_json::Value::String(format!("{}@tezos:{}", address.to_string(), network)),
        );
        let vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some("blockchainAccountId".to_string()),
            ..Default::default()
        };

        let doc = Document {
            context: Contexts::One(Context::URI(DEFAULT_CONTEXT.to_string())),
            id: did.to_string(),
            authentication: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            assertion_method: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            verification_method: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: String::from(vm_didurl),
                type_: proof_type.to_string(),
                controller: did.to_string(),
                property_set: Some(property_set),
                ..Default::default()
            })]),
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

// addr must be at least 4 bytes
fn prefix_to_curve_type(prefix: &str) -> Option<(&'static str, &'static str)> {
    let curve_type = match prefix {
        "tz1" => (
            "Ed25519",
            "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
        ),
        // "tz2" => ("secp256k1", "TODO"),
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi::did_resolve::ResolutionInputMetadata;
    use ssi::jwk::JWK;

    const TZ1: &'static str = "did:tz:tz1VFda3KmzRecjsYptDq5bJh1M1NyAqgBJf";
    const TZ1_JSON: &'static str = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"GvidwVqGgicuL68BRM89OOtDzK1gjs8IqUXFkjKkm8Iwg18slw==\",\"d\":\"K44dAtJ-MMl-JKuOupfcGRPI5n3ZVH_Gk65c6Rcgn_IV28987PMw_b6paCafNOBOi5u-FZMgGJd3mc5MkfxfwjCrXQM-\"}";

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
        assert_eq!(res_meta.error, None);
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
    async fn credential_prove_verify_did_tz() {
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
            verifiable_credential: OneOrMany::One(CredentialOrJWT::Credential(vc)),
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
}
