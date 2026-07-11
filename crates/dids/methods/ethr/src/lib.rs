mod abi;
mod events;
mod json_ld_context;
mod network;
mod provider;
mod resolver;
mod vm;

pub use network::NetworkChain;
pub use provider::{BlockRef, EthProvider, Log, LogFilter, NetworkConfig};
pub use resolver::DIDEthr;
pub use vm::{VerificationMethod, VerificationMethodType};

#[cfg(test)]
mod tests {
    use super::*;
    use iref::IriBuf;
    use serde_json::json;
    use ssi_claims::{
        data_integrity::{
            signing::AlterSignature, AnyInputSuiteOptions, AnySuite, CryptographicSuite,
            ProofOptions,
        },
        vc::{
            syntax::NonEmptyVec,
            v1::{JsonCredential, JsonPresentation},
        },
        VerificationParameters,
    };
    use ssi_dids_core::{did, DIDResolver};
    use ssi_jwk::JWK;
    use ssi_verification_methods_core::{ProofPurpose, ReferenceOrOwned, SingleSecretSigner};
    use static_iref::uri;

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
        let did = DIDEthr::generate(&jwk).unwrap();
        assert_eq!(did, "did:ethr:0x2fbf1be19d90a29aea9363f4ef0b6bf1c4ff0758");
    }

    #[tokio::test]
    async fn resolve_did_ethr_addr() {
        // https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#create-register
        let resolver = DIDEthr::<()>::default();
        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap()
            .document;
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            json!({
              "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                  "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                  "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020",
                  "Eip712Method2021": "https://w3id.org/security#Eip712Method2021"
                }
              ],
              "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
              "verificationMethod": [{
                "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
                "type": "EcdsaSecp256k1RecoveryMethod2020",
                "controller": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                "blockchainAccountId": "eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"
              }, {
                "id": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#Eip712Method2021",
                "type": "Eip712Method2021",
                "controller": "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a",
                "blockchainAccountId": "eip155:1:0xb9c5714089478a327f09197987f16f9e5d936e8a"
              }],
              "authentication": [
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#Eip712Method2021"
              ],
              "assertionMethod": [
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#controller",
                "did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a#Eip712Method2021"
              ]
            })
        );
    }

    #[tokio::test]
    async fn resolve_did_ethr_pk() {
        let resolver = DIDEthr::<()>::default();
        let doc = resolver
            .resolve(did!(
                "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479"
            ))
            .await
            .unwrap()
            .document;
        eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
        let doc_expected: serde_json::Value =
            serde_json::from_str(include_str!("../tests/did-pk.jsonld")).unwrap();
        assert_eq!(
            serde_json::to_value(doc).unwrap(),
            serde_json::to_value(doc_expected).unwrap()
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
        let didethr = DIDEthr::<()>::default().into_vm_resolver();
        let verifier = VerificationParameters::from_resolver(&didethr);
        let key: JWK = serde_json::from_value(json!({
            "alg": "ES256K-R",
            "kty": "EC",
            "crv": "secp256k1",
            "x": "yclqMZ0MtyVkKm1eBh2AyaUtsqT0l5RJM3g4SzRT96A",
            "y": "yQzUwKnftWCJPGs-faGaHiYi1sxA6fGJVw2Px_LCNe8",
            "d": "meTmccmR_6ZsOa2YuTTkKkJ4ZPYsKdAH1Wx_RRf2j_E"
        }))
        .unwrap();

        let did = DIDEthr::generate(&key).unwrap();
        eprintln!("did: {}", did);

        let cred = JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-02-18T20:23:13Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:example:foo"
            })),
        );

        let verification_method = if eip712 {
            ReferenceOrOwned::Reference(IriBuf::new(format!("{did}#Eip712Method2021")).unwrap())
        } else {
            ReferenceOrOwned::Reference(IriBuf::new(format!("{did}#controller")).unwrap())
        };

        let suite = AnySuite::pick(&key, Some(&verification_method)).unwrap();
        let issue_options = ProofOptions::new(
            "2021-02-18T20:23:13Z".parse().unwrap(),
            verification_method,
            ProofPurpose::Assertion,
            AnyInputSuiteOptions::default(),
        );

        eprintln!("vm {:?}", issue_options.verification_method);
        let signer = SingleSecretSigner::new(key).into_local();
        let vc = suite
            .sign(cred.clone(), &didethr, &signer, issue_options.clone())
            .await
            .unwrap();
        println!(
            "proof: {}",
            serde_json::to_string_pretty(&vc.proofs).unwrap()
        );
        if eip712 {
            assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "0xd3f4a049551fd25c7fb0789c7303be63265e8ade2630747de3807710382bbb7a25b0407e9f858a771782c35b4f487f4337341e9a4375a073730bda643895964e1b")
        } else {
            assert_eq!(vc.proofs.first().unwrap().signature.as_ref(), "eyJhbGciOiJFUzI1NkstUiIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..nwNfIHhCQlI-j58zgqwJgX2irGJNP8hqLis-xS16hMwzs3OuvjqzZIHlwvdzDMPopUA_Oq7M7Iql2LNe0B22oQE");
        }
        assert!(vc.verify(&verifier).await.unwrap().is_ok());

        // test that issuer property is used for verification
        let mut vc_bad_issuer = vc.clone();
        vc_bad_issuer.issuer = uri!("did:pkh:example:bad").to_owned().into();

        // It should fail.
        assert!(vc_bad_issuer.verify(&verifier).await.unwrap().is_err());

        // Check that proof JWK must match proof verificationMethod
        let wrong_key = JWK::generate_secp256k1();
        let wrong_signer = SingleSecretSigner::new(wrong_key.clone()).into_local();
        let vc_wrong_key = suite
            .sign(
                cred,
                &didethr,
                &wrong_signer,
                ProofOptions {
                    options: AnyInputSuiteOptions::default()
                        .with_public_key(wrong_key.to_public())
                        .unwrap(),
                    ..issue_options
                },
            )
            .await
            .unwrap();
        assert!(vc_wrong_key.verify(&verifier).await.unwrap().is_err());

        // Make it into a VP
        let presentation = JsonPresentation::new(
            Some(uri!("http://example.org/presentations/3731").to_owned()),
            None,
            vec![vc],
        );

        let vp_issue_options = ProofOptions::new(
            "2021-02-18T20:23:13Z".parse().unwrap(),
            IriBuf::new(format!("{did}#controller")).unwrap().into(),
            ProofPurpose::Authentication,
            AnyInputSuiteOptions::default(),
        );

        let vp = suite
            .sign(presentation, &didethr, &signer, vp_issue_options)
            .await
            .unwrap();

        println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
        assert!(vp.verify(&verifier).await.unwrap().is_ok());

        // Mess with proof signature to make verify fail.
        let mut vp_fuzzed = vp.clone();
        vp_fuzzed.proofs.first_mut().unwrap().signature.alter();
        let vp_fuzzed_result = vp_fuzzed.verify(&verifier).await;
        assert!(vp_fuzzed_result.is_err() || vp_fuzzed_result.is_ok_and(|v| v.is_err()));

        // test that holder is verified
        let mut vp_bad_holder = vp;
        vp_bad_holder.holder = Some(uri!("did:pkh:example:bad").to_owned());

        // It should fail.
        assert!(vp_bad_holder.verify(&verifier).await.unwrap().is_err());
    }

    #[tokio::test]
    async fn credential_verify_eip712vm() {
        let didethr = DIDEthr::<()>::default().into_vm_resolver();
        let vc = ssi_claims::vc::v1::data_integrity::any_credential_from_json_str(include_str!(
            "../tests/vc.jsonld"
        ))
        .unwrap();
        // eprintln!("vc {:?}", vc);
        assert!(vc
            .verify(VerificationParameters::from_resolver(didethr))
            .await
            .unwrap()
            .is_ok())
    }

    #[tokio::test]
    async fn metadata_serializes_correctly_in_json() {
        // Test 7.3: versionId/updated appear when present, omitted when None
        use ssi_dids_core::document::Metadata;

        // Metadata with all fields set
        let meta_full = Metadata {
            deactivated: Some(true),
            version_id: Some("42".to_string()),
            updated: Some("2024-06-01T12:00:00Z".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&meta_full).unwrap();
        assert_eq!(json["deactivated"], true);
        assert_eq!(json["versionId"], "42");
        assert_eq!(json["updated"], "2024-06-01T12:00:00Z");

        // Metadata with no fields set — all should be omitted
        let meta_empty = Metadata::default();
        let json = serde_json::to_value(&meta_empty).unwrap();
        assert!(json.get("deactivated").is_none());
        assert!(json.get("versionId").is_none());
        assert!(json.get("updated").is_none());

        // Metadata with only versionId/updated (no deactivated)
        let meta_partial = Metadata {
            deactivated: None,
            version_id: Some("100".to_string()),
            updated: Some("2024-01-15T09:50:00Z".to_string()),
            ..Default::default()
        };
        let json = serde_json::to_value(&meta_partial).unwrap();
        assert!(json.get("deactivated").is_none());
        assert_eq!(json["versionId"], "100");
        assert_eq!(json["updated"], "2024-01-15T09:50:00Z");
    }

    // ── Phase 9: Network Configuration Cleanup ──

    #[tokio::test]
    async fn sepolia_network_parses_with_correct_chain_id() {
        let resolver = DIDEthr::<()>::default();
        let output = resolver
            .resolve(did!("did:ethr:sepolia:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap();
        let doc_value = serde_json::to_value(&output.document).unwrap();
        // blockchainAccountId should use eip155:11155111
        let vm = &doc_value["verificationMethod"][0];
        assert_eq!(
            vm["blockchainAccountId"],
            "eip155:11155111:0xb9c5714089478a327f09197987f16f9e5d936e8a"
        );
    }

    #[tokio::test]
    async fn goerli_network_still_works() {
        let resolver = DIDEthr::<()>::default();
        let output = resolver
            .resolve(did!("did:ethr:goerli:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap();
        let doc_value = serde_json::to_value(&output.document).unwrap();
        let vm = &doc_value["verificationMethod"][0];
        assert_eq!(
            vm["blockchainAccountId"],
            "eip155:5:0xb9c5714089478a327f09197987f16f9e5d936e8a"
        );
    }

    #[tokio::test]
    async fn deprecated_network_ropsten_still_parses() {
        let resolver = DIDEthr::<()>::default();
        let output = resolver
            .resolve(did!("did:ethr:ropsten:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap();
        let doc_value = serde_json::to_value(&output.document).unwrap();
        let vm = &doc_value["verificationMethod"][0];
        assert_eq!(
            vm["blockchainAccountId"],
            "eip155:3:0xb9c5714089478a327f09197987f16f9e5d936e8a"
        );
    }

    #[tokio::test]
    async fn hex_chain_id_works() {
        let resolver = DIDEthr::<()>::default();
        let output = resolver
            .resolve(did!("did:ethr:0x5:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap();
        let doc_value = serde_json::to_value(&output.document).unwrap();
        let vm = &doc_value["verificationMethod"][0];
        assert_eq!(
            vm["blockchainAccountId"],
            "eip155:5:0xb9c5714089478a327f09197987f16f9e5d936e8a"
        );
    }

    #[tokio::test]
    async fn unknown_network_name_returns_error() {
        let resolver = DIDEthr::<()>::default();
        let result = resolver
            .resolve(did!("did:ethr:fakenet:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await;
        assert!(result.is_err());
    }

    // ── Phase 11: Eip712Method2021 for public-key DIDs ──

    #[tokio::test]
    async fn pubkey_did_genesis_includes_eip712method2021() {
        // Public-key DID genesis doc should include Eip712Method2021 VM
        // paired with #controller (same blockchainAccountId).
        let resolver = DIDEthr::<()>::default();
        let doc = resolver
            .resolve(did!(
                "did:ethr:0x03fdd57adec3d438ea237fe46b33ee1e016eda6b585c3e27ea66686c2ea5358479"
            ))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let vms = doc_value["verificationMethod"].as_array().unwrap();

        // Should have 3 VMs: #controller, #controllerKey, #Eip712Method2021
        assert_eq!(vms.len(), 3, "public-key DID should have 3 VMs");

        // Find the Eip712Method2021 VM
        let eip712_vm = vms.iter()
            .find(|vm| vm["type"].as_str() == Some("Eip712Method2021"))
            .expect("should have Eip712Method2021 VM");

        assert!(
            eip712_vm["id"].as_str().unwrap().ends_with("#Eip712Method2021"),
            "Eip712Method2021 VM should have #Eip712Method2021 fragment"
        );

        // Same blockchainAccountId as #controller
        let controller_vm = vms.iter()
            .find(|vm| vm["id"].as_str().unwrap().ends_with("#controller"))
            .unwrap();
        assert_eq!(
            eip712_vm["blockchainAccountId"],
            controller_vm["blockchainAccountId"],
            "Eip712Method2021 should share blockchainAccountId with #controller"
        );

        // Referenced in assertionMethod and authentication
        let assertion = doc_value["assertionMethod"].as_array().unwrap();
        let auth = doc_value["authentication"].as_array().unwrap();
        let eip712_id = eip712_vm["id"].as_str().unwrap();
        assert!(
            assertion.iter().any(|r| r.as_str() == Some(eip712_id)),
            "Eip712Method2021 should be in assertionMethod"
        );
        assert!(
            auth.iter().any(|r| r.as_str() == Some(eip712_id)),
            "Eip712Method2021 should be in authentication"
        );
    }

    #[tokio::test]
    async fn resolve_address_did_has_no_public_key_jwk_in_context() {
        // An address-only DID (no public key, no attribute keys) should NOT
        // have publicKeyJwk in the @context — it was a bug where any
        // EcdsaSecp256k1VerificationKey2019 VM triggered publicKeyJwk context.
        let resolver = DIDEthr::<()>::default();
        let doc = resolver
            .resolve(did!("did:ethr:0xb9c5714089478a327f09197987f16f9e5d936e8a"))
            .await
            .unwrap()
            .document;

        let doc_value = serde_json::to_value(&doc).unwrap();
        let context = doc_value["@context"].as_array().unwrap();
        let ctx_obj = context.iter().find(|c| c.is_object()).unwrap();

        assert!(
            ctx_obj.get("publicKeyJwk").is_none(),
            "address-only DID should NOT have publicKeyJwk in context"
        );
    }
}
