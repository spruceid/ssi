use did_tz::DIDTz;
use iref::{IriBuf, IriRefBuf, UriBuf};
use linked_data::LinkedData;
use serde_json::json;
use ssi_dids::{did, resolution::Options, DIDResolver, DIDURLBuf, DIDVerifier, DIDURL};
use ssi_jwk::JWK;
use ssi_jws::CompactJWSString;
use ssi_top::{AnySuite, AnySuiteOptions};
use ssi_vc::Verifiable;
use ssi_vc_ldp::{
    verification::method::{signer::SingleSecretSigner, ProofPurpose},
    CryptographicSuiteInput, DataIntegrity, LinkedDataInput, ProofConfiguration,
};
use static_iref::iri;

const TZ1: &str = "did:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x";
const TZ1_JSON: &str = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"GvidwVqGgicuL68BRM89OOtDzK1gjs8IqUXFkjKkm8Iwg18slw==\",\"d\":\"K44dAtJ-MMl-JKuOupfcGRPI5n3ZVH_Gk65c6Rcgn_IV28987PMw_b6paCafNOBOi5u-FZMgGJd3mc5MkfxfwjCrXQM-\"}";

// const LIVE_TZ1: &str = "tz1giDGsifWB9q9siekCKQaJKrmC9da5M43J";
// const LIVE_KT1: &str = "KT1ACXxefCq3zVG9cth4whZqS1XYK9Qsn8Gi";
// const LIVE_NETWORK: &str = "NetXdQprcVkpaWU";

const DIDTZ: DIDTz = DIDTz::new(None);

#[test]
fn jwk_to_did_tezos() {
    // TODO: add tz2 and tz3 test cases
    let jwk: JWK = serde_json::from_str(TZ1_JSON).unwrap();
    let tz1 = DIDTZ.generate(&jwk).unwrap();
    assert_eq!(tz1, TZ1);
}

#[test]
fn jwk_to_tz3() {
    let jwk: JWK = serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "UmzXjEZzlGmpaM_CmFEJtOO5JBntW8yl_fM1LEQlWQ4",
        "y": "OmoZmcbUadg7dEC8bg5kXryN968CJqv2UFMUKRERZ6s"
    }))
    .unwrap();
    let did = DIDTZ.generate(&jwk).unwrap();
    // https://github.com/murbard/pytezos/blob/a228a67fbc94b11dd7dbc7ff0df9e996d0ff5f01tests/test_crypto.py#L34
    assert_eq!(did, "did:tz:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX");
}

#[tokio::test]
async fn test_too_short_did() {
    // Subslicing this method-specific id by byte range 0..3 would overflow.
    let bad_did = did!("did:tz:tz");
    assert!(DIDTZ.resolve(bad_did, Options::default()).await.is_err())
}

#[tokio::test]
async fn test_derivation_tz1() {
    let output = DIDTZ
        .resolve(
            did!("did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8"),
            Options::default(),
        )
        .await
        .unwrap();
    let doc = output.document;
    eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
    assert_eq!(
        serde_json::to_value(doc).unwrap(),
        json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                    "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                    "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021": "https://w3id.org/security#Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021"
                }
            ],
            "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
            "verificationMethod": [{
                "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId",
                "type": "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                "controller": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
                "blockchainAccountId": "tezos:NetXdQprcVkpaWU:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8"
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
    let output = DIDTZ
        .resolve(
            did!("did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq"),
            Options::default(),
        )
        .await
        .unwrap();
    let doc = output.document;
    eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
    assert_eq!(
        serde_json::to_value(doc).unwrap(),
        json!({
            "@context": [
            "https://www.w3.org/ns/did/v1",
            {
                "blockchainAccountId": "https://w3id.org/security#blockchainAccountId",
                "EcdsaSecp256k1RecoveryMethod2020": "https://identity.foundation/EcdsaSecp256k1RecoverySignature2020#EcdsaSecp256k1RecoveryMethod2020"
            }
            ],
            "id": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
            "verificationMethod": [{
            "id": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq#blockchainAccountId",
            "type": "EcdsaSecp256k1RecoveryMethod2020",
            "controller": "did:tz:mainnet:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq",
            "blockchainAccountId": "tezos:NetXdQprcVkpaWU:tz2BFTyPeYRzxd5aiBchbXN3WCZhx7BqbMBq"
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

#[derive(Clone, serde::Serialize, LinkedData)]
#[ld(prefix("cred" = "https://www.w3.org/2018/credentials#"))]
#[ld(type = "cred:VerifiableCredential")]
struct Credential {
    #[ld("cred:issuer")]
    issuer: IriBuf,

    #[ld("cred:issuanceDate")]
    issuance_date: xsd_types::DateTime,

    #[ld("cred:credentialSubject")]
    credential_subject: IriBuf,
}

#[tokio::test]
async fn credential_prove_verify_did_tz1() {
    // use ssi_vc::{Credential, Issuer, LinkedDataProofOptions, URI};
    use wiremock::matchers::{method, path, query_param};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    let mock_server = MockServer::start().await;

    Mock::given(method("GET"))
        .and(path("v1/contracts"))
        .and(query_param(
            "creator",
            "tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq",
        ))
        .and(query_param("codeHash", "1222545108"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_body_json(json!(["KT1ACXxefCq3zVG9cth4whZqS1XYK9Qsn8Gi"])),
        )
        .mount(&mock_server)
        .await;
    Mock::given(method("GET"))
		.and(path(&format!("v1/contracts/{}/storage", "KT1ACXxefCq3zVG9cth4whZqS1XYK9Qsn8Gi")))
		.respond_with(
		ResponseTemplate::new(200)
		.set_body_json(json!({"verification_method": "did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId",
			"service": {"type_": "TezosDiscoveryService", "endpoint": "http://example.com"}})),
		)
		.mount(&mock_server)
		.await;

    let didtz = DIDVerifier::new(DIDTz::new(Some(
        UriBuf::new(mock_server.uri().into_bytes()).unwrap(),
    )));

    let did = did!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq").to_owned();

    let cred = Credential {
        issuer: did.clone().into(),
        issuance_date: "2021-01-27T16:39:07Z".parse().unwrap(),
        credential_subject: iri!("did:example:foo").to_owned(),
    };

    let proof = ssi_vc_ldp::Proof::new(
		ssi_vc_ldp::suite::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
		"2021-03-02T18:59:44.462Z".parse().unwrap(),
		iri!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId").to_owned().into(),
		ProofPurpose::Assertion,
        ssi_vc_ldp::suite::ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021::Options::new(
            r#"{"crv": "Ed25519","kty": "OKP","x": "CFdO_rVP08v1wQQVNybqBxHmTPOBPIt4Kn6LLhR1fMA"}"#.parse().unwrap()
        ),
		ssi_vc_ldp::suite::JwsSignature::new(
			"eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..thpumbPTltH6b6P9QUydy8DcoK2Jj63-FIntxiq09XBk7guF_inA0iQWw7_B_GBwmmsmhYdGL4TdtiNieAdeAg".parse().unwrap()
		)
	);

    println!("{}", serde_json::to_string_pretty(&proof).unwrap());

    let ldp_cred = ssi_vc_ldp::DataIntegrity::new(
        cred,
        LinkedDataInput::default(),
        proof.suite(),
        proof.configuration(),
    )
    .unwrap();

    let vc = ssi_vc::Verifiable::new(ldp_cred, proof);

    assert!(vc.verify(&didtz).await.unwrap().is_valid());

    // test that issuer property is used for verification
    let mut cred_bad_issuer = vc.credential().value().clone();
    cred_bad_issuer.issuer = iri!("did:example:bad").to_owned();

    let ldp_cred_bad_issuer = ssi_vc_ldp::DataIntegrity::new(
        cred_bad_issuer,
        LinkedDataInput::default(),
        vc.proof().suite(),
        vc.proof().configuration(),
    )
    .unwrap();

    let vc_bad_issuer = ssi_vc::Verifiable::new(ldp_cred_bad_issuer, vc.proof().clone());

    assert!(vc_bad_issuer.verify(&didtz).await.unwrap().is_invalid());

    let signer = SingleSecretSigner::new(&didtz, JWK::generate_ed25519().unwrap());

    // Check that proof JWK must match proof verificationMethod
    let vc_wrong_key = ssi_vc_ldp::DataIntegrity::<
        _, // Credential,
        ssi_vc_ldp::suite::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
    >::sign(
        vc.credential().value().clone(),
        LinkedDataInput::default(),
        &signer,
        ssi_vc_ldp::suite::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
        vc.proof().clone_configuration(),
    )
    .await
    .unwrap();

    assert!(vc_wrong_key.verify(&didtz).await.unwrap().is_invalid());

    #[derive(Clone, serde::Serialize, LinkedData)]
    #[ld(prefix("cred" = "https://www.w3.org/2018/credentials#"))]
    #[ld(type = "cred:VerifiablePresentation")]
    struct Presentation {
        #[ld(id)]
        id: IriBuf,

        #[ld("cred:holder")]
        holder: linked_data::Ref<UriBuf>,

        #[ld("cred:verifiableCredential", graph)]
        verifiable_credential: Verifiable<
            DataIntegrity<
                Credential,
                ssi_vc_ldp::suite::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            >,
        >,
    }

    let presentation = Presentation {
        id: iri!("http://example.org/presentations/3731").to_owned(),
        holder: linked_data::Ref(did.into()),
        verifiable_credential: vc,
    };

    let vp_proof = ssi_vc_ldp::Proof::new(
		ssi_vc_ldp::suite::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
		"2021-03-02T19:05:08.271Z".parse().unwrap(),
		iri!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId").to_owned().into(),
		ProofPurpose::Authentication,
        ssi_vc_ldp::suite::ed25519_blake2b_digest_size20_base58_check_encoded_signature_2021::Options::new(
            r#"{"crv": "Ed25519","kty": "OKP","x": "CFdO_rVP08v1wQQVNybqBxHmTPOBPIt4Kn6LLhR1fMA"}"#.parse().unwrap()
        ),
		ssi_vc_ldp::suite::JwsSignature::new(
			"eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..7GLIUeNKvO3WsA3DmBZpbuPinhOcv7Mhgx9QP0svO55T_Zoy7wmJJtLXSoghtkI7DWOnVbiJO5X246Qr0CqGDw".parse().unwrap()
		)
	);

    let ldp_vp = ssi_vc_ldp::DataIntegrity::new(
        presentation.clone(),
        LinkedDataInput::default(),
        vp_proof.suite(),
        vp_proof.configuration(),
    )
    .unwrap();

    let vp = ssi_vc::Verifiable::new(ldp_vp, vp_proof.clone());

    println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());

    assert!(vp.verify(&didtz).await.unwrap().is_valid());

    // mess with the VP proof to make verify fail
    let mut vp1 = vp.clone();
    vp1.proof_mut().signature_mut().jws =
        CompactJWSString::from_string(format!("x{}", vp1.proof_mut().signature_mut().jws)).unwrap();
    assert!(vp1.verify(&didtz).await.is_err());

    // test that holder is verified
    let mut presentation2 = presentation.clone();
    presentation2.holder = linked_data::Ref(did!("did:example:bad").to_owned().into());
    let ldp_vp2 = ssi_vc_ldp::DataIntegrity::new(
        presentation2,
        LinkedDataInput::default(),
        vp_proof.suite(),
        vp_proof.configuration(),
    )
    .unwrap();
    let vp2 = ssi_vc::Verifiable::new(ldp_vp2, vp_proof);
    assert!(vp2.verify(&didtz).await.unwrap().is_invalid());
}

#[tokio::test]
async fn credential_prove_verify_did_tz2() {
    use ssi_jwk::Algorithm;
    // 	use ssi_vc::{Credential, Issuer, LinkedDataProofOptions, URI};

    let mut key = JWK::generate_secp256k1().unwrap();
    // mark this key as being for use with key recovery
    key.algorithm = Some(Algorithm::ES256KR);
    let did = DIDTZ.generate(&key).unwrap();

    let cred = Credential {
        issuer: did.clone().into(),
        issuance_date: "2021-02-18T20:23:13Z".parse().unwrap(),
        credential_subject: did!("did:example:foo").to_owned().into(),
    };

    let didtz = DIDVerifier::new(DIDTZ);
    let signer = SingleSecretSigner::new(&didtz, key.clone());

    let issue_options = ProofConfiguration::new(
        cred.issuance_date.clone(),
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Assertion,
        AnySuiteOptions::new(key.clone()),
    );

    let suite = AnySuite::pick(&key, Some(&issue_options.verification_method)).unwrap();
    let vc = suite
        .sign(cred, LinkedDataInput::default(), &signer, issue_options)
        .await
        .unwrap();
    assert!(vc.verify(&didtz).await.unwrap().is_valid());

    // // Test that issuer property is used for verification.
    // let mut cred_bad_issuer = vc.credential().value().clone();
    // cred_bad_issuer.issuer = iri!("did:example:bad").to_owned();
    // let ldp_cred_bad_issuer = ssi_vc_ldp::DataIntegrity::new(
    //     cred_bad_issuer,
    //     LinkedDataInput::default(),
    //     vc.proof().suite(),
    //     vc.proof().configuration(),
    // )
    // .unwrap();
    // let vc_bad_issuer = ssi_vc::Verifiable::new(ldp_cred_bad_issuer, vc.proof().clone());
    // assert!(vc_bad_issuer.verify(&didtz).await.unwrap().is_invalid());
}

// #[tokio::test]
// #[ignore]
// async fn test_full_resolution() {
// 	let jws = "eyJhbGciOiJFZERTQSIsImtpZCI6ImRpZDp0ejp0ejFnaURHc2lmV0I5cTlzaWVrQ0tRYUpLcm1DOWRhNU00M0ojYmxvY2tjaGFpbkFjY291bnRJZCJ9.eyJpZXRmLWpzb24tcGF0Y2giOiBbCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIHsKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICJvcCI6ICJhZGQiLAogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInBhdGgiOiAiL3NlcnZpY2UvMSIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAidmFsdWUiOiB7CiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgImlkIjogInRlc3Rfc2VydmljZV9pZCIsCiAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgInR5cGUiOiAidGVzdF9zZXJ2aWNlIiwKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAic2VydmljZUVuZHBvaW50IjogInRlc3Rfc2VydmljZV9lbmRwb2ludCIKICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIH0KICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgfQogICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgIF19.HqPI6jFXuEMZ-fQfSE9MstDlKifoqdt8sAtUJ8I3IYwMybLxrabl35hTXyf5Uj6XwnYKrKbBvXImt52WQla5CQ".to_string();
// 	let input_metadata: ResolutionInputMetadata = serde_json::from_value(
// 		json!({"updates": {"type": "signed-ietf-json-patch", "value": [jws]},
// 				"public_key": "edpkvRWhuk5cLe5vwR7TGfSJxVLmVDk5og45WAhsAAvfqQXmYKNPve"}),
// 	)
// 	.unwrap();
// 	let live_did = format!("did:tz:{}", LIVE_TZ1);
// 	let (res_meta, res_doc, _res_doc_meta) = DIDTZ.resolve(&live_did, &input_metadata).await;
// 	assert_eq!(res_meta.error, None);
// 	let d = res_doc.unwrap();
// 	let expected = Document {
// 		id: live_did.clone(),
// 		verification_method: Some(vec![
// 			VerificationMethod::Map(VerificationMethodMap {
// 				id: format!("{}#blockchainAccountId", live_did),
// 				type_: "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021".to_string(),
// 				blockchain_account_id: Some(format!("tezos:{}:{}", LIVE_NETWORK, LIVE_TZ1)),
// 				controller: live_did.clone(),
// 				property_set: Some(Map::new()), // TODO should be None
// 				..Default::default()
// 			}),
// 			VerificationMethod::DIDURL(DIDURL {
// 				did: format!("did:pkh:tz:{}", LIVE_TZ1),
// 				path_abempty: "".to_string(),
// 				query: None,
// 				fragment: Some("TezosMethod2021".to_string()),
// 			}),
// 		]),
// 		service: Some(vec![
// 			Service {
// 				id: format!("{}#discovery", live_did),
// 				type_: OneOrMany::One("TezosDiscoveryService".to_string()),
// 				service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
// 					"http://example.com".to_string(),
// 				))),
// 				property_set: Some(Map::new()), // TODO should be None
// 			},
// 			Service {
// 				id: "test_service_id".to_string(),
// 				type_: OneOrMany::One("test_service".to_string()),
// 				service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
// 					"test_service_endpoint".to_string(),
// 				))),
// 				property_set: Some(Map::new()),
// 			},
// 		]),
// 		..Default::default()
// 	};
// 	assert_eq!(d.id, expected.id);
// 	assert_eq!(d.controller, expected.controller);
// 	assert_eq!(d.verification_method, expected.verification_method);
// 	assert_eq!(d.service, expected.service);
// 	// assert_eq!(d, expected);
// }

// #[tokio::test]
// #[ignore]
// async fn test_full_resolution_kt1() {
// 	let live_did_manager = format!("did:tz:{}", LIVE_KT1);

// 	let (res_meta, res_doc, _res_doc_meta) = DIDTZ
// 		.resolve(&live_did_manager, &ResolutionInputMetadata::default())
// 		.await;
// 	assert_eq!(res_meta.error, None);
// 	let d = res_doc.unwrap();
// 	let expected = Document {
// 		id: live_did_manager.clone(),
// 		verification_method: Some(vec![
// 			VerificationMethod::Map(VerificationMethodMap {
// 				id: format!("{}#blockchainAccountId", live_did_manager),
// 				type_: "Ed25519PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021".to_string(),
// 				blockchain_account_id: Some(format!("tezos:{}:{}", LIVE_NETWORK, LIVE_KT1)),
// 				controller: live_did_manager.clone(),
// 				property_set: None,
// 				..Default::default()
// 			}),
// 			VerificationMethod::DIDURL(DIDURL {
// 				did: format!("did:pkh:tz:{}", LIVE_TZ1),
// 				path_abempty: "".to_string(),
// 				query: None,
// 				fragment: Some("TezosMethod2021".to_string()),
// 			}),
// 		]),
// 		service: Some(vec![Service {
// 			id: format!("{}#discovery", live_did_manager),
// 			type_: OneOrMany::One("TezosDiscoveryService".to_string()),
// 			service_endpoint: Some(OneOrMany::One(ServiceEndpoint::URI(
// 				"http://example.com".to_string(),
// 			))),
// 			property_set: None,
// 		}]),
// 		..Default::default()
// 	};
// 	assert_eq!(d.id, expected.id);
// 	assert_eq!(d.controller, expected.controller);
// 	assert_eq!(d.verification_method, expected.verification_method);
// 	assert_eq!(d.service, expected.service);
// }

// #[tokio::test]
// async fn credential_prove_verify_did_tz3() {
// 	use ssi_jwk::Algorithm;
// 	use ssi_vc::{Credential, Issuer, LinkedDataProofOptions, URI};

// 	let mut key = JWK::generate_p256().unwrap();
// 	key.algorithm = Some(Algorithm::ESBlake2b);
// 	let did = DIDTZ.generate(&Source::Key(&key)).unwrap();
// 	let mut vc: Credential = serde_json::from_value(json!({
// 		"@context": "https://www.w3.org/2018/credentials/v1",
// 		"type": "VerifiableCredential",
// 		"issuer": did.clone(),
// 		"issuanceDate": "2021-03-04T14:18:21Z",
// 		"credentialSubject": {
// 			"id": "did:example:foo"
// 		}
// 	}))
// 	.unwrap();
// 	vc.validate_unsigned().unwrap();
// 	let issue_options = LinkedDataProofOptions {
// 		verification_method: Some(URI::String(did.to_string() + "#blockchainAccountId")),
// 		..Default::default()
// 	};
// 	eprintln!("vm {:?}", issue_options.verification_method);
// 	let mut context_loader = ssi_json_ld::ContextLoader::default();
// 	let vc_no_proof = vc.clone();
// 	let proof = vc
// 		.generate_proof(&key, &issue_options, &DIDTZ, &mut context_loader)
// 		.await
// 		.unwrap();
// 	println!("{}", serde_json::to_string_pretty(&proof).unwrap());
// 	vc.add_proof(proof);
// 	vc.validate().unwrap();
// 	let verification_result = vc.verify(None, &DIDTZ, &mut context_loader).await;
// 	println!("{:#?}", verification_result);
// 	assert!(verification_result.errors.is_empty());

// 	// test that issuer property is used for verification
// 	let mut vc_bad_issuer = vc.clone();
// 	vc_bad_issuer.issuer = Some(Issuer::URI(URI::String("did:example:bad".to_string())));
// 	assert!(!vc_bad_issuer
// 		.verify(None, &DIDTZ, &mut context_loader)
// 		.await
// 		.errors
// 		.is_empty());

// 	// Check that proof JWK must match proof verificationMethod
// 	let mut vc_wrong_key = vc_no_proof.clone();
// 	let other_key = JWK::generate_p256().unwrap();
// 	let proof_bad = ProofSuiteType::P256BLAKE2BDigestSize20Base58CheckEncodedSignature2021
// 		.sign(
// 			&vc_no_proof,
// 			&issue_options,
// 			&DIDTZ,
// 			&mut context_loader,
// 			&other_key,
// 			None,
// 		)
// 		.await
// 		.unwrap();
// 	vc_wrong_key.add_proof(proof_bad);
// 	vc_wrong_key.validate().unwrap();
// 	assert!(!vc_wrong_key
// 		.verify(None, &DIDTZ, &mut context_loader)
// 		.await
// 		.errors
// 		.is_empty());

// 	// Make it into a VP
// 	use ssi_core::one_or_many::OneOrMany;
// 	use ssi_vc::{CredentialOrJWT, Presentation, ProofPurpose, DEFAULT_CONTEXT};
// 	let mut vp = Presentation {
// 		context: ssi_vc::Contexts::Many(vec![ssi_vc::Context::URI(ssi_vc::URI::String(
// 			DEFAULT_CONTEXT.to_string(),
// 		))]),

// 		id: Some("http://example.org/presentations/3731".try_into().unwrap()),
// 		type_: OneOrMany::One("VerifiablePresentation".to_string()),
// 		verifiable_credential: Some(OneOrMany::One(CredentialOrJWT::Credential(vc))),
// 		proof: None,
// 		holder: None,
// 		property_set: None,
// 		holder_binding: None,
// 	};
// 	let mut vp_issue_options = LinkedDataProofOptions::default();
// 	vp.holder = Some(URI::String(did.to_string()));
// 	vp_issue_options.verification_method =
// 		Some(URI::String(did.to_string() + "#blockchainAccountId"));
// 	vp_issue_options.proof_purpose = Some(ProofPurpose::Authentication);
// 	eprintln!("vp: {}", serde_json::to_string_pretty(&vp).unwrap());
// 	let vp_proof = vp
// 		.generate_proof(&key, &vp_issue_options, &DIDTZ, &mut context_loader)
// 		.await
// 		.unwrap();
// 	vp.add_proof(vp_proof);
// 	println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());
// 	vp.validate().unwrap();
// 	let vp_verification_result = vp
// 		.verify(Some(vp_issue_options.clone()), &DIDTZ, &mut context_loader)
// 		.await;
// 	println!("{:#?}", vp_verification_result);
// 	assert!(vp_verification_result.errors.is_empty());

// 	// mess with the VP proof to make verify fail
// 	let mut vp1 = vp.clone();
// 	match vp1.proof {
// 		Some(OneOrMany::One(ref mut proof)) => match proof.jws {
// 			Some(ref mut jws) => {
// 				jws.insert(0, 'x');
// 			}
// 			_ => unreachable!(),
// 		},
// 		_ => unreachable!(),
// 	}
// 	let vp_verification_result = vp1
// 		.verify(Some(vp_issue_options), &DIDTZ, &mut context_loader)
// 		.await;
// 	println!("{:#?}", vp_verification_result);
// 	assert!(!vp_verification_result.errors.is_empty());

// 	// test that holder is verified
// 	let mut vp2 = vp.clone();
// 	vp2.holder = Some(URI::String("did:example:bad".to_string()));
// 	assert!(!vp2
// 		.verify(None, &DIDTZ, &mut context_loader)
// 		.await
// 		.errors
// 		.is_empty());
// }
