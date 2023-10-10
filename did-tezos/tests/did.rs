use did_tz::DIDTz;
use iref::{IriBuf, UriBuf};
use linked_data::LinkedData;
use rand_chacha::rand_core::SeedableRng;
use serde_json::json;
use ssi_dids::{did, resolution::Options, DIDResolver, DIDVerifier};
use ssi_jwk::JWK;
use ssi_jws::CompactJWSString;
use ssi_top::{AnySuite, AnySuiteOptions, AnyInputContext};
use ssi_vc::Verifiable;
use ssi_vc_ldp::{
    verification::method::{signer::SingleSecretSigner, ProofPurpose},
    CryptographicSuiteInput, DataIntegrity, LinkedDataInput, ProofConfiguration,
};
use static_iref::iri;

const TZ1: &str = "did:tz:tz1YwA1FwpgLtc1G8DKbbZ6e6PTb1dQMRn5x";
const TZ1_JSON: &str = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"GvidwVqGgicuL68BRM89OOtDzK1gjs8IqUXFkjKkm8Iwg18slw==\",\"d\":\"K44dAtJ-MMl-JKuOupfcGRPI5n3ZVH_Gk65c6Rcgn_IV28987PMw_b6paCafNOBOi5u-FZMgGJd3mc5MkfxfwjCrXQM-\"}";

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

#[tokio::test]
async fn test_derivation_tz3() {
    let resolved = DIDTZ
        .resolve(
            did!("did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX"),
            Options::default(),
        )
        .await
        .unwrap();
    let doc = resolved.document;
    eprintln!("{}", serde_json::to_string_pretty(&doc).unwrap());
    assert_eq!(
        serde_json::to_value(doc).unwrap(),
        json!({
            "@context": [
                "https://www.w3.org/ns/did/v1",
                {
                "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021": "https://w3id.org/security#P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                "blockchainAccountId": "https://w3id.org/security#blockchainAccountId"
                }
            ],
            "id": "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
            "verificationMethod": [{
                "id": "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId",
                "type": "P256PublicKeyBLAKE2BDigestSize20Base58CheckEncoded2021",
                "controller": "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX",
                "blockchainAccountId": "tezos:NetXdQprcVkpaWU:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX"
            }],
            "authentication": [
                "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId"
            ],
            "assertionMethod": [
                "did:tz:mainnet:tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX#blockchainAccountId"
            ]
        })
    )
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
        ssi_vc_ldp::suite::tezos::Options::new(
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
    ).await.unwrap();

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
    ).await.unwrap();

    let vc_bad_issuer = ssi_vc::Verifiable::new(ldp_cred_bad_issuer, vc.proof().clone());

    assert!(vc_bad_issuer.verify(&didtz).await.unwrap().is_invalid());

    // Check that proof JWK must match proof verificationMethod
    let wrong_signer = SingleSecretSigner::new(&didtz, JWK::generate_ed25519().unwrap());
    let vc_wrong_key = ssi_vc_ldp::DataIntegrity::<
        _, // Credential,
        ssi_vc_ldp::suite::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
    >::sign(
        vc.credential().value().clone(),
        LinkedDataInput::default(),
        &wrong_signer,
        ssi_vc_ldp::suite::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
        vc.proof().clone_configuration(),
    )
    .await
    .unwrap();
    assert!(vc_wrong_key.verify(&didtz).await.unwrap().is_invalid());

    // Make it into a VP
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
        ssi_vc_ldp::suite::tezos::Options::new(
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
    ).await.unwrap();

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
    ).await.unwrap();
    let vp2 = ssi_vc::Verifiable::new(ldp_vp2, vp_proof);
    assert!(vp2.verify(&didtz).await.unwrap().is_invalid());
}

#[tokio::test]
async fn credential_prove_verify_did_tz2() {
    use ssi_jwk::Algorithm;
    // 	use ssi_vc::{Credential, Issuer, LinkedDataProofOptions, URI};

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
    let mut key = JWK::generate_secp256k1_from(&mut rng).unwrap();
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

    let vc_issue_options = ProofConfiguration::new(
        cred.issuance_date.clone(),
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Assertion,
        Default::default(),
    );
    let suite = AnySuite::pick(&key, Some(&vc_issue_options.verification_method)).unwrap();
    let vc = suite
        .sign(cred, AnyInputContext::default(), &signer, vc_issue_options)
        .await
        .unwrap();
    println!("{}", serde_json::to_string_pretty(vc.proof()).unwrap());
    assert!(vc.verify(&didtz).await.unwrap().is_valid());

    // Test that issuer property is used for verification.
    let mut cred_bad_issuer = vc.credential().value().clone();
    cred_bad_issuer.issuer = iri!("did:example:bad").to_owned();
    let ldp_cred_bad_issuer = ssi_vc_ldp::DataIntegrity::new(
        cred_bad_issuer,
        AnyInputContext::default(),
        vc.proof().suite(),
        vc.proof().configuration(),
    ).await.unwrap();
    let vc_bad_issuer = ssi_vc::Verifiable::new(ldp_cred_bad_issuer, vc.proof().clone());
    assert!(vc_bad_issuer.verify(&didtz).await.unwrap().is_invalid());

    // Check that proof JWK must match proof verificationMethod
    let wrong_signer =
        SingleSecretSigner::new(&didtz, JWK::generate_secp256k1_from(&mut rng).unwrap());
    let vc_wrong_key = suite
        .sign(
            vc.credential().value().clone(),
            AnyInputContext::default(),
            &wrong_signer,
            vc.proof().clone_configuration(),
        )
        .await
        .unwrap();
    assert!(vc_wrong_key.verify(&didtz).await.unwrap().is_invalid());

    // Make it into a VP
    #[derive(Clone, serde::Serialize, LinkedData)]
    #[ld(prefix("cred" = "https://www.w3.org/2018/credentials#"))]
    #[ld(type = "cred:VerifiablePresentation")]
    struct Presentation {
        #[ld(id)]
        id: IriBuf,

        #[ld("cred:holder")]
        holder: linked_data::Ref<UriBuf>,

        #[ld("cred:verifiableCredential", graph)]
        verifiable_credential: Verifiable<DataIntegrity<Credential, AnySuite>>,
    }

    let presentation = Presentation {
        id: iri!("http://example.org/presentations/3731").to_owned(),
        holder: linked_data::Ref(did.clone().into()),
        verifiable_credential: vc,
    };

    let vp_issue_options = ProofConfiguration::new(
        "2021-02-18T20:23:13Z".parse().unwrap(),
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Authentication,
        Default::default(),
    );
    let suite = AnySuite::pick(&key, Some(&vp_issue_options.verification_method)).unwrap();
    let vp = suite
        .sign(
            presentation,
            AnyInputContext::default(),
            &signer,
            vp_issue_options,
        )
        .await
        .unwrap();
    println!("VP: {}", serde_json::to_string_pretty(vp.proof()).unwrap());
    assert!(vp.verify(&didtz).await.unwrap().is_valid());

    // mess with the VP proof to make verify fail
    let mut vp1 = vp.clone();
    vp1.proof_mut().signature_mut().jws = Some(
        CompactJWSString::from_string(format!("x{}", vp.proof().signature().jws.as_ref().unwrap()))
            .unwrap(),
    );
    assert!(vp1.verify(&didtz).await.is_err());

    // test that holder is verified
    let mut presentation2 = vp.credential().value().clone();
    presentation2.holder = linked_data::Ref(did!("did:example:bad").to_owned().into());
    let ldp_vp2 = ssi_vc_ldp::DataIntegrity::new(
        presentation2,
        AnyInputContext::default(),
        vp.proof().suite(),
        vp.proof().configuration(),
    ).await.unwrap();
    let vp2 = ssi_vc::Verifiable::new(ldp_vp2, vp.proof().clone());
    assert!(vp2.verify(&didtz).await.unwrap().is_invalid());
}

#[tokio::test]
async fn credential_prove_verify_did_tz3() {
    use ssi_jwk::Algorithm;

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
    let mut key = JWK::generate_p256_from(&mut rng).unwrap();
    key.algorithm = Some(Algorithm::ESBlake2b);
    let did = DIDTZ.generate(&key).unwrap();

    let cred = Credential {
        issuer: did.clone().into(),
        issuance_date: "2021-03-04T14:18:21Z".parse().unwrap(),
        credential_subject: did!("did:example:foo").to_owned().into(),
    };

    let didtz = DIDVerifier::new(DIDTZ);
    let signer = SingleSecretSigner::new(&didtz, key.clone());

    let vc_issue_options = ProofConfiguration::new(
        cred.issuance_date.clone(),
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Assertion,
        AnySuiteOptions::with_public_key(key.to_public()),
    );
    let suite = AnySuite::pick(&key, Some(&vc_issue_options.verification_method)).unwrap();
    eprintln!("suite {suite:?}");
    let vc = suite
        .sign(cred, AnyInputContext::default(), &signer, vc_issue_options)
        .await
        .unwrap();
    println!("{}", serde_json::to_string_pretty(vc.proof()).unwrap());
    assert!(vc.verify(&didtz).await.unwrap().is_valid());

    // Test that issuer property is used for verification.
    let mut cred_bad_issuer = vc.credential().value().clone();
    cred_bad_issuer.issuer = iri!("did:example:bad").to_owned();
    let ldp_cred_bad_issuer = ssi_vc_ldp::DataIntegrity::new(
        cred_bad_issuer,
        AnyInputContext::default(),
        vc.proof().suite(),
        vc.proof().configuration(),
    ).await.unwrap();
    let vc_bad_issuer = ssi_vc::Verifiable::new(ldp_cred_bad_issuer, vc.proof().clone());
    assert!(vc_bad_issuer.verify(&didtz).await.unwrap().is_invalid());

    // Check that proof JWK must match proof verificationMethod
    let wrong_signer = SingleSecretSigner::new(&didtz, JWK::generate_p256_from(&mut rng).unwrap());
    let vc_wrong_key = suite
        .sign(
            vc.credential().value().clone(),
            AnyInputContext::default(),
            &wrong_signer,
            vc.proof().clone_configuration(),
        )
        .await
        .unwrap();
    assert!(vc_wrong_key.verify(&didtz).await.unwrap().is_invalid());

    // Make it into a VP
    #[derive(Clone, serde::Serialize, LinkedData)]
    #[ld(prefix("cred" = "https://www.w3.org/2018/credentials#"))]
    #[ld(type = "cred:VerifiablePresentation")]
    struct Presentation {
        #[ld(id)]
        id: IriBuf,

        #[ld("cred:holder")]
        holder: linked_data::Ref<UriBuf>,

        #[ld("cred:verifiableCredential", graph)]
        verifiable_credential: Verifiable<DataIntegrity<Credential, AnySuite>>,
    }

    let presentation = Presentation {
        id: iri!("http://example.org/presentations/3731").to_owned(),
        holder: linked_data::Ref(did.clone().into()),
        verifiable_credential: vc,
    };

    let vp_issue_options = ProofConfiguration::new(
        "2021-03-04T14:18:21Z".parse().unwrap(),
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Authentication,
        AnySuiteOptions::with_public_key(key.to_public()),
    );
    let suite = AnySuite::pick(&key, Some(&vp_issue_options.verification_method)).unwrap();
    let vp = suite
        .sign(
            presentation,
            AnyInputContext::default(),
            &signer,
            vp_issue_options,
        )
        .await
        .unwrap();
    println!("VP: {}", serde_json::to_string_pretty(vp.proof()).unwrap());
    assert!(vp.verify(&didtz).await.unwrap().is_valid());

    // mess with the VP proof to make verify fail
    let mut vp1 = vp.clone();
    vp1.proof_mut().signature_mut().jws = Some(
        CompactJWSString::from_string(format!("x{}", vp.proof().signature().jws.as_ref().unwrap()))
            .unwrap(),
    );
    assert!(vp1.verify(&didtz).await.is_err());

    // test that holder is verified
    let mut presentation2 = vp.credential().value().clone();
    presentation2.holder = linked_data::Ref(did!("did:example:bad").to_owned().into());
    let ldp_vp2 = ssi_vc_ldp::DataIntegrity::new(
        presentation2,
        AnyInputContext::default(),
        vp.proof().suite(),
        vp.proof().configuration(),
    )
    .await
    .unwrap();
    let vp2 = ssi_vc::Verifiable::new(ldp_vp2, vp.proof().clone());
    assert!(vp2.verify(&didtz).await.unwrap().is_invalid());
}
