use did_tz::DIDTz;
use iref::{IriBuf, UriBuf};
use rand_chacha::rand_core::SeedableRng;
use serde_json::json;
use ssi_claims::{
    data_integrity::{
        verification::method::{signer::SingleSecretSigner, ProofPurpose},
        AnyInputContext, AnySuite, AnySuiteOptions, CryptographicSuiteInput, ProofConfiguration,
    },
    vc::{JsonCredential, JsonPresentation, JsonVerifiableCredential, JsonVerifiablePresentation},
    Verifiable,
};
use ssi_dids_core::{did, resolution::Options, DIDResolver, DIDVerifier};
use ssi_json_ld::JsonLdEnvironment;
use ssi_jwk::JWK;
use ssi_jws::CompactJWSString;
use static_iref::{iri, uri};

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
    assert!(DIDTZ
        .resolve_with(bad_did, Options::default())
        .await
        .is_err())
}

#[tokio::test]
async fn test_derivation_tz1() {
    let output = DIDTZ
        .resolve_with(
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
        .resolve_with(
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
        .resolve_with(
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

#[tokio::test]
async fn credential_prove_verify_did_tz1() {
    // use ssi_claims::{Credential, Issuer, LinkedDataProofOptions, URI};
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
    let cred = JsonVerifiableCredential::new(
        None,
        did.clone().into_uri().into(),
        "2021-01-27T16:39:07Z".parse().unwrap(),
        vec![json_syntax::json!({
            "id": "did:example:foo"
        })],
        vec![ssi_claims::data_integrity::Proof::new(
            ssi_claims::data_integrity::suites::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            "2021-03-02T18:59:44.462Z".parse().unwrap(),
            iri!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId").to_owned().into(),
            ProofPurpose::Assertion,
            ssi_claims::data_integrity::suites::tezos::Options::new(
                r#"{"crv": "Ed25519","kty": "OKP","x": "CFdO_rVP08v1wQQVNybqBxHmTPOBPIt4Kn6LLhR1fMA"}"#.parse().unwrap()
            ),
            ssi_claims::data_integrity::suites::JwsSignature::new(
                "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..thpumbPTltH6b6P9QUydy8DcoK2Jj63-FIntxiq09XBk7guF_inA0iQWw7_B_GBwmmsmhYdGL4TdtiNieAdeAg".parse().unwrap()
            )
        ).with_context(ssi_claims::data_integrity::suites::tezos::TZ_CONTEXT.clone().into())]
    );

    let vc = Verifiable::new_with(cred, JsonLdEnvironment::default())
        .await
        .unwrap();

    assert!(vc.verify(&didtz).await.unwrap().is_valid());

    // test that issuer property is used for verification
    let vc_bad_issuer = Verifiable::tamper(vc.clone(), JsonLdEnvironment::default(), |mut cred| {
        cred.issuer = uri!("did:example:bad").to_owned().into();
        cred
    })
    .await
    .unwrap();

    assert!(vc_bad_issuer.verify(&didtz).await.unwrap().is_invalid());

    // Check that proof JWK must match proof verificationMethod
    let wrong_signer = SingleSecretSigner::new(&didtz, JWK::generate_ed25519().unwrap());
    let vc_wrong_key =
    ssi_claims::data_integrity::suites::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021.sign(
        vc.claims().clone(),
        JsonLdEnvironment::default(),
        &wrong_signer,
        vc.proof().first().unwrap().clone_configuration()
    )
    .await
    .unwrap();
    assert!(vc_wrong_key.verify(&didtz).await.unwrap().is_invalid());

    let presentation = JsonVerifiablePresentation::new(
        Some(uri!("http://example.org/presentations/3731").to_owned()),
        vec![vc],
        vec![did.into()],
        vec![ssi_claims::data_integrity::Proof::new(
            ssi_claims::data_integrity::suites::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            "2021-03-02T19:05:08.271Z".parse().unwrap(),
            iri!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId").to_owned().into(),
            ProofPurpose::Authentication,
            ssi_claims::data_integrity::suites::tezos::Options::new(
                r#"{"crv": "Ed25519","kty": "OKP","x": "CFdO_rVP08v1wQQVNybqBxHmTPOBPIt4Kn6LLhR1fMA"}"#.parse().unwrap()
            ),
            ssi_claims::data_integrity::suites::JwsSignature::new(
                "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..7GLIUeNKvO3WsA3DmBZpbuPinhOcv7Mhgx9QP0svO55T_Zoy7wmJJtLXSoghtkI7DWOnVbiJO5X246Qr0CqGDw".parse().unwrap()
            )
        )]
    );

    let vp = Verifiable::new_with(presentation, JsonLdEnvironment::default())
        .await
        .unwrap();

    println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());

    assert!(vp.verify(&didtz).await.unwrap().is_valid());

    // mess with the VP proof to make verify fail
    let mut vp1 = vp.clone();
    vp1.proof_mut().first_mut().unwrap().signature_mut().jws =
        CompactJWSString::from_string(format!(
            "x{}",
            vp1.proof_mut().first_mut().unwrap().signature_mut().jws
        ))
        .unwrap();
    assert!(vp1.verify(&didtz).await.is_err());

    // test that holder is verified
    let vp2 = Verifiable::tamper(vp.clone(), JsonLdEnvironment::default(), |mut pres| {
        pres.holders = vec![did!("did:example:bad").to_owned().into()];
        pres
    })
    .await
    .unwrap();
    assert!(vp2.verify(&didtz).await.unwrap().is_invalid());
}

#[tokio::test]
async fn credential_prove_verify_did_tz2() {
    use ssi_jwk::Algorithm;
    // 	use ssi_claims::{Credential, Issuer, LinkedDataProofOptions, URI};

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
    let mut key = JWK::generate_secp256k1_from(&mut rng).unwrap();
    // mark this key as being for use with key recovery
    key.algorithm = Some(Algorithm::ES256KR);
    let did = DIDTZ.generate(&key).unwrap();

    let cred = JsonCredential::new(
        None,
        did.clone().into_uri().into(),
        "2021-02-18T20:23:13Z".parse().unwrap(),
        vec![json_syntax::json!({
            "id": "did:example:foo"
        })],
    );

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
    let vc_bad_issuer = Verifiable::tamper(vc.clone(), AnyInputContext::default(), |mut cred| {
        cred.issuer = uri!("did:example:bad").to_owned().into();
        cred
    })
    .await
    .unwrap();
    assert!(vc_bad_issuer.verify(&didtz).await.unwrap().is_invalid());

    // Check that proof JWK must match proof verificationMethod
    let wrong_signer =
        SingleSecretSigner::new(&didtz, JWK::generate_secp256k1_from(&mut rng).unwrap());
    let vc_wrong_key = suite
        .sign(
            vc.claims().clone(),
            AnyInputContext::default(),
            &wrong_signer,
            vc.proof().first().unwrap().clone_configuration(),
        )
        .await
        .unwrap();
    assert!(vc_wrong_key.verify(&didtz).await.unwrap().is_invalid());

    let presentation = JsonPresentation::new(
        Some(uri!("http://example.org/presentations/3731").to_owned()),
        vec![vc],
        vec![did.clone().into()],
    );

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
    vp1.proof_mut().first_mut().unwrap().signature_mut().jws = Some(
        CompactJWSString::from_string(format!(
            "x{}",
            vp.proof()
                .first()
                .unwrap()
                .signature()
                .jws
                .as_ref()
                .unwrap()
        ))
        .unwrap(),
    );
    assert!(vp1.verify(&didtz).await.is_err());

    // test that holder is verified
    let vp2 = Verifiable::tamper(vp.clone(), AnyInputContext::default(), |mut pres| {
        pres.holders = vec![did!("did:example:bad").to_owned().into()];
        pres
    })
    .await
    .unwrap();
    assert!(vp2.verify(&didtz).await.unwrap().is_invalid());
}

#[tokio::test]
async fn credential_prove_verify_did_tz3() {
    use ssi_jwk::Algorithm;

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
    let mut key = JWK::generate_p256_from(&mut rng);
    key.algorithm = Some(Algorithm::ESBlake2b);
    let did = DIDTZ.generate(&key).unwrap();

    let cred = JsonCredential::new(
        None,
        did.clone().into_uri().into(),
        "2021-03-04T14:18:21Z".parse().unwrap(),
        vec![json_syntax::json!({
            "id": "did:example:foo"
        })],
    );

    let didtz = DIDVerifier::new(DIDTZ);
    let signer = SingleSecretSigner::new(&didtz, key.clone());

    let vc_issue_options = ProofConfiguration::new(
        cred.issuance_date.clone(),
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Assertion,
        AnySuiteOptions::default()
            .with_public_key(key.to_public())
            .unwrap(),
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
    let vc_bad_issuer = Verifiable::tamper(vc.clone(), AnyInputContext::default(), |mut cred| {
        cred.issuer = uri!("did:example:bad").to_owned().into();
        cred
    })
    .await
    .unwrap();
    assert!(vc_bad_issuer.verify(&didtz).await.unwrap().is_invalid());

    // Check that proof JWK must match proof verificationMethod
    let wrong_signer = SingleSecretSigner::new(&didtz, JWK::generate_p256_from(&mut rng));
    let vc_wrong_key = suite
        .sign(
            vc.claims().clone(),
            AnyInputContext::default(),
            &wrong_signer,
            vc.proof().first().unwrap().clone_configuration(),
        )
        .await
        .unwrap();
    assert!(vc_wrong_key.verify(&didtz).await.unwrap().is_invalid());

    let presentation = JsonPresentation::new(
        Some(uri!("http://example.org/presentations/3731").to_owned()),
        vec![vc],
        vec![did.clone().into()],
    );

    let vp_issue_options = ProofConfiguration::new(
        "2021-03-04T14:18:21Z".parse().unwrap(),
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Authentication,
        AnySuiteOptions::default()
            .with_public_key(key.to_public())
            .unwrap(),
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
    vp1.proof_mut().first_mut().unwrap().signature_mut().jws = Some(
        CompactJWSString::from_string(format!(
            "x{}",
            vp.proof()
                .first()
                .unwrap()
                .signature()
                .jws
                .as_ref()
                .unwrap()
        ))
        .unwrap(),
    );
    assert!(vp1.verify(&didtz).await.is_err());

    // test that holder is verified
    let vp2 = Verifiable::tamper(vp.clone(), AnyInputContext::default(), |mut pres| {
        pres.holders = vec![did!("did:example:bad").to_owned().into()];
        pres
    })
    .await
    .unwrap();
    assert!(vp2.verify(&didtz).await.unwrap().is_invalid());
}
