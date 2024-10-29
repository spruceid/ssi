use did_tz::DIDTz;
use iref::{IriBuf, UriBuf};
use rand_chacha::rand_core::SeedableRng;
use serde_json::json;
use ssi_claims::{
    data_integrity::{
        signing::AlterSignature, AnyInputSuiteOptions, AnySuite, CryptographicSuite, DataIntegrity,
        ProofOptions as SuiteOptions,
    },
    vc::{
        syntax::NonEmptyVec,
        v1::{JsonCredential, JsonPresentation},
    },
    VerificationParameters,
};
use ssi_dids_core::{did, resolution::Options, DIDResolver, VerificationMethodDIDResolver};
use ssi_jwk::JWK;
use ssi_jws::JwsString;
use ssi_verification_methods_core::{ProofPurpose, SingleSecretSigner};
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

// #[test]
// fn resign() {
//     let key: JWK = JWK::generate_ed25519().unwrap();
//     eprintln!("key: {key}");
//     eprintln!("tz: {}", DIDTZ.generate(&key).unwrap());
//     let payload: [u8; 64] = [44, 233, 177, 108, 248, 117, 84, 121, 35, 7, 87, 119, 2, 212, 229, 157, 221, 208, 206, 76, 185, 92, 57, 63, 138, 219, 168, 195, 177, 107, 213, 58, 27, 241, 132, 88, 62, 203, 41, 12, 104, 219, 160, 226, 140, 67, 120, 163, 165, 238, 40, 24, 159, 190, 218, 46, 201, 184, 111, 127, 108, 241, 35, 211];

//     let header = ssi_jws::Header::new_unencoded(ssi_jwk::Algorithm::EdBlake2b, None);
//     let signing_bytes = header.encode_signing_bytes(&payload);
//     let signature = ssi_jws::sign_bytes(ssi_jwk::Algorithm::EdBlake2b, &signing_bytes, &key).unwrap();
//     let jws = ssi_jws::JwsBuf::encode_detached(header, &signature);
//     eprintln!("JWS: {jws}");
// }

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

    let didtz = VerificationMethodDIDResolver::new(DIDTz::new(Some(
        UriBuf::new(mock_server.uri().into_bytes()).unwrap(),
    )));
    let params = VerificationParameters::from_resolver(&didtz);

    let did = did!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq").to_owned();
    let vc = DataIntegrity::new(
        JsonCredential::new(
            None,
            did.clone().into_uri().into(),
            "2021-01-27T16:39:07Z".parse().unwrap(),
            NonEmptyVec::new(json_syntax::json!({
                "id": "did:example:foo"
            }))
        ),
        vec![ssi_claims::data_integrity::Proof::new(
            ssi_claims::data_integrity::suites::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            "2021-03-02T18:59:44.462Z".parse().unwrap(),
            iri!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId").to_owned().into(),
            ProofPurpose::Assertion,
            ssi_claims::data_integrity::suites::tezos::Options::new(
                r#"{"crv": "Ed25519","kty": "OKP","x": "CFdO_rVP08v1wQQVNybqBxHmTPOBPIt4Kn6LLhR1fMA"}"#.parse().unwrap()
            ),
            ssi_claims::data_integrity::signing::DetachedJwsSignature::new(
                // FIXME: this is wrong! The VM expects an EdBlake2b signature,
                // instead this is EdDsa.
                "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..thpumbPTltH6b6P9QUydy8DcoK2Jj63-FIntxiq09XBk7guF_inA0iQWw7_B_GBwmmsmhYdGL4TdtiNieAdeAg".parse().unwrap()
            )
        ).with_context(ssi_claims::data_integrity::suites::tezos::TZ_CONTEXT.clone().into())].into()
    );

    // FIXME: this cannot work because the VC is wrong!
    // `Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021` expects an
    // EdBlake2b signature, but the provided signature is EdDsa.
    // assert_eq!(vc.verify(&didtz).await.unwrap(), Ok(()));

    // test that issuer property is used for verification
    let mut _vc_bad_issuer = vc.clone();
    _vc_bad_issuer.issuer = uri!("did:example:bad").to_owned().into();

    // FIXME: this cannot work because the VC is wrong! See above.
    // assert!(vc_bad_issuer.verify(&didtz).await.unwrap().is_err());

    // Check that proof JWK must match proof verificationMethod
    let wrong_signer = SingleSecretSigner::new(JWK::generate_ed25519().unwrap());
    let vc_wrong_key =
    ssi_claims::data_integrity::suites::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021.sign(
        vc.claims.clone(),
        &didtz,
        &wrong_signer,
        vc.proofs.first().unwrap().configuration().to_owned().into_options()
    )
    .await
    .unwrap();
    assert!(vc_wrong_key.verify(&params).await.unwrap().is_err());

    let vp = DataIntegrity::new(
        JsonPresentation::new(
            Some(uri!("http://example.org/presentations/3731").to_owned()),
            Some(did.into()),
            vec![vc]
        ),
        vec![ssi_claims::data_integrity::Proof::new(
            ssi_claims::data_integrity::suites::Ed25519BLAKE2BDigestSize20Base58CheckEncodedSignature2021,
            "2021-03-02T19:05:08.271Z".parse().unwrap(),
            iri!("did:tz:delphinet:tz1WvvbEGpBXGeTVbLiR6DYBe1izmgiYuZbq#blockchainAccountId").to_owned().into(),
            ProofPurpose::Authentication,
            ssi_claims::data_integrity::suites::tezos::Options::new(
                r#"{"crv": "Ed25519","kty": "OKP","x": "CFdO_rVP08v1wQQVNybqBxHmTPOBPIt4Kn6LLhR1fMA"}"#.parse().unwrap()
            ),
            ssi_claims::data_integrity::signing::DetachedJwsSignature::new(
                // FIXME: this is wrong! The VM expects an EdBlake2b signature,
                // instead this is EdDsa.
                "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il0sImI2NCI6ZmFsc2V9..7GLIUeNKvO3WsA3DmBZpbuPinhOcv7Mhgx9QP0svO55T_Zoy7wmJJtLXSoghtkI7DWOnVbiJO5X246Qr0CqGDw".parse().unwrap()
            )
        ).with_context(ssi_claims::data_integrity::suites::tezos::TZ_CONTEXT.clone().into())].into()
    );

    println!("VP: {}", serde_json::to_string_pretty(&vp).unwrap());

    // FIXME: this cannot work because the VP is wrong! See above.
    // assert!(vp.verify(&didtz).await.unwrap().is_ok());

    // mess with the VP proof to make verify fail
    let mut vp1 = vp.clone();
    vp1.proofs.first_mut().unwrap().signature.jws = JwsString::from_string(format!(
        "x{}",
        vp1.proofs.first_mut().unwrap().signature.jws
    ))
    .unwrap();
    assert!(vp1.verify(&params).await.is_err());

    // test that holder is verified
    let mut _vp2 = vp.clone();
    _vp2.holder = Some(did!("did:example:bad").to_owned().into());

    // FIXME: this cannot work because the VP is wrong! See above.
    // assert!(vp2.verify(&didtz).await.unwrap().is_err());
}

#[tokio::test]
async fn credential_prove_verify_did_tz2() {
    use ssi_jwk::Algorithm;
    // 	use ssi_claims::{Credential, Issuer, LinkedDataProofOptions, URI};

    let mut rng = rand_chacha::ChaCha8Rng::seed_from_u64(2);
    let mut key = JWK::generate_secp256k1_from(&mut rng);
    // mark this key as being for use with key recovery
    key.algorithm = Some(Algorithm::ES256KR);
    let did = DIDTZ.generate(&key).unwrap();

    let cred = JsonCredential::new(
        None,
        did.clone().into_uri().into(),
        "2021-02-18T20:23:13Z".parse().unwrap(),
        NonEmptyVec::new(json_syntax::json!({
            "id": "did:example:foo"
        })),
    );

    let didtz = VerificationMethodDIDResolver::new(DIDTZ);
    let params = VerificationParameters::from_resolver(&didtz);
    let signer = SingleSecretSigner::new(key.clone()).into_local();

    let issuance_date = cred.issuance_date.clone().unwrap();
    let created_date =
        xsd_types::DateTimeStamp::new(issuance_date.date_time, issuance_date.offset.unwrap());
    let vc_issue_options = SuiteOptions::new(
        created_date,
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Assertion,
        Default::default(),
    );
    let suite = AnySuite::pick(&key, vc_issue_options.verification_method.as_ref()).unwrap();
    let vc = suite
        .sign(cred, &didtz, &signer, vc_issue_options)
        .await
        .unwrap();
    println!("{}", serde_json::to_string_pretty(&vc.proofs).unwrap());
    assert!(vc.verify(&params).await.unwrap().is_ok());

    // Test that issuer property is used for verification.
    let mut vc_bad_issuer = vc.clone();
    vc_bad_issuer.issuer = uri!("did:example:bad").to_owned().into();
    assert!(vc_bad_issuer.verify(&params).await.unwrap().is_err());

    // Check that proof JWK must match proof verificationMethod
    let wrong_signer = SingleSecretSigner::new(JWK::generate_secp256k1_from(&mut rng)).into_local();
    let vc_wrong_key = suite
        .sign(
            vc.claims.clone(),
            &didtz,
            &wrong_signer,
            vc.proofs
                .first()
                .unwrap()
                .configuration()
                .to_owned()
                .into_options()
                .cast(),
        )
        .await
        .unwrap();
    assert!(vc_wrong_key.verify(&params).await.unwrap().is_err());

    let presentation = JsonPresentation::new(
        Some(uri!("http://example.org/presentations/3731").to_owned()),
        Some(did.clone().into()),
        vec![vc],
    );

    let vp_issue_options = SuiteOptions::new(
        "2021-02-18T20:23:13Z".parse().unwrap(),
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Authentication,
        Default::default(),
    );
    let suite = AnySuite::pick(&key, vp_issue_options.verification_method.as_ref()).unwrap();
    let vp = suite
        .sign(presentation, &didtz, &signer, vp_issue_options)
        .await
        .unwrap();
    println!("VP: {}", serde_json::to_string_pretty(&vp.proofs).unwrap());
    assert!(vp.verify(&params).await.unwrap().is_ok());

    // mess with the VP proof to make verify fail
    let mut vp1 = vp.clone();
    vp1.proofs.first_mut().unwrap().signature.alter();
    assert!(vp1.verify(&params).await.is_err());

    // test that holder is verified
    let mut vp2 = vp.clone();
    vp2.holder = Some(did!("did:example:bad").to_owned().into());
    assert!(vp2.verify(&params).await.unwrap().is_err());
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
        NonEmptyVec::new(json_syntax::json!({
            "id": "did:example:foo"
        })),
    );

    let didtz = VerificationMethodDIDResolver::new(DIDTZ);
    let params = VerificationParameters::from_resolver(&didtz);
    let signer = SingleSecretSigner::new(key.clone()).into_local();

    let issuance_date = cred.issuance_date.clone().unwrap();
    let created_date =
        xsd_types::DateTimeStamp::new(issuance_date.date_time, issuance_date.offset.unwrap());
    let vc_issue_options = SuiteOptions::new(
        created_date,
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Assertion,
        AnyInputSuiteOptions::default()
            .with_public_key(key.to_public())
            .unwrap(),
    );
    let suite = AnySuite::pick(&key, vc_issue_options.verification_method.as_ref()).unwrap();
    eprintln!("suite {suite:?}");
    let vc = suite
        .sign(cred, &didtz, &signer, vc_issue_options)
        .await
        .unwrap();
    println!("{}", serde_json::to_string_pretty(&vc.proofs).unwrap());
    assert!(vc.verify(&params).await.unwrap().is_ok());

    // Test that issuer property is used for verification.
    let mut vc_bad_issuer = vc.clone();
    vc_bad_issuer.issuer = uri!("did:example:bad").to_owned().into();
    assert!(vc_bad_issuer.verify(&params).await.unwrap().is_err());

    // Check that proof JWK must match proof verificationMethod
    let wrong_signer = SingleSecretSigner::new(JWK::generate_p256_from(&mut rng)).into_local();
    let vc_wrong_key = suite
        .sign(
            vc.claims.clone(),
            &didtz,
            &wrong_signer,
            vc.proofs
                .first()
                .unwrap()
                .configuration()
                .to_owned()
                .into_options()
                .cast(),
        )
        .await
        .unwrap();
    assert!(vc_wrong_key.verify(&params).await.unwrap().is_err());

    let presentation = JsonPresentation::new(
        Some(uri!("http://example.org/presentations/3731").to_owned()),
        Some(did.clone().into()),
        vec![vc],
    );

    let vp_issue_options = SuiteOptions::new(
        "2021-03-04T14:18:21Z".parse().unwrap(),
        IriBuf::new(format!("{did}#blockchainAccountId"))
            .unwrap()
            .into(),
        ProofPurpose::Authentication,
        AnyInputSuiteOptions::default()
            .with_public_key(key.to_public())
            .unwrap(),
    );
    let suite = AnySuite::pick(&key, vp_issue_options.verification_method.as_ref()).unwrap();
    let vp = suite
        .sign(presentation, &didtz, &signer, vp_issue_options)
        .await
        .unwrap();
    println!("VP: {}", serde_json::to_string_pretty(&vp.proofs).unwrap());
    assert!(vp.verify(&params).await.unwrap().is_ok());

    // mess with the VP proof to make verify fail
    let mut vp1 = vp.clone();
    vp1.proofs.first_mut().unwrap().signature.alter();
    assert!(vp1.verify(&params).await.is_err());

    // test that holder is verified
    let mut vp2 = vp.clone();
    vp2.holder = Some(did!("did:example:bad").to_owned().into());
    assert!(vp2.verify(params).await.unwrap().is_err());
}
