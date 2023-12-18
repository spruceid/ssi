use std::collections::HashMap;

use async_trait::async_trait;
use rstest::*;
use serde::Deserialize;
use ssi_dids::{
    did_resolve::{
        Content, ContentMetadata, DIDResolver, DereferencingInputMetadata, DereferencingMetadata,
        DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, TYPE_DID_LD_JSON,
    },
    Document, PrimaryDIDURL,
};
use ssi_json_ld::ContextLoader;
use ssi_jwk::JWK;
use ssi_ldp::{dataintegrity::DataIntegrityCryptoSuite, ProofSuiteType};
use ssi_vc::{Credential, LinkedDataProofOptions, OneOrMany, ProofPurpose, URI};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct KeyPair {
    public_key_multibase: String,
    private_key_multibase: String,
}

struct DiResolver;

const DI_ISSUER: &str = "https://vc.example/issuers/5678";
const DI_ISSUER_JSON: &str = r#"{
  "@context": [
    "https://www.w3.org/ns/did/v1",
    "https://w3id.org/security/multikey/v1"
  ],
  "id": "https://vc.example/issuers/5678",
  "assertionMethod": [
    {
      "@context": "https://w3id.org/security/multikey/v1",
      "id": "https://vc.example/issuers/5678#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2",
      "controller": "https://vc.example/issuers/5678",
      "type": "Multikey",
      "publicKeyMultibase": "z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2"
    },
    {
      "@context": "https://w3id.org/security/multikey/v1",
      "id": "https://vc.example/issuers/5678#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP",
      "controller": "https://vc.example/issuers/5678",
      "type": "Multikey",
      "publicKeyMultibase": "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP"
    },
    {
      "@context": "https://w3id.org/security/multikey/v1",
      "id": "https://vc.example/issuers/5678#z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ",
      "controller": "https://vc.example/issuers/5678",
      "type": "Multikey",
      "publicKeyMultibase": "z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ"
    }
  ]
}"#;

#[async_trait]
impl DIDResolver for DiResolver {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        if did == DI_ISSUER {
            let doc = Document::from_json(DI_ISSUER_JSON).expect("Could not deserialize document");
            (
                ResolutionMetadata {
                    content_type: Some(TYPE_DID_LD_JSON.to_string()),
                    ..Default::default()
                },
                Some(doc),
                Some(DocumentMetadata::default()),
            )
        } else if did == "https:" {
            (
                ResolutionMetadata {
                    content_type: Some(TYPE_DID_LD_JSON.to_string()),
                    ..Default::default()
                },
                Some(Document::new(did)),
                Some(DocumentMetadata::default()),
            )
        } else {
            panic!("Invalid did for di-eddsa");
        }
    }

    async fn resolve_representation(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (ResolutionMetadata, Vec<u8>, Option<DocumentMetadata>) {
        if did == DI_ISSUER {
            let vec = DI_ISSUER_JSON.as_bytes().to_vec();
            (
                ResolutionMetadata {
                    error: None,
                    content_type: Some(TYPE_DID_LD_JSON.to_string()),
                    property_set: None,
                },
                vec,
                Some(DocumentMetadata::default()),
            )
        } else {
            panic!("Invalid did for di-eddsa");
        }
    }

    async fn dereference(
        &self,
        did_url: &PrimaryDIDURL,
        _input_metadata: &DereferencingInputMetadata,
    ) -> Option<(DereferencingMetadata, Content, ContentMetadata)> {
        let doc = Document::from_json(DI_ISSUER_JSON).expect("Could not deserialize document");
        match &did_url.to_string()[..] {
            "https://vc.example/issuers/5678" => Some((
                DereferencingMetadata {
                    content_type: Some(TYPE_DID_LD_JSON.to_string()),
                    ..Default::default()
                },
                Content::DIDDocument(doc),
                ContentMetadata::default(),
            )),
            _ => None,
        }
    }
}

#[async_std::test]
async fn vc_di_eddsa_ed25519signature2020() {
    // let signed_vc = include_str!(
    //     "../../tests/vc-di-eddsa/TestVectors/Ed25519Signature2020/signedEdSig.json"
    // );
    // let mut signed_vc: Credential = serde_json::from_str(signed_vc).unwrap();
    // let proofs = signed_vc.proof.unwrap();
    // let mut proof = proofs.first().unwrap().clone();
    // proof.context = serde_json::Value::String(
    //     "https://w3id.org/security/suites/ed25519-2020/v1".to_string(),
    // );
    // signed_vc.proof = Some(OneOrMany::One(proof));
    // let res = signed_vc
    //     .verify(None, &DiEddsaResolver, &mut ContextLoader::default())
    //     .await;
    // assert_eq!(res.errors, Vec::<String>::default());

    let unsigned_vc = include_str!("../../tests/vc-di-eddsa/TestVectors/unsigned.json");
    let mut unsigned_vc: Credential = serde_json::from_str(unsigned_vc).unwrap();
    let key: KeyPair = serde_json::from_str(include_str!(
        "../../tests/vc-di-eddsa/TestVectors/keyPair.json"
    ))
    .unwrap();
    let jwk = JWK::from_multicodec(&key.private_key_multibase).unwrap();
    let proof = unsigned_vc
        .generate_proof(
            &jwk,
            &LinkedDataProofOptions {
                type_: Some(ProofSuiteType::Ed25519Signature2020),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                verification_method: Some(URI::String("https://vc.example/issuers/5678#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2".into())),
                ..Default::default()
            },
            &DiResolver,
            &mut ContextLoader::default(),
        )
        .await
        .unwrap();
    assert!(proof.proof_value.is_some());
    unsigned_vc.proof = Some(OneOrMany::One(proof));
    let res = unsigned_vc
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert_eq!(res.errors, Vec::<String>::default());
}

struct TestParams {
    signed_vc: String,
    unsigned_vc: String,
    keypair: String,
    cryptosuite: Option<DataIntegrityCryptoSuite>,
}

#[fixture]
fn test_cases() -> HashMap<String, TestParams> {
    vec![
        (
            "eddsa2022".into(),
            TestParams {
                signed_vc: include_str!(
                    "../../tests/vc-di-eddsa/TestVectors/eddsa-2022/signedDataInt.json"
                )
                .into(),
                unsigned_vc: include_str!("../../tests/vc-di-eddsa/TestVectors/unsigned.json")
                    .into(),
                keypair: include_str!("../../tests/vc-di-eddsa/TestVectors/keyPair.json").into(),
                cryptosuite: Some(DataIntegrityCryptoSuite::Eddsa2022),
            },
        ),
        (
            "jcseddsa2022".into(),
            TestParams {
                signed_vc: include_str!(
                               "../../tests/vc-di-eddsa/TestVectors/jcs-eddsa-2022/signedJCS.json"
                               )
                    .into(),
                    unsigned_vc: include_str!("../../tests/vc-di-eddsa/TestVectors/unsigned.json")
                        .into(),
                        keypair: include_str!("../../tests/vc-di-eddsa/TestVectors/keyPair.json").into(),
                        cryptosuite: Some(DataIntegrityCryptoSuite::JcsEddsa2022),
            },
            ),
        (
            "ecdsa2019p256".into(),
            TestParams {
                signed_vc: include_str!(
                    "../../tests/vc-di-ecdsa/TestVectors/ecdsa-2019-p256/signedECDSAP256.json"
                )
                .into(),
                unsigned_vc: include_str!("../../tests/vc-di-ecdsa/TestVectors/unsigned.json")
                    .into(),
                keypair: include_str!("../../tests/vc-di-ecdsa/TestVectors/p256KeyPair.json")
                    .into(),
                cryptosuite: None,
            },
        ),
        (
            "jcsecdsa2019p256".into(),
            TestParams {
                signed_vc: include_str!(
                    "../../tests/vc-di-ecdsa/TestVectors/jcs-ecdsa-2019-p256/signedJCSECDSAP256.json"
                )
                .into(),
                unsigned_vc: include_str!("../../tests/vc-di-ecdsa/TestVectors/unsigned.json")
                    .into(),
                keypair: include_str!("../../tests/vc-di-ecdsa/TestVectors/p256KeyPair.json")
                    .into(),
                cryptosuite: Some(DataIntegrityCryptoSuite::JcsEcdsa2019),
            },
        ),
        (
            "ecdsa2019p384".into(),
            TestParams {
                signed_vc: include_str!(
                    "../../tests/vc-di-ecdsa/TestVectors/ecdsa-2019-p384/signedECDSAP384.json"
                )
                .into(),
                unsigned_vc: include_str!("../../tests/vc-di-ecdsa/TestVectors/unsigned.json")
                    .into(),
                keypair: include_str!("../../tests/vc-di-ecdsa/TestVectors/p384KeyPair.json")
                    .into(),
                cryptosuite: None,
            },
        ),
        (
            "jcsecdsa2019p384".into(),
            TestParams {
                signed_vc: include_str!(
                    "../../tests/vc-di-ecdsa/TestVectors/jcs-ecdsa-2019-p384/signedJCSECDSAP384.json"
                )
                .into(),
                unsigned_vc: include_str!("../../tests/vc-di-ecdsa/TestVectors/unsigned.json")
                    .into(),
                keypair: include_str!("../../tests/vc-di-ecdsa/TestVectors/p384KeyPair.json")
                    .into(),
                cryptosuite: Some(DataIntegrityCryptoSuite::JcsEcdsa2019),
            },
        ),
    ]
    .into_iter()
    .collect()
}

#[rstest]
#[case::eddsa2022("eddsa2022")]
#[case::jcs_eddsa2022("jcseddsa2022")]
#[case::ecdsa2019_p256("ecdsa2019p256")]
#[case::jcs_ecdsa2019_p256("jcsecdsa2019p256")]
// #[ignore = "p384 requires the canon document/proof to be hashed with sha384 but it's defaulting to sha256"]
#[case::ecdsa2019_p384("ecdsa2019p384")]
#[case::jcs_ecdsa2019_p384("jcsecdsa2019p384")]
#[async_std::test]
async fn vc_dataintegrity(#[case] name: String, test_cases: HashMap<String, TestParams>) {
    let test_case = test_cases.get(&name).unwrap();
    let signed_vc: Credential = serde_json::from_str(&test_case.signed_vc).unwrap();
    let res = signed_vc
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert_eq!(res.errors, Vec::<String>::default());

    let proofs = signed_vc.proof.unwrap();
    let signed_proof = proofs.first().unwrap();

    let mut unsigned_vc: Credential = serde_json::from_str(&test_case.unsigned_vc).unwrap();
    let key: KeyPair = serde_json::from_str(&test_case.keypair).unwrap();
    let jwk = JWK::from_multicodec(&key.private_key_multibase).unwrap();
    let proof = unsigned_vc
        .generate_proof(
            &jwk,
            &LinkedDataProofOptions {
                type_: Some(ProofSuiteType::DataIntegrityProof),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                verification_method: Some(URI::String(format!(
                    "https://vc.example/issuers/5678#{}",
                    key.public_key_multibase
                ))),
                cryptosuite: test_case.cryptosuite.clone(),
                ..Default::default()
            },
            &DiResolver,
            &mut ContextLoader::default(),
        )
        .await
        .unwrap();
    assert!(proof.proof_value.is_some());
    assert_eq!(proof.cryptosuite, signed_proof.cryptosuite);
    unsigned_vc.proof = Some(OneOrMany::One(proof));
    let res = unsigned_vc
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert_eq!(res.errors, Vec::<String>::default());
}
