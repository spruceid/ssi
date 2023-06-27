use async_trait::async_trait;
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
use ssi_ldp::ProofSuiteType;
use ssi_vc::{Credential, LinkedDataProofOptions, OneOrMany, ProofPurpose, URI};

struct DiResolver;

const DI_ISSUER: &str = "https://vc.example/issuers/5678";
const DI_ISSUER_JSON: &str = include_str!("../../tests/issuer-http-5678.json");

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

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KeyPair {
        // public_key_multibase: String,
        private_key_multibase: String,
    }

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

#[async_std::test]
async fn vc_di_eddsa_dataintegrity() {
    let signed_vc =
        include_str!("../../tests/vc-di-eddsa/TestVectors/eddsa-2022/signedDataInt.json");
    let signed_vc: Credential = serde_json::from_str(signed_vc).unwrap();
    let res = signed_vc
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert_eq!(res.errors, Vec::<String>::default());

    let proofs = signed_vc.proof.unwrap();
    let signed_proof = proofs.first().unwrap();

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KeyPair {
        private_key_multibase: String,
    }

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
            type_: Some(ProofSuiteType::DataIntegrityProof),
            proof_purpose: Some(ProofPurpose::AssertionMethod),
            verification_method: Some(URI::String("https://vc.example/issuers/5678#z6MkrJVnaZkeFzdQyMZu1cgjg7k1pZZ6pvBQ7XJPt4swbTQ2".into())),
            cryptosuite: Some("eddsa-2022".try_into().unwrap()),
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

#[async_std::test]
async fn vc_di_ecdsa_p256_dataintegrity() {
    let signed_vc =
        include_str!("../../tests/vc-di-ecdsa/TestVectors/ecdsa-2019-p256/signedECDSAP256.json");
    let signed_vc: Credential = serde_json::from_str(signed_vc).unwrap();
    let res = signed_vc
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert_eq!(res.errors, Vec::<String>::default());

    let proofs = signed_vc.proof.unwrap();
    let signed_proof = proofs.first().unwrap();

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KeyPair {
        private_key_multibase: String,
    }

    let unsigned_vc = include_str!("../../tests/vc-di-ecdsa/TestVectors/unsigned.json");
    let mut unsigned_vc: Credential = serde_json::from_str(unsigned_vc).unwrap();
    let key: KeyPair = serde_json::from_str(include_str!(
        "../../tests/vc-di-ecdsa/TestVectors/p256KeyPair.json"
    ))
    .unwrap();
    let jwk = JWK::from_multicodec(&key.private_key_multibase).unwrap();
    let proof = unsigned_vc
        .generate_proof(
            &jwk,
            &LinkedDataProofOptions {
                type_: Some(ProofSuiteType::DataIntegrityProof),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                verification_method: Some(URI::String("https://vc.example/issuers/5678#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP".into())),
                // cryptosuite: Some("ecdsa-2022".try_into().unwrap()),
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

#[ignore = "p384 requires the canon document/proof to be hashed with sha384 but it's defaulting to sha256"]
#[async_std::test]
async fn vc_di_ecdsa_p384_dataintegrity() {
    let signed_vc =
        include_str!("../../tests/vc-di-ecdsa/TestVectors/ecdsa-2019-p384/signedECDSAP384.json");
    let signed_vc: Credential = serde_json::from_str(signed_vc).unwrap();
    let res = signed_vc
        .verify(None, &DiResolver, &mut ContextLoader::default())
        .await;
    assert_eq!(res.errors, Vec::<String>::default());

    let proofs = signed_vc.proof.unwrap();
    let signed_proof = proofs.first().unwrap();

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct KeyPair {
        private_key_multibase: String,
    }

    let unsigned_vc = include_str!("../../tests/vc-di-ecdsa/TestVectors/unsigned.json");
    let mut unsigned_vc: Credential = serde_json::from_str(unsigned_vc).unwrap();
    let key: KeyPair = serde_json::from_str(include_str!(
        "../../tests/vc-di-ecdsa/TestVectors/p384KeyPair.json"
    ))
    .unwrap();
    let jwk = JWK::from_multicodec(&key.private_key_multibase).unwrap();
    let proof = unsigned_vc
        .generate_proof(
            &jwk,
            &LinkedDataProofOptions {
                type_: Some(ProofSuiteType::DataIntegrityProof),
                proof_purpose: Some(ProofPurpose::AssertionMethod),
                verification_method: Some(URI::String("https://vc.example/issuers/5678#z82LkuBieyGShVBhvtE2zoiD6Kma4tJGFtkAhxR5pfkp5QPw4LutoYWhvQCnGjdVn14kujQ".into())),
                cryptosuite: Some("ecdsa-2022".try_into().unwrap()),
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
