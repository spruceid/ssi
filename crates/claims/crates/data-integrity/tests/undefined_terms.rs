//! Undefined JSON-LD terms are an error, never silently dropped.
//!
//! Data Integrity §2.4.3 requires this: a dropped term is not covered by the
//! proof, so a lenient processor would let claims injected after signing
//! verify. Neither the VC v1 nor the Data Integrity context has an `@vocab`,
//! so `undefinedTerm` is undefined.
#![cfg(all(feature = "w3c", feature = "secp256r1"))]

use std::collections::HashMap;

use iref::IriBuf;
use json_syntax::Parse;
use ssi_claims_core::{SignatureEnvironment, VerificationParameters};
use ssi_data_integrity::{
    AnyDataIntegrity, AnySelectionOptions, AnySignatureOptions, AnySuite, CryptographicSuite,
    DataIntegrityDocument, ProofConfiguration,
};
use ssi_verification_methods::{multikey::MultikeyPair, AnyMethod, SingleSecretSigner};

/// Key pair and verification method from the `ecdsa-rdfc-2019` P-256 spec vector.
const VM_ID: &str =
    "https://vc.example/issuers/5678#zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP";
const PUBLIC_KEY: &str = "zDnaepBuvsQ8cpsWrVKw8fbpGpvPeNSjVPTWoq6cRqaYzBKVP";
const SECRET_KEY: &str = "z42twTcNeSYcnqg1FLuSFs2bsGH3ZqbRHFmvS9XMsYhjxvHN";

const V1_CREDENTIAL: &str = r#"{
    "@context": [
        "https://www.w3.org/2018/credentials/v1",
        "https://w3id.org/security/data-integrity/v2"
    ],
    "type": ["VerifiableCredential"],
    "issuer": "https://vc.example/issuers/5678",
    "issuanceDate": "2023-01-01T00:00:00Z",
    "credentialSubject": { "id": "did:example:abcdefgh" }
}"#;

fn parse<T: serde::de::DeserializeOwned>(src: &str) -> T {
    let json = json_syntax::Value::parse_str(src).unwrap().0;
    json_syntax::from_value(json).unwrap()
}

fn verification_methods() -> HashMap<IriBuf, AnyMethod> {
    let vm: AnyMethod = parse(&format!(
        r#"{{
            "type": "Multikey",
            "id": "{VM_ID}",
            "controller": "https://vc.example/issuers/5678",
            "publicKeyMultibase": "{PUBLIC_KEY}"
        }}"#
    ));
    HashMap::from([(VM_ID.parse().unwrap(), vm)])
}

fn inject_undefined_term(document: &mut DataIntegrityDocument) {
    document.properties.insert(
        "undefinedTerm".to_owned(),
        json_syntax::Value::String("injected".into()),
    );
}

async fn sign(
    document: DataIntegrityDocument,
    cryptosuite: &str,
    signature_options: AnySignatureOptions,
) -> Result<AnyDataIntegrity, impl std::fmt::Debug> {
    let configuration: ProofConfiguration<AnySuite> = parse(&format!(
        r#"{{
            "type": "DataIntegrityProof",
            "cryptosuite": "{cryptosuite}",
            "created": "2023-02-24T23:36:38Z",
            "verificationMethod": "{VM_ID}",
            "proofPurpose": "assertionMethod"
        }}"#
    ));
    let key_pair: MultikeyPair = parse(&format!(
        r#"{{ "publicKeyMultibase": "{PUBLIC_KEY}", "secretKeyMultibase": "{SECRET_KEY}" }}"#
    ));

    let (suite, options) = configuration.into_suite_and_options();
    suite
        .sign_with(
            SignatureEnvironment::default(),
            document,
            &verification_methods(),
            SingleSecretSigner::new(key_pair.secret_jwk().unwrap()).into_local(),
            options.cast(),
            signature_options,
        )
        .await
}

async fn sign_rdfc(
    document: DataIntegrityDocument,
) -> Result<AnyDataIntegrity, impl std::fmt::Debug> {
    sign(document, "ecdsa-rdfc-2019", AnySignatureOptions::default()).await
}

/// Base proof, then full-subject-reveal derivation, as a JSON value.
async fn derive_sd(document: DataIntegrityDocument) -> json_syntax::Value {
    let options: AnySignatureOptions = parse(&format!(
        r#"{{
            "keyPair": {{
                "publicKeyMultibase": "zDnaeTHfhmSaQKBc7CmdL3K7oYg3D6SC7yowe2eBeVd2DH32r",
                "secretKeyMultibase": "z42tqvNGyzyXRzotAYn43UhcFtzDUVdxJ7461fwrfhBPLmfY"
            }},
            "hmacKeyString": "00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF",
            "mandatoryPointers": ["/issuer"]
        }}"#
    ));
    let base = sign(document, "ecdsa-sd-2023", options)
        .await
        .expect("base proof");

    let selection: AnySelectionOptions =
        parse(r#"{ "selectivePointers": ["/credentialSubject"] }"#);
    let derived = base
        .select(
            VerificationParameters::from_resolver(verification_methods()),
            selection,
        )
        .await
        .expect("derivation");
    json_syntax::to_value(&derived).unwrap()
}

/// Control: the unmodified credential signs and verifies.
#[async_std::test]
async fn v1_credential_signs_and_verifies() {
    let vc = sign_rdfc(parse(V1_CREDENTIAL)).await.expect("signing");
    let result = vc
        .verify(VerificationParameters::from_resolver(verification_methods()))
        .await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "control must verify: {result:?}"
    );
}

/// Signing a document with an undefined term is an error.
#[async_std::test]
async fn signing_rejects_undefined_term() {
    let mut document: DataIntegrityDocument = parse(V1_CREDENTIAL);
    inject_undefined_term(&mut document);
    assert!(sign_rdfc(document).await.is_err());
}

/// A term injected after signing must not verify. A processor that drops
/// undefined terms would recompute the original hash and accept it.
#[async_std::test]
async fn verification_rejects_injected_undefined_term() {
    let mut vc = sign_rdfc(parse(V1_CREDENTIAL)).await.expect("signing");
    inject_undefined_term(&mut vc);
    let result = vc
        .verify(VerificationParameters::from_resolver(verification_methods()))
        .await;
    assert!(
        !matches!(result, Ok(Ok(()))),
        "injected undefined term must not verify: {result:?}"
    );
}

/// Control for the selective-disclosure path: the derived credential verifies.
#[async_std::test]
async fn v1_derived_credential_verifies() {
    let derived: AnyDataIntegrity =
        json_syntax::from_value(derive_sd(parse(V1_CREDENTIAL)).await).unwrap();
    let result = derived
        .verify(VerificationParameters::from_resolver(verification_methods()))
        .await;
    assert!(
        matches!(result, Ok(Ok(()))),
        "control must verify: {result:?}"
    );
}

/// Same injection on an `ecdsa-sd-2023` derived credential.
#[async_std::test]
async fn derived_verification_rejects_injected_undefined_term() {
    let mut json = derive_sd(parse(V1_CREDENTIAL)).await;
    json.as_object_mut().unwrap().insert(
        "undefinedTerm".into(),
        json_syntax::Value::String("injected".into()),
    );
    let derived: AnyDataIntegrity = json_syntax::from_value(json).unwrap();
    let result = derived
        .verify(VerificationParameters::from_resolver(verification_methods()))
        .await;
    assert!(
        !matches!(result, Ok(Ok(()))),
        "injected undefined term must not verify: {result:?}"
    );
}
