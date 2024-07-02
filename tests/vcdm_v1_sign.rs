use serde_json::json;
use ssi::JWK;
use ssi_claims::{
    data_integrity::{AnySuite, CryptographicSuite, ProofOptions},
    vc::v1::JsonCredential,
    VerificationParameters,
};
use ssi_dids::{AnyDidMethod, VerificationMethodDIDResolver};
use ssi_verification_methods::{AnyMethod, SingleSecretSigner};
use static_iref::iri;

#[async_std::test]
async fn ed25519_signature_2020() {
    let jwk: JWK = serde_json::from_value(json!({
      "kty": "OKP",
      "crv": "Ed25519",
      "x": "HvjBEw94RHAh9KkiD385aYZNxGkxIkwBcrLBY5Z7Koo",
      "d": "1onWu34oC29Y09qCRl0aD2FOp5y5obTqHZxQQRT3-bs"
    }))
    .unwrap();
    let resolver = VerificationMethodDIDResolver::<_, AnyMethod>::new(AnyDidMethod::default());
    let vc: JsonCredential = serde_json::from_value(json!({
      "@context": [
        "https://www.w3.org/2018/credentials/v1"
      ],
      "type": [
        "VerifiableCredential"
      ],
      "credentialSubject": {
        "id": "did:key:z6MkhTNL7i2etLerDK8Acz5t528giE5KA4p75T6ka1E1D74r"
      },
      "issuanceDate": "2024-06-01T09:09:48Z",
      "id": "urn:uuid:7a6cafb9-11c3-41a8-98d8-8b5a45c2548f",
      "issuer": "did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD"
    }))
    .unwrap();
    let signed_vc = AnySuite::Ed25519Signature2020
        .sign(
            vc,
            &resolver,
            SingleSecretSigner::new(jwk).into_local(),
            ProofOptions::from_method(iri!("did:key:z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD#z6MkgYAGxLBSXa6Ygk1PnUbK2F7zya8juE9nfsZhrvY7c9GD").into()),
        )
        .await
        .unwrap();
    signed_vc
        .verify(VerificationParameters::from_resolver(resolver))
        .await
        .unwrap()
        .unwrap();
}
