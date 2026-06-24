use serde::{Deserialize, Serialize};
use ssi::claims::sd_jwt::{ConcealJwtClaims, SdAlg};
use ssi::json_pointer;
use ssi::prelude::*;

#[derive(Debug, Serialize, Deserialize, PartialEq)]
struct CredentialClaims {
    name: Option<String>,
    email: Option<String>,
}

impl ssi::claims::jwt::ClaimSet for CredentialClaims {}
impl<E, P> ssi::claims::ValidateClaims<E, P> for CredentialClaims {}

#[async_std::test]
async fn issue_vc() {
    let key_path = "issuer_key.jwk";

    let mut key: JWK = match std::fs::read_to_string(key_path) {
        Ok(contents) => serde_json::from_str(&contents).expect("failed to parse key"),
        Err(_) => {
            let new_key = JWK::generate_p256();
            let key_json = serde_json::to_string_pretty(&new_key).expect("failed to serialize key");
            std::fs::write(key_path, &key_json).expect("failed to save key");
            new_key
        }
    };

    // Set the key ID to a DID:JWK URL so verifiers can resolve the public key
    let did = DIDJWK::generate_url(&key.to_public());
    key.key_id = Some(did.into());

    let claims = JWTClaims::builder()
        .iss("https://example.org/issuer")
        .sub("alice")
        .with_private_claims(CredentialClaims {
            name: Some("Alice Doe".to_string()),
            email: Some("alice.doe@example.com".to_string()),
        })
        .unwrap();

    // Conceal both fields — holder decides what to reveal
    let sd_jwt = claims
        .conceal_and_sign(
            SdAlg::Sha256,
            &[json_pointer!("/name"), json_pointer!("/email")],
            &key,
        )
        .await
        .expect("SD-JWT signing failed");

    std::fs::write("credential.sd-jwt", sd_jwt.as_str()).expect("failed to write SD-JWT file");
}
