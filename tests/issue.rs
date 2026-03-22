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
    // Load the issuer's key from file, or generate a new one and save it.
    let key_path = std::env::var("ISSUER_KEY_PATH")
        .unwrap_or_else(|_| "issuer_key.jwk".to_string());

    let mut key: JWK = match std::fs::read_to_string(&key_path) {
        Ok(contents) => {
            println!("Loaded issuer key from {key_path}");
            serde_json::from_str(&contents).expect("failed to parse issuer key")
        }
        Err(_) => {
            let new_key = JWK::generate_p256();
            let key_json = serde_json::to_string_pretty(&new_key)
                .expect("failed to serialize key");
            std::fs::write(&key_path, &key_json).expect("failed to save issuer key");
            println!("Generated new issuer key and saved to {key_path}");
            new_key
        }
    };

    // Set the key ID to a DID:JWK URL so verifiers can resolve the public key
    let did = DIDJWK::generate_url(&key.to_public());
    key.key_id = Some(did.into());

    // Build JWT claims with custom credential data.
    // Both name and email are marked as concealable — the holder can choose
    // which fields to disclose later.
    let claims = JWTClaims::builder()
        .iss("https://example.org/issuer")
        .sub("alice")
        .with_private_claims(CredentialClaims {
            name: Some("Alice Doe".to_string()),
            email: Some("alice.doe@example.com".to_string()),
        })
        .unwrap();

    // Conceal both fields and sign as an SD-JWT.
    // The issuer decides which claims CAN be selectively disclosed.
    let sd_jwt = claims
        .conceal_and_sign(
            SdAlg::Sha256,
            &[json_pointer!("/name"), json_pointer!("/email")],
            &key,
        )
        .await
        .expect("SD-JWT signing failed");

    // Save the SD-JWT to a file
    let vc_path = std::env::var("VC_PATH")
        .unwrap_or_else(|_| "credential.sd-jwt".to_string());
    std::fs::write(&vc_path, sd_jwt.as_str()).expect("failed to write SD-JWT file");

    println!("SD-JWT saved to {vc_path}");
}
