use serde::{Deserialize, Serialize};
use ssi::claims::sd_jwt::SdJwtBuf;
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
async fn verify_with_selective_disclosure() {
    // Read the SD-JWT from a file (produced by the issuer)
    let vc_path = std::env::var("VC_PATH")
        .unwrap_or_else(|_| "credential.sd-jwt".to_string());

    let sd_jwt_str = std::fs::read_to_string(&vc_path)
        .unwrap_or_else(|e| panic!(
            "failed to read SD-JWT from {vc_path}: {e}\n\
             Run the issue test first: cargo test --test issue"
        ));

    let sd_jwt = SdJwtBuf::new(sd_jwt_str).expect("invalid SD-JWT format");

    // The issuer's public key is embedded in the DID:JWK (set as the JWT's kid).
    // The DIDJWK resolver extracts it automatically.
    let vm_resolver = DIDJWK.into_vm_resolver::<AnyJwkMethod>();
    let params = VerificationParameters::from_resolver(&vm_resolver);

    // === Step 1: Decode and verify the full SD-JWT ===
    // This reveals ALL concealed claims and verifies the signature.
    let (mut revealed, verification) = sd_jwt
        .decode_reveal_verify::<CredentialClaims, _>(&params)
        .await
        .expect("SD-JWT decode/reveal failed");

    assert_eq!(verification, Ok(()));

    println!("Full claims: {:?}", revealed.claims().private);
    // → CredentialClaims { name: Some("Alice Doe"), email: Some("alice.doe@example.com") }

    // === Step 2: Selective disclosure — only present email ===
    // The holder removes the name disclosure, keeping only email.
    // The verifier will only see the email field; name will be None.
    revealed.retain(&[json_pointer!("/email")]);

    // Re-encode the SD-JWT with only the selected disclosures
    let selective_sd_jwt = revealed.into_encoded();

    // === Step 3: Verify the selectively-disclosed SD-JWT ===
    // This is what the verifier would do after receiving the holder's SD-JWT.
    let (verified, verification) = selective_sd_jwt
        .decode_reveal_verify::<CredentialClaims, _>(params)
        .await
        .expect("selective SD-JWT verification failed");

    assert_eq!(verification, Ok(()));

    // Only email is revealed; name is concealed (None)
    assert_eq!(verified.claims().private.name, None);
    assert_eq!(
        verified.claims().private.email,
        Some("alice.doe@example.com".to_string())
    );

    println!("Selectively disclosed claims: {:?}", verified.claims().private);
    // → CredentialClaims { name: None, email: Some("alice.doe@example.com") }

    println!("Selective disclosure verified successfully!");
}
