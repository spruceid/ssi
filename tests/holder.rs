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
    let sd_jwt_str =
        std::fs::read_to_string("credential.sd-jwt").expect("failed to read SD-JWT file");
    let sd_jwt = SdJwtBuf::new(sd_jwt_str).expect("invalid SD-JWT format");

    let vm_resolver = DIDJWK.into_vm_resolver::<AnyJwkMethod>();
    let params = VerificationParameters::from_resolver(&vm_resolver);

    let (mut revealed, verification) = sd_jwt
        .decode_reveal_verify::<CredentialClaims, _>(&params)
        .await
        .expect("SD-JWT decode/reveal failed");

    assert_eq!(verification, Ok(()));

    // Only reveal email — hide name
    revealed.retain(&[json_pointer!("/email")]);

    // Re-encode the SD-JWT with only the selected disclosures
    let selective_sd_jwt = revealed.into_encoded();

    // Save the email-only version so you can compare the two files
    std::fs::write("credential-email-only.sd-jwt", selective_sd_jwt.as_str())
        .expect("failed to write selective SD-JWT");

    let (verified, verification) = selective_sd_jwt
        .decode_reveal_verify::<CredentialClaims, _>(params)
        .await
        .expect("selective SD-JWT verification failed");

    assert_eq!(verification, Ok(()));

    // Only email is visible — name is concealed
    assert_eq!(verified.claims().private.name, None);
    assert_eq!(
        verified.claims().private.email,
        Some("alice.doe@example.com".to_string())
    );
}
