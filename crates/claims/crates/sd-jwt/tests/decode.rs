use serde::{Deserialize, Serialize};
use ssi_jwk::{Algorithm, JWK};
use ssi_jwt::NumericDate;
use ssi_sd_jwt::{decode_verify_disclosure_array, Deserialized};

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
struct ExampleClaims {
    sub: Option<String>,
    given_name: Option<String>,
    family_name: Option<String>,
    email: Option<String>,
    phone_number: Option<String>,
    phone_number_verified: Option<bool>,
    address: Option<AddressClaim>,
    birthdate: Option<String>,
    updated_at: Option<NumericDate>,
    nationalities: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
struct AddressClaim {
    street_address: Option<String>,
    locality: Option<String>,
    region: Option<String>,
    country: Option<String>,
}

fn test_key() -> JWK {
    serde_json::from_value(serde_json::json!({
        "kty": "EC",
        "d": "oYVImrMZjUclmWuhqa6bjzqGx5HFkbx76_00oWUHiLw",
        "use": "sig",
        "crv": "P-256",
        "kid": "rpaXW8yADRnS2150CdsMtftwxtzSiVTV9bgHHG86v-E",
        "x": "UX7TC8uQ9sn06c3DxXy1Ua5V9BK-cb9fQfukVrCLD8s",
        "y": "yNXRKOnwBMTx536uajfNHklxpG9bAbdLlmVn6-XuK0Q",
        "alg": "ES256"
    }))
    .unwrap()
}

fn test_standard_sd_jwt() -> String {
    let key = test_key();
    let claims = serde_json::json!({
        "_sd": [
            "CrQe7S5kqBAHt-nMYXgc6bdt2SH5aTY1sU_M-PgkjPI",
            "JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE",
            "PorFbpKuVu6xymJagvkFsFXAbRoc2JGlAUA2BA4o7cI",
            "TGf4oLbgwd5JQaHyKVQZU9UdGE0w5rtDsrZzfUaomLo",
            "XQ_3kPKt1XyX7KANkqVR6yZ2Va5NrPIvPYbyMvRKBMM",
            "XzFrzwscM6Gn6CJDc6vVK8BkMnfG8vOSKfpPIZdAfdE",
            "gbOsI4Edq2x2Kw-w5wPEzakob9hV1cRD0ATN3oQL9JM",
            "jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4"
        ],
        "iss": "https://example.com/issuer",
        "iat": 1683000000,
        "exp": 1883000000,
        "sub": "user_42",
        "nationalities": [
            { "...": "pFndjkZ_VCzmyTa6UjlZo3dh-ko8aIKQc9DlGzhaVYo" },
            { "...": "7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0" }
        ],
        "_sd_alg": "sha-256"
    });

    ssi_jwt::encode_sign(Algorithm::ES256, &claims, &key).unwrap()
}

// *Claim email*:
// *  SHA-256 Hash: JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE
// *  Disclosure:
//     WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VA
//     ZXhhbXBsZS5jb20iXQ
// *  Contents: ["6Ij7tM-a5iVPGboS5tmvVA", "email",
//     "johndoe@example.com"]
const EMAIL_DISCLOSURE: &'static str =
    "WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ";

// *Array Entry*:
// *  SHA-256 Hash: 7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0
// *  Disclosure:
//    WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0
// *  Contents: ["nPuoQnkRFq3BIeAm7AnXFA", "DE"]
const NATIONALITY_DE_DISCLOSURE: &'static str = "WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0";

#[test]
fn decode_single() {
    let claims = decode_verify_disclosure_array::<ExampleClaims>(
        Deserialized {
            jwt: &test_standard_sd_jwt(),
            disclosures: vec![EMAIL_DISCLOSURE],
        },
        &test_key(),
    )
    .unwrap();

    assert_eq!(
        claims,
        ExampleClaims {
            sub: Some("user_42".to_owned()),
            email: Some("johndoe@example.com".to_owned()),
            nationalities: Some(vec![]),
            ..Default::default()
        },
    )
}

#[test]
fn decode_single_array_item() {
    let claims = decode_verify_disclosure_array::<ExampleClaims>(
        Deserialized {
            jwt: &test_standard_sd_jwt(),
            disclosures: vec![NATIONALITY_DE_DISCLOSURE],
        },
        &test_key(),
    )
    .unwrap();

    assert_eq!(
        claims,
        ExampleClaims {
            sub: Some("user_42".to_owned()),
            nationalities: Some(vec!["DE".to_owned()]),
            ..Default::default()
        },
    )
}
