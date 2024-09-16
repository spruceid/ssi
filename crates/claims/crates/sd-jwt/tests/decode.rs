use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use ssi_jwk::JWK;
use ssi_jws::{JwsBuf, JwsPayload};
use ssi_jwt::{JWTClaims, NumericDate};
use ssi_sd_jwt::{disclosure, Disclosure, PartsRef};

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
struct ExampleClaims {
    #[serde(skip_serializing_if = "Option::is_none")]
    given_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    family_name: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    email: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    phone_number: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    phone_number_verified: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    address: Option<AddressClaim>,

    #[serde(skip_serializing_if = "Option::is_none")]
    birthdate: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    updated_at: Option<NumericDate>,

    #[serde(skip_serializing_if = "Option::is_none")]
    nationalities: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize, Serialize, PartialEq)]
struct AddressClaim {
    #[serde(skip_serializing_if = "Option::is_none")]
    street_address: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    locality: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    region: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    country: Option<String>,
}

static JWK: LazyLock<JWK> = LazyLock::new(|| {
    serde_json::json!({
        "kty": "EC",
        "d": "oYVImrMZjUclmWuhqa6bjzqGx5HFkbx76_00oWUHiLw",
        "use": "sig",
        "crv": "P-256",
        "kid": "rpaXW8yADRnS2150CdsMtftwxtzSiVTV9bgHHG86v-E",
        "x": "UX7TC8uQ9sn06c3DxXy1Ua5V9BK-cb9fQfukVrCLD8s",
        "y": "yNXRKOnwBMTx536uajfNHklxpG9bAbdLlmVn6-XuK0Q",
        "alg": "ES256"
    })
    .try_into()
    .unwrap()
});

static UNDISCLOSED_CLAIMS: LazyLock<Value> = LazyLock::new(|| {
    json!({
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
    })
});

async fn test_standard_sd_jwt() -> JwsBuf {
    (*UNDISCLOSED_CLAIMS).sign(&*JWK).await.unwrap()
}

// *Claim email*:
// *  SHA-256 Hash: JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE
// *  Disclosure:
//     WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VA
//     ZXhhbXBsZS5jb20iXQ
// *  Contents: ["6Ij7tM-a5iVPGboS5tmvVA", "email",
//     "johndoe@example.com"]
const EMAIL_DISCLOSURE: &Disclosure =
    disclosure!("WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ");

// *Array Entry*:
// *  SHA-256 Hash: 7Cf6JkPudry3lcbwHgeZ8khAv1U1OSlerP0VkBJrWZ0
// *  Disclosure:
//    WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0
// *  Contents: ["nPuoQnkRFq3BIeAm7AnXFA", "DE"]
const NATIONALITY_DE_DISCLOSURE: &Disclosure =
    disclosure!("WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0");

#[async_std::test]
async fn disclose_single() {
    let jwt = test_standard_sd_jwt().await;

    let sd_jwt = PartsRef::new(&jwt, vec![EMAIL_DISCLOSURE]);

    let disclosed = sd_jwt.decode().unwrap().reveal::<ExampleClaims>().unwrap();

    let expected = JWTClaims::builder()
        .iss("https://example.com/issuer")
        .iat(1683000000)
        .exp(1883000000)
        .sub("user_42")
        .with_private_claims(ExampleClaims {
            email: Some("johndoe@example.com".to_owned()),
            nationalities: Some(vec![]),
            ..Default::default()
        })
        .unwrap();

    eprintln!(
        "found    = {}",
        serde_json::to_string_pretty(disclosed.claims()).unwrap()
    );
    eprintln!(
        "expected = {}",
        serde_json::to_string_pretty(&expected).unwrap()
    );

    assert_eq!(disclosed.into_claims(), expected);
}

#[async_std::test]
async fn decode_single_array_item() {
    let jwt = test_standard_sd_jwt().await;

    let sd_jwt = PartsRef::new(&jwt, vec![NATIONALITY_DE_DISCLOSURE]);

    let disclosed = sd_jwt.decode().unwrap().reveal::<ExampleClaims>().unwrap();

    assert_eq!(
        disclosed.into_claims(),
        JWTClaims::builder()
            .iss("https://example.com/issuer")
            .iat(1683000000)
            .exp(1883000000)
            .sub("user_42")
            .with_private_claims(ExampleClaims {
                nationalities: Some(vec!["DE".to_owned()]),
                ..Default::default()
            })
            .unwrap()
    )
}
