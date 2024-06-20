use serde::{Deserialize, Serialize};
use serde_json::json;
use ssi_jwk::{Algorithm, JWK};
use ssi_sd_jwt::*;

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

#[test]
fn full_pathway_regular_claim() {
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct BaseClaims {
        sub: String,
        disclosure0: Option<String>,
        disclosure1: Option<String>,
    }

    let base_claims = BaseClaims {
        sub: "user".to_owned(),
        disclosure0: None,
        disclosure1: None,
    };

    let (jwt, disclosures) = encode_sign(
        Algorithm::ES256,
        &base_claims,
        &test_key(),
        SdAlg::Sha256,
        vec![
            UnencodedDisclosure::new_property("disclosure0", &json!("value0")).unwrap(),
            UnencodedDisclosure::new_property("disclosure1", &json!("value1")).unwrap(),
        ],
    )
    .unwrap();

    let full_jwt_claims = decode_verify_disclosure_array::<BaseClaims>(
        Deserialized {
            jwt: &jwt,
            disclosures: vec![&disclosures[0].encoded, &disclosures[1].encoded],
        },
        &test_key(),
    )
    .unwrap();

    assert_eq!(
        BaseClaims {
            sub: "user".to_owned(),
            disclosure0: Some("value0".to_owned()),
            disclosure1: Some("value1".to_owned()),
        },
        full_jwt_claims,
    );

    let one_sd_claim = decode_verify_disclosure_array::<BaseClaims>(
        Deserialized {
            jwt: &jwt,
            disclosures: vec![&disclosures[1].encoded],
        },
        &test_key(),
    )
    .unwrap();

    assert_eq!(
        BaseClaims {
            sub: "user".to_owned(),
            disclosure0: None,
            disclosure1: Some("value1".to_owned())
        },
        one_sd_claim,
    );
}

#[test]
fn full_pathway_array() {
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct BaseClaims {
        sub: String,
        array_disclosure: Vec<String>,
    }

    let base_claims = BaseClaims {
        sub: "user".to_owned(),
        array_disclosure: vec![],
    };

    let (jwt, disclosures) = encode_sign(
        Algorithm::ES256,
        &base_claims,
        &test_key(),
        SdAlg::Sha256,
        vec![
            UnencodedDisclosure::new_array_item("array_disclosure", &json!("value0")).unwrap(),
            UnencodedDisclosure::new_array_item("array_disclosure", &json!("value1")).unwrap(),
        ],
    )
    .unwrap();

    let full_jwt_claims = decode_verify_disclosure_array::<BaseClaims>(
        Deserialized {
            jwt: &jwt,
            disclosures: vec![&disclosures[0].encoded, &disclosures[1].encoded],
        },
        &test_key(),
    )
    .unwrap();

    assert_eq!(
        BaseClaims {
            sub: "user".to_owned(),
            array_disclosure: vec!["value0".to_owned(), "value1".to_owned()],
        },
        full_jwt_claims
    );
}

#[test]
fn nested_claims() {
    const SD_ALG: SdAlg = SdAlg::Sha256;

    // Decode types
    #[derive(Debug, Deserialize, PartialEq)]
    struct InnerNestedClaim {
        inner_property: String,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct OuterNestedClaim {
        inner: Option<InnerNestedClaim>,
    }

    #[derive(Debug, Deserialize, PartialEq)]
    struct Claims {
        sub: String,
        outer: Option<OuterNestedClaim>,
    }

    // Manually encode
    let inner_disclosure = encode_property_disclosure(
        SD_ALG,
        "inner",
        &serde_json::json!({"inner_property": "value"}),
    )
    .unwrap();

    let outer_disclosure = encode_property_disclosure(
        SD_ALG,
        "outer",
        &serde_json::json!({
            "_sd": [
                inner_disclosure.hash
            ]
        }),
    )
    .unwrap();

    let jwt = ssi_jwt::encode_sign(
        Algorithm::ES256,
        &serde_json::json!({
            "_sd": [
                outer_disclosure.hash
            ],
            "_sd_alg": SD_ALG.to_str(),
            "sub": "user",
        }),
        &test_key(),
    )
    .unwrap();

    // No claims provided
    let no_sd_claims = decode_verify_disclosure_array::<Claims>(
        Deserialized {
            jwt: &jwt,
            disclosures: vec![],
        },
        &test_key(),
    )
    .unwrap();
    assert_eq!(
        no_sd_claims,
        Claims {
            sub: "user".to_owned(),
            outer: None,
        }
    );

    // Outer provided
    let outer_provided = decode_verify_disclosure_array::<Claims>(
        Deserialized {
            jwt: &jwt,
            disclosures: vec![&outer_disclosure.encoded],
        },
        &test_key(),
    )
    .unwrap();

    assert_eq!(
        outer_provided,
        Claims {
            sub: "user".to_owned(),
            outer: Some(OuterNestedClaim { inner: None })
        }
    );

    // Inner and outer provided
    let inner_and_outer_provided = decode_verify_disclosure_array::<Claims>(
        Deserialized {
            jwt: &jwt,
            disclosures: vec![&outer_disclosure.encoded, &inner_disclosure.encoded],
        },
        &test_key(),
    )
    .unwrap();

    assert_eq!(
        inner_and_outer_provided,
        Claims {
            sub: "user".to_owned(),
            outer: Some(OuterNestedClaim {
                inner: Some(InnerNestedClaim {
                    inner_property: "value".to_owned(),
                })
            })
        }
    );

    // Inner without outer errors
    let result = decode_verify_disclosure_array::<Claims>(
        Deserialized {
            jwt: &jwt,
            disclosures: vec![&inner_disclosure.encoded],
        },
        &test_key(),
    );

    assert!(result.is_err());
}
