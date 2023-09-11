use serde::{Deserialize, Serialize};
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
            UnencodedDisclosure::Claim("disclosure0".to_owned(), serde_json::json!("value0")),
            UnencodedDisclosure::Claim("disclosure1".to_owned(), serde_json::json!("value1")),
        ],
    )
    .unwrap();

    let (_, full_jwt_claims) = decode_verify::<BaseClaims>(
        &jwt,
        &test_key(),
        &[&disclosures[0].encoded, &disclosures[1].encoded],
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

    let (_, one_sd_claim) =
        decode_verify::<BaseClaims>(&jwt, &test_key(), &[&disclosures[1].encoded]).unwrap();

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
            UnencodedDisclosure::ArrayItem(
                "array_disclosure".to_owned(),
                serde_json::json!("value0"),
            ),
            UnencodedDisclosure::ArrayItem(
                "array_disclosure".to_owned(),
                serde_json::json!("value1"),
            ),
        ],
    )
    .unwrap();

    let (_, full_jwt_claims) = decode_verify::<BaseClaims>(
        &jwt,
        &test_key(),
        &[&disclosures[0].encoded, &disclosures[1].encoded],
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
