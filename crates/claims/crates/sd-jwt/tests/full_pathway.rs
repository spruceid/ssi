use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use serde_json::json;
use ssi_claims_core::{ValidateClaims, VerificationParameters};
use ssi_core::json_pointer;
use ssi_jwk::JWK;
use ssi_jwt::{ClaimSet, JWTClaims};
use ssi_sd_jwt::*;

static JWK: LazyLock<JWK> = LazyLock::new(|| {
    json!({
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

#[async_std::test]
async fn full_pathway_regular_claim() {
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct BaseClaims {
        property0: Option<String>,
        property1: Option<String>,
    }

    impl ClaimSet for BaseClaims {}
    impl<E, P> ValidateClaims<E, P> for BaseClaims {}

    let base_claims = JWTClaims::builder()
        .sub("user")
        .with_private_claims(BaseClaims {
            property0: Some("value0".to_owned()),
            property1: Some("value1".to_owned()),
        })
        .unwrap();

    let sd_jwt = base_claims
        .conceal_and_sign(
            SdAlg::Sha256,
            &[json_pointer!("/property0"), json_pointer!("/property1")],
            &*JWK,
        )
        .await
        .unwrap();

    let params = VerificationParameters::from_resolver(&*JWK);

    let (mut revealed, verification) = sd_jwt
        .decode_reveal_verify::<BaseClaims, _>(&params)
        .await
        .unwrap();

    assert_eq!(verification, Ok(()));
    assert_eq!(*revealed.claims(), base_claims);

    // Retain only the `property1` property disclosure.
    revealed.retain(&[json_pointer!("/property1")]);

    let sd_jwt = revealed.into_encoded();

    let (revealed, verification) = sd_jwt
        .decode_reveal_verify::<BaseClaims, _>(params)
        .await
        .unwrap();

    assert_eq!(verification, Ok(()));
    assert_eq!(
        *revealed.claims(),
        JWTClaims::builder()
            .sub("user")
            .with_private_claims(BaseClaims {
                property0: None, // concealed
                property1: Some("value1".to_owned()),
            })
            .unwrap()
    );
}

#[async_std::test]
async fn full_pathway_array() {
    #[derive(Debug, Serialize, Deserialize, PartialEq)]
    struct BaseClaims {
        array_disclosure: Vec<String>,
    }

    impl ClaimSet for BaseClaims {}
    impl<E, P> ValidateClaims<E, P> for BaseClaims {}

    let base_claims = JWTClaims::builder()
        .sub("user")
        .with_private_claims(BaseClaims {
            array_disclosure: vec!["value0".to_owned(), "value1".to_owned()],
        })
        .unwrap();

    let sd_jwt = base_claims
        .conceal_and_sign(
            SdAlg::Sha256,
            &[
                json_pointer!("/array_disclosure/0"),
                json_pointer!("/array_disclosure/1"),
            ],
            &*JWK,
        )
        .await
        .unwrap();

    let params = VerificationParameters::from_resolver(&*JWK);

    let (mut revealed, verification) = sd_jwt
        .decode_reveal_verify::<BaseClaims, _>(&params)
        .await
        .unwrap();

    assert_eq!(verification, Ok(()));
    assert_eq!(*revealed.claims(), base_claims);

    // Retain only the second item disclosure.
    revealed.retain(&[json_pointer!("/array_disclosure/1")]);

    let sd_jwt = revealed.into_encoded();

    let (revealed, verification) = sd_jwt
        .decode_reveal_verify::<BaseClaims, _>(params)
        .await
        .unwrap();

    assert_eq!(verification, Ok(()));
    assert_eq!(
        *revealed.claims(),
        JWTClaims::builder()
            .sub("user")
            .with_private_claims(BaseClaims {
                array_disclosure: vec!["value1".to_owned()]
            })
            .unwrap()
    );
}

#[async_std::test]
async fn nested_claims() {
    // Decode types
    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct InnerNestedClaim {
        inner_property: String,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct OuterNestedClaim {
        inner: Option<InnerNestedClaim>,
    }

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct Claims {
        outer: Option<OuterNestedClaim>,
    }

    impl ClaimSet for Claims {}
    impl<E, P> ValidateClaims<E, P> for Claims {}

    let base_claims = JWTClaims::builder()
        .sub("user")
        .with_private_claims(Claims {
            outer: Some(OuterNestedClaim {
                inner: Some(InnerNestedClaim {
                    inner_property: "value".to_owned(),
                }),
            }),
        })
        .unwrap();

    // Conceal the base claims.
    base_claims
        .conceal_and_sign(
            SdAlg::Sha256,
            &[json_pointer!("/outer"), json_pointer!("/outer/inner")],
            &*JWK,
        )
        .await
        .unwrap();

    // Conceal again but changing the order of pointers (this should have no effect).
    let base_sd_jwt = base_claims
        .conceal_and_sign(
            SdAlg::Sha256,
            &[json_pointer!("/outer/inner"), json_pointer!("/outer")],
            &*JWK,
        )
        .await
        .unwrap();

    let inner_revealed = base_sd_jwt.decode_reveal::<Claims>().unwrap();

    let params = VerificationParameters::from_resolver(&*JWK);

    let empty_sd_jwt = inner_revealed.clone().cleared().into_encoded();

    let (empty_revealed, verification) = empty_sd_jwt
        .decode_reveal_verify::<Claims, _>(&params)
        .await
        .unwrap();

    assert_eq!(verification, Ok(()));
    assert_eq!(
        *empty_revealed.claims(),
        JWTClaims::builder()
            .sub("user")
            .with_private_claims(Claims { outer: None })
            .unwrap()
    );

    let full_sd_jwt = inner_revealed
        .clone()
        .retaining(&[json_pointer!("/outer"), json_pointer!("/outer/inner")])
        .into_encoded();

    let (full_revealed, verification) = full_sd_jwt
        .decode_reveal_verify::<Claims, _>(&params)
        .await
        .unwrap();

    assert_eq!(verification, Ok(()));
    assert_eq!(*full_revealed.claims(), base_claims);

    let outer_sd_jwt = inner_revealed
        .clone()
        .retaining(&[json_pointer!("/outer")])
        .into_encoded();

    let (full_revealed, verification) = outer_sd_jwt
        .decode_reveal_verify::<Claims, _>(&params)
        .await
        .unwrap();

    assert_eq!(verification, Ok(()));
    assert_eq!(
        *full_revealed.claims(),
        JWTClaims::builder()
            .sub("user")
            .with_private_claims(Claims {
                outer: Some(OuterNestedClaim { inner: None })
            })
            .unwrap()
    );

    let inner_sd_jwt = inner_revealed
        .clone()
        .retaining(&[json_pointer!("/outer/inner")])
        .into_encoded();

    let result = inner_sd_jwt
        .decode_reveal_verify::<Claims, _>(&params)
        .await;

    assert!(result.is_err());
}
