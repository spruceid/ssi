use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use serde_json::json;
use ssi_claims_core::{ValidateClaims, VerificationParameters};
use ssi_core::json_pointer;
use ssi_jwk::JWK;
use ssi_jws::{jws, Jws};
use ssi_jwt::{ClaimSet, JWTClaims};
use ssi_sd_jwt::{disclosure, Disclosure, PartsRef};

static JWK: LazyLock<JWK> = LazyLock::new(|| {
    json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "b28d4MwZMjw8-00CG4xfnn9SLMVMM19SlqZpVb_uNtQ",
        "y": "Xv5zWwuoaTgdS6hV43yI6gBwTnjukmFQQnJ_kCxzqk8"
    })
    .try_into()
    .unwrap()
});

#[async_std::test]
async fn rfc_a_1_example_2_verification() {
    #[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
    struct Example2Address {
        #[serde(skip_serializing_if = "Option::is_none")]
        street_address: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        locality: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        region: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        country: Option<String>,
    }

    #[derive(Debug, Default, Clone, Serialize, Deserialize, PartialEq)]
    struct Example2Claims {
        #[serde(skip_serializing_if = "Option::is_none")]
        given_name: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        family_name: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        email: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        phone_number: Option<String>,

        address: Example2Address,

        #[serde(skip_serializing_if = "Option::is_none")]
        birthdate: Option<String>,
    }

    impl ClaimSet for Example2Claims {}
    impl<E, P> ValidateClaims<E, P> for Example2Claims {}

    const JWT: &Jws = jws!("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIkM5aW5wNllvUmFFWFI0Mjd6WUpQN1FyazFXSF84YmR3T0FfWVVyVW5HUVUiLCAiS3VldDF5QWEwSElRdlluT1ZkNTloY1ZpTzlVZzZKMmtTZnFZUkJlb3d2RSIsICJNTWxkT0ZGekIyZDB1bWxtcFRJYUdlcmhXZFVfUHBZZkx2S2hoX2ZfOWFZIiwgIlg2WkFZT0lJMnZQTjQwVjd4RXhad1Z3ejd5Um1MTmNWd3Q1REw4Ukx2NGciLCAiWTM0em1JbzBRTExPdGRNcFhHd2pCZ0x2cjE3eUVoaFlUMEZHb2ZSLWFJRSIsICJmeUdwMFdUd3dQdjJKRFFsbjFsU2lhZW9iWnNNV0ExMGJRNTk4OS05RFRzIiwgIm9tbUZBaWNWVDhMR0hDQjB1eXd4N2ZZdW8zTUhZS08xNWN6LVJaRVlNNVEiLCAiczBCS1lzTFd4UVFlVTh0VmxsdE03TUtzSVJUckVJYTFQa0ptcXhCQmY1VSJdLCAiaXNzIjogImh0dHBzOi8vaXNzdWVyLmV4YW1wbGUuY29tIiwgImlhdCI6IDE2ODMwMDAwMDAsICJleHAiOiAxODgzMDAwMDAwLCAiYWRkcmVzcyI6IHsiX3NkIjogWyI2YVVoelloWjdTSjFrVm1hZ1FBTzN1MkVUTjJDQzFhSGhlWnBLbmFGMF9FIiwgIkF6TGxGb2JrSjJ4aWF1cFJFUHlvSnotOS1OU2xkQjZDZ2pyN2ZVeW9IemciLCAiUHp6Y1Z1MHFiTXVCR1NqdWxmZXd6a2VzRDl6dXRPRXhuNUVXTndrclEtayIsICJiMkRrdzBqY0lGOXJHZzhfUEY4WmN2bmNXN3p3Wmo1cnlCV3ZYZnJwemVrIiwgImNQWUpISVo4VnUtZjlDQ3lWdWIyVWZnRWs4anZ2WGV6d0sxcF9KbmVlWFEiLCAiZ2xUM2hyU1U3ZlNXZ3dGNVVEWm1Xd0JUdzMyZ25VbGRJaGk4aEdWQ2FWNCIsICJydkpkNmlxNlQ1ZWptc0JNb0d3dU5YaDlxQUFGQVRBY2k0MG9pZEVlVnNBIiwgInVOSG9XWWhYc1poVkpDTkUyRHF5LXpxdDd0NjlnSkt5NVFhRnY3R3JNWDQiXX0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.H0uI6M5t7BDfAt_a3Rw5zq4IiYNtkMORENcQFXYkW1LURRp66baOXRcxb164snsUJneI-XLM2-COCTX1y7Sedw");

    const SUB_CLAIM_DISCLOSURE: &Disclosure =
        disclosure!("WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInN1YiIsICI2YzVjMGE0OS1iNTg5LTQzMWQtYmFlNy0yMTkxMjJhOWVjMmMiXQ");
    const GIVEN_NAME_DISCLOSURE: &Disclosure =
        disclosure!("WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgImdpdmVuX25hbWUiLCAiXHU1OTJhXHU5MGNlIl0");
    const FAMILY_NAME_DISCLOSURE: &Disclosure =
        disclosure!("WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImZhbWlseV9uYW1lIiwgIlx1NWM3MVx1NzUzMCJd");
    const EMAIL_CLAIM_DISCLOSURE: &Disclosure =
        disclosure!("WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgImVtYWlsIiwgIlwidW51c3VhbCBlbWFpbCBhZGRyZXNzXCJAZXhhbXBsZS5qcCJd");
    const PHONE_NUMBER_DISCLOSURE: &Disclosure = disclosure!(
        "WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInBob25lX251bWJlciIsICIrODEtODAtMTIzNC01Njc4Il0"
    );
    const ADDRESS_STREET_ADDRESS_DISCLOSURES: &Disclosure =
        disclosure!("WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgInN0cmVldF9hZGRyZXNzIiwgIlx1Njc3MVx1NGVhY1x1OTBmZFx1NmUyZlx1NTMzYVx1ODI5ZFx1NTE2Y1x1NTcxMlx1ZmYxNFx1NGUwMVx1NzZlZVx1ZmYxMlx1MjIxMlx1ZmYxOCJd");
    const ADDRESS_LOCALITY_DISCLOSURE: &Disclosure = disclosure!(
        "WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgImxvY2FsaXR5IiwgIlx1Njc3MVx1NGVhY1x1OTBmZCJd"
    );
    const ADDRESS_REGION_DISCLOSURE: &Disclosure =
        disclosure!("WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgInJlZ2lvbiIsICJcdTZlMmZcdTUzM2EiXQ");
    const ADDRESS_COUNTRY_DISCLOSURE: &Disclosure =
        disclosure!("WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImNvdW50cnkiLCAiSlAiXQ");
    const BIRTHDATE_DISCLOSURE: &Disclosure =
        disclosure!("WyJ5eXRWYmRBUEdjZ2wyckk0QzlHU29nIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0");

    let sd_jwt = PartsRef {
        jwt: JWT,
        disclosures: vec![
            SUB_CLAIM_DISCLOSURE,
            GIVEN_NAME_DISCLOSURE,
            FAMILY_NAME_DISCLOSURE,
            EMAIL_CLAIM_DISCLOSURE,
            PHONE_NUMBER_DISCLOSURE,
            ADDRESS_STREET_ADDRESS_DISCLOSURES,
            ADDRESS_LOCALITY_DISCLOSURE,
            ADDRESS_REGION_DISCLOSURE,
            ADDRESS_COUNTRY_DISCLOSURE,
            BIRTHDATE_DISCLOSURE,
        ],
    };

    let params = VerificationParameters::from_resolver(&*JWK);

    let (revealed, verification) = sd_jwt
        .decode_reveal_verify::<Example2Claims, _>(&params)
        .await
        .unwrap();

    assert_eq!(verification, Ok(()));

    let expected = JWTClaims::builder()
        .sub("6c5c0a49-b589-431d-bae7-219122a9ec2c")
        .iss("https://issuer.example.com")
        .iat(1683000000)
        .exp(1883000000)
        .with_private_claims(Example2Claims {
            given_name: Some("太郎".to_owned()),
            family_name: Some("山田".to_owned()),
            email: Some("\"unusual email address\"@example.jp".to_owned()),
            phone_number: Some("+81-80-1234-5678".to_owned()),
            address: Example2Address {
                street_address: Some("東京都港区芝公園４丁目２−８".to_owned()),
                locality: Some("東京都".to_owned()),
                region: Some("港区".to_owned()),
                country: Some("JP".to_owned()),
            },
            birthdate: Some("1940-01-01".to_owned()),
        })
        .unwrap();

    eprintln!(
        "expected = {}",
        serde_json::to_string_pretty(&expected).unwrap()
    );
    eprintln!(
        "found    = {}",
        serde_json::to_string_pretty(revealed.claims()).unwrap()
    );

    assert_eq!(*revealed.claims(), expected);

    let empty_sd_jwt = revealed.clone().cleared().into_encoded();

    let (empty_revealed, verification) = empty_sd_jwt.decode_reveal_verify(&params).await.unwrap();

    assert_eq!(verification, Ok(()));

    let expected = JWTClaims::builder()
        .iss("https://issuer.example.com")
        .iat(1683000000)
        .exp(1883000000)
        .with_private_claims(Example2Claims::default())
        .unwrap();

    eprintln!(
        "expected = {}",
        serde_json::to_string_pretty(&expected).unwrap()
    );
    eprintln!(
        "found    = {}",
        serde_json::to_string_pretty(empty_revealed.claims()).unwrap()
    );

    assert_eq!(*empty_revealed.claims(), expected);

    let sub_sd_jwt = revealed
        .clone()
        .retaining(&[json_pointer!("/sub")])
        .into_encoded();

    let (sub_revealed, verification) = sub_sd_jwt.decode_reveal_verify(&params).await.unwrap();

    assert_eq!(verification, Ok(()));
    assert_eq!(
        *sub_revealed.claims(),
        JWTClaims::builder()
            .sub("6c5c0a49-b589-431d-bae7-219122a9ec2c")
            .iss("https://issuer.example.com")
            .iat(1683000000)
            .exp(1883000000)
            .with_private_claims(Example2Claims::default())
            .unwrap()
    );

    let country_sd_jwt = revealed
        .clone()
        .retaining(&[json_pointer!("/address/country")])
        .into_encoded();

    let (country_revealed, verification) =
        country_sd_jwt.decode_reveal_verify(&params).await.unwrap();

    assert_eq!(verification, Ok(()));

    let expected = JWTClaims::builder()
        .iss("https://issuer.example.com")
        .iat(1683000000)
        .exp(1883000000)
        .with_private_claims(Example2Claims {
            address: Example2Address {
                country: Some("JP".to_owned()),
                ..Default::default()
            },
            ..Default::default()
        })
        .unwrap();

    eprintln!(
        "expected = {}",
        serde_json::to_string_pretty(&expected).unwrap()
    );
    eprintln!(
        "found    = {}",
        serde_json::to_string_pretty(country_revealed.claims()).unwrap()
    );

    assert_eq!(*country_revealed.claims(), expected);
}

#[async_std::test]
async fn rfc_a_2_example_3_verification() {
    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct VerificationEvidenceDocumentIssuer {
        name: String,
        country: String,
    }

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct VerificationEvidenceDocument {
        #[serde(rename = "type")]
        _type: String,
        issuer: VerificationEvidenceDocumentIssuer,
        number: String,
        date_of_issuance: String,
        date_of_expiry: String,
    }

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct VerificationEvidence {
        #[serde(rename = "type", skip_serializing_if = "Option::is_none")]
        _type: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        method: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        time: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        document: Option<VerificationEvidenceDocument>,
    }

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct Verification {
        trust_framework: String,

        #[serde(skip_serializing_if = "Option::is_none")]
        time: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        verification_process: Option<String>,
        evidence: Vec<VerificationEvidence>,
    }

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct PlaceOfBirth {
        country: String,
        locality: String,
    }

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct Address {
        locality: String,
        postal_code: String,
        country: String,
        street_address: String,
    }

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct VerifiedClaimsClaims {
        #[serde(skip_serializing_if = "Option::is_none")]
        given_name: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        family_name: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        nationalities: Option<Vec<String>>,

        #[serde(skip_serializing_if = "Option::is_none")]
        birthdate: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        place_of_birth: Option<PlaceOfBirth>,

        #[serde(skip_serializing_if = "Option::is_none")]
        address: Option<Address>,
    }

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct VerifiedClaims {
        verification: Verification,
        claims: VerifiedClaimsClaims,
    }

    #[derive(Debug, Default, Serialize, Deserialize, PartialEq)]
    struct Example3Claims {
        verified_claims: VerifiedClaims,

        #[serde(skip_serializing_if = "Option::is_none")]
        birth_middle_name: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        salutation: Option<String>,

        #[serde(skip_serializing_if = "Option::is_none")]
        msisdn: Option<String>,
    }

    impl ClaimSet for Example3Claims {}
    impl<E, P> ValidateClaims<E, P> for Example3Claims {}

    const JWT: &Jws = jws!("eyJhbGciOiAiRVMyNTYiLCAidHlwIjogImV4YW1wbGUrc2Qtand0In0.eyJfc2QiOiBbIi1hU3puSWQ5bVdNOG9jdVFvbENsbHN4VmdncTEtdkhXNE90bmhVdFZtV3ciLCAiSUticllObjN2QTdXRUZyeXN2YmRCSmpERFVfRXZRSXIwVzE4dlRScFVTZyIsICJvdGt4dVQxNG5CaXd6TkozTVBhT2l0T2w5cFZuWE9hRUhhbF94a3lOZktJIl0sICJpc3MiOiAiaHR0cHM6Ly9pc3N1ZXIuZXhhbXBsZS5jb20iLCAiaWF0IjogMTY4MzAwMDAwMCwgImV4cCI6IDE4ODMwMDAwMDAsICJ2ZXJpZmllZF9jbGFpbXMiOiB7InZlcmlmaWNhdGlvbiI6IHsiX3NkIjogWyI3aDRVRTlxU2N2REtvZFhWQ3VvS2ZLQkpwVkJmWE1GX1RtQUdWYVplM1NjIiwgInZUd2UzcmFISUZZZ0ZBM3hhVUQyYU14Rno1b0RvOGlCdTA1cUtsT2c5THciXSwgInRydXN0X2ZyYW1ld29yayI6ICJkZV9hbWwiLCAiZXZpZGVuY2UiOiBbeyIuLi4iOiAidFlKMFREdWN5WlpDUk1iUk9HNHFSTzV2a1BTRlJ4RmhVRUxjMThDU2wzayJ9XX0sICJjbGFpbXMiOiB7Il9zZCI6IFsiUmlPaUNuNl93NVpIYWFka1FNcmNRSmYwSnRlNVJ3dXJSczU0MjMxRFRsbyIsICJTXzQ5OGJicEt6QjZFYW5mdHNzMHhjN2NPYW9uZVJyM3BLcjdOZFJtc01vIiwgIldOQS1VTks3Rl96aHNBYjlzeVdPNklJUTF1SGxUbU9VOHI4Q3ZKMGNJTWsiLCAiV3hoX3NWM2lSSDliZ3JUQkppLWFZSE5DTHQtdmpoWDFzZC1pZ09mXzlsayIsICJfTy13SmlIM2VuU0I0Uk9IbnRUb1FUOEptTHR6LW1oTzJmMWM4OVhvZXJRIiwgImh2RFhod21HY0pRc0JDQTJPdGp1TEFjd0FNcERzYVUwbmtvdmNLT3FXTkUiXX19LCAiX3NkX2FsZyI6ICJzaGEtMjU2In0.BYUpdUIaUTNj5UlPBk6g0GhDp213yGD_HIMk8P45LwkSAfZgc_ayGnf9VC4gebeE-crDoonxf89Y7qsTA-4qdQ");

    const VERIFIED_CLAIMS_TIME_DISCLOSURE: &Disclosure =
        disclosure!("WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgInRpbWUiLCAiMjAxMi0wNC0yM1QxODoyNVoiXQ");
    const VERIFIED_CLAIMS_VERIFICATION_PROCESS_DISCLOSURE: &Disclosure =
        disclosure!("WyJlbHVWNU9nM2dTTklJOEVZbnN4QV9BIiwgInZlcmlmaWNhdGlvbl9wcm9jZXNzIiwgImYyNGM2Zi02ZDNmLTRlYzUtOTczZS1iMGQ4NTA2ZjNiYzciXQ");
    const VERIFIED_CLAIMS_EVIDENCE_0_TYPE_DISCLOSURE: &Disclosure =
        disclosure!("WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgInR5cGUiLCAiZG9jdW1lbnQiXQ");
    const VERIFIED_CLAIMS_EVIDENCE_0_METHOD_DISCLOSURE: &Disclosure =
        disclosure!("WyJlSThaV205UW5LUHBOUGVOZW5IZGhRIiwgIm1ldGhvZCIsICJwaXBwIl0");
    const VERIFIED_CLAIMS_EVIDENCE_0_TIME_DISCLOSURE: &Disclosure =
        disclosure!("WyJRZ19PNjR6cUF4ZTQxMmExMDhpcm9BIiwgInRpbWUiLCAiMjAxMi0wNC0yMlQxMTozMFoiXQ");
    const VERIFIED_CLAIMS_EVIDENCE_0_DOCUMENT_DISCLOSURE: &Disclosure =
        disclosure!("WyJBSngtMDk1VlBycFR0TjRRTU9xUk9BIiwgImRvY3VtZW50IiwgeyJ0eXBlIjogImlkY2FyZCIsICJpc3N1ZXIiOiB7Im5hbWUiOiAiU3RhZHQgQXVnc2J1cmciLCAiY291bnRyeSI6ICJERSJ9LCAibnVtYmVyIjogIjUzNTU0NTU0IiwgImRhdGVfb2ZfaXNzdWFuY2UiOiAiMjAxMC0wMy0yMyIsICJkYXRlX29mX2V4cGlyeSI6ICIyMDIwLTAzLTIyIn1d");
    const VERIFIED_CLAIMS_EVIDENCE_0_DISCLOSURE: &Disclosure =
        disclosure!("WyJQYzMzSk0yTGNoY1VfbEhnZ3ZfdWZRIiwgeyJfc2QiOiBbIjl3cGpWUFd1RDdQSzBuc1FETDhCMDZsbWRnVjNMVnliaEh5ZFFwVE55TEkiLCAiRzVFbmhPQU9vVTlYXzZRTU52ekZYanBFQV9SYy1BRXRtMWJHX3djYUtJayIsICJJaHdGcldVQjYzUmNacTl5dmdaMFhQYzdHb3doM08ya3FYZUJJc3dnMUI0IiwgIldweFE0SFNvRXRjVG1DQ0tPZURzbEJfZW11Y1lMejJvTzhvSE5yMWJFVlEiXX1d");
    const VERIFIED_CLAIMS_CLAIMS_GIVEN_NAME_DISCLOSURE: &Disclosure =
        disclosure!("WyJHMDJOU3JRZmpGWFE3SW8wOXN5YWpBIiwgImdpdmVuX25hbWUiLCAiTWF4Il0");
    const VERIFIED_CLAIMS_CLAIMS_FAMILY_NAME_DISCLOSURE: &Disclosure =
        disclosure!("WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImZhbWlseV9uYW1lIiwgIk1cdTAwZmNsbGVyIl0");
    const VERIFIED_CLAIMS_CLAIMS_NATIONALITIES_DISCLOSURE: &Disclosure =
        disclosure!("WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIm5hdGlvbmFsaXRpZXMiLCBbIkRFIl1d");
    const VERIFIED_CLAIMS_CLAIMS_BIRTHDATE_DISCLOSURE: &Disclosure =
        disclosure!("WyI1YlBzMUlxdVpOYTBoa2FGenp6Wk53IiwgImJpcnRoZGF0ZSIsICIxOTU2LTAxLTI4Il0");
    const VERIFIED_CLAIMS_CLAIMS_PLACE_OF_BIRTH_DISCLOSURE: &Disclosure =
        disclosure!("WyI1YTJXMF9OcmxFWnpmcW1rXzdQcS13IiwgInBsYWNlX29mX2JpcnRoIiwgeyJjb3VudHJ5IjogIklTIiwgImxvY2FsaXR5IjogIlx1MDBkZXlra3ZhYlx1MDBlNmphcmtsYXVzdHVyIn1d");
    const VERIFIED_CLAIMS_CLAIMS_ADDRESS_DISCLOSURE: &Disclosure =
        disclosure!("WyJ5MXNWVTV3ZGZKYWhWZGd3UGdTN1JRIiwgImFkZHJlc3MiLCB7ImxvY2FsaXR5IjogIk1heHN0YWR0IiwgInBvc3RhbF9jb2RlIjogIjEyMzQ0IiwgImNvdW50cnkiOiAiREUiLCAic3RyZWV0X2FkZHJlc3MiOiAiV2VpZGVuc3RyYVx1MDBkZmUgMjIifV0");
    const BIRTH_MIDDLE_NAME_DISCLOSURE: &Disclosure = disclosure!(
        "WyJIYlE0WDhzclZXM1FEeG5JSmRxeU9BIiwgImJpcnRoX21pZGRsZV9uYW1lIiwgIlRpbW90aGV1cyJd"
    );
    const SALUTATION_DISCLOSURE: &Disclosure =
        disclosure!("WyJDOUdTb3VqdmlKcXVFZ1lmb2pDYjFBIiwgInNhbHV0YXRpb24iLCAiRHIuIl0");
    const MSISDN_DISCLOSURE: &Disclosure =
        disclosure!("WyJreDVrRjE3Vi14MEptd1V4OXZndnR3IiwgIm1zaXNkbiIsICI0OTEyMzQ1Njc4OSJd");

    let params = VerificationParameters::from_resolver(&*JWK);

    let (revealed, verification) = PartsRef {
        jwt: JWT,
        disclosures: vec![
            VERIFIED_CLAIMS_TIME_DISCLOSURE,
            VERIFIED_CLAIMS_VERIFICATION_PROCESS_DISCLOSURE,
            VERIFIED_CLAIMS_EVIDENCE_0_TYPE_DISCLOSURE,
            VERIFIED_CLAIMS_EVIDENCE_0_METHOD_DISCLOSURE,
            VERIFIED_CLAIMS_EVIDENCE_0_TIME_DISCLOSURE,
            VERIFIED_CLAIMS_EVIDENCE_0_DOCUMENT_DISCLOSURE,
            VERIFIED_CLAIMS_EVIDENCE_0_DISCLOSURE,
            VERIFIED_CLAIMS_CLAIMS_GIVEN_NAME_DISCLOSURE,
            VERIFIED_CLAIMS_CLAIMS_FAMILY_NAME_DISCLOSURE,
            VERIFIED_CLAIMS_CLAIMS_NATIONALITIES_DISCLOSURE,
            VERIFIED_CLAIMS_CLAIMS_BIRTHDATE_DISCLOSURE,
            VERIFIED_CLAIMS_CLAIMS_PLACE_OF_BIRTH_DISCLOSURE,
            VERIFIED_CLAIMS_CLAIMS_ADDRESS_DISCLOSURE,
            BIRTH_MIDDLE_NAME_DISCLOSURE,
            SALUTATION_DISCLOSURE,
            MSISDN_DISCLOSURE,
        ],
    }
    .decode_reveal_verify(&params)
    .await
    .unwrap();

    assert_eq!(verification, Ok(()));
    assert_eq!(
        *revealed.claims(),
        JWTClaims::builder()
            .iss("https://issuer.example.com")
            .iat(1683000000)
            .exp(1883000000)
            .with_private_claims(Example3Claims {
                verified_claims: VerifiedClaims {
                    verification: Verification {
                        trust_framework: "de_aml".to_owned(),
                        time: Some("2012-04-23T18:25Z".to_owned()),
                        verification_process: Some("f24c6f-6d3f-4ec5-973e-b0d8506f3bc7".to_owned()),
                        evidence: vec![VerificationEvidence {
                            _type: Some("document".to_owned()),
                            method: Some("pipp".to_owned()),
                            time: Some("2012-04-22T11:30Z".to_owned()),
                            document: Some(VerificationEvidenceDocument {
                                _type: "idcard".to_owned(),
                                issuer: VerificationEvidenceDocumentIssuer {
                                    name: "Stadt Augsburg".to_owned(),
                                    country: "DE".to_owned(),
                                },
                                number: "53554554".to_owned(),
                                date_of_issuance: "2010-03-23".to_owned(),
                                date_of_expiry: "2020-03-22".to_owned(),
                            })
                        }],
                    },
                    claims: VerifiedClaimsClaims {
                        given_name: Some("Max".to_owned()),
                        family_name: Some("Müller".to_owned()),
                        nationalities: Some(vec!["DE".to_owned()]),
                        birthdate: Some("1956-01-28".to_owned()),
                        place_of_birth: Some(PlaceOfBirth {
                            country: "IS".to_owned(),
                            locality: "Þykkvabæjarklaustur".to_owned(),
                        }),
                        address: Some(Address {
                            locality: "Maxstadt".to_owned(),
                            postal_code: "12344".to_owned(),
                            country: "DE".to_owned(),
                            street_address: "Weidenstraße 22".to_owned(),
                        }),
                    },
                },
                birth_middle_name: Some("Timotheus".to_owned()),
                salutation: Some("Dr.".to_owned()),
                msisdn: Some("49123456789".to_owned()),
            })
            .unwrap()
    )
}
