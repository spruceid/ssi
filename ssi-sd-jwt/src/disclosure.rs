use base64::URL_SAFE_NO_PAD;

use crate::DecodeError;

#[derive(Debug, PartialEq)]
pub struct DecodedDisclosure {
    pub salt: String,
    pub kind: DisclosureKind,
}

#[derive(Debug, PartialEq)]
pub enum DisclosureKind {
    Property {
        name: String,
        value: serde_json::Value,
    },
    ArrayItem(serde_json::Value),
}

impl DecodedDisclosure {
    pub fn new(encoded: &str) -> Result<Self, DecodeError> {
        let bytes = base64::decode_config(encoded, URL_SAFE_NO_PAD)
            .map_err(|_| DecodeError::DisclosureMalformed)?;
        let json: serde_json::Value = serde_json::from_slice(&bytes)?;

        match json {
            serde_json::Value::Array(values) => match values.as_slice() {
                [salt, name, value] => validate_property_disclosure(salt, name, value),
                [salt, value] => validate_array_item_disclosure(salt, value),
                _ => Err(DecodeError::DisclosureMalformed),
            },
            _ => Err(DecodeError::DisclosureMalformed),
        }
    }
}

fn validate_property_disclosure(
    salt: &serde_json::Value,
    name: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<DecodedDisclosure, DecodeError> {
    let salt = salt.as_str().ok_or(DecodeError::DisclosureMalformed)?;

    let name = name.as_str().ok_or(DecodeError::DisclosureMalformed)?;

    Ok(DecodedDisclosure {
        salt: salt.to_owned(),
        kind: DisclosureKind::Property {
            name: name.to_owned(),
            value: value.clone(),
        },
    })
}

fn validate_array_item_disclosure(
    salt: &serde_json::Value,
    value: &serde_json::Value,
) -> Result<DecodedDisclosure, DecodeError> {
    let salt = salt.as_str().ok_or(DecodeError::DisclosureMalformed)?;

    Ok(DecodedDisclosure {
        salt: salt.to_owned(),
        kind: DisclosureKind::ArrayItem(value.clone()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::digest::{hash_encoded_disclosure, SdAlg};

    fn verify_sd_disclosures_array(
        digest_algo: SdAlg,
        disclosures: &[&str],
        sd_claim: &[&str],
    ) -> Result<serde_json::Value, DecodeError> {
        let mut verfied_claims = serde_json::Map::new();

        for disclosure in disclosures {
            let disclosure_hash = hash_encoded_disclosure(digest_algo, disclosure);

            if !disclosure_hash_exists_in_sd_claims(&disclosure_hash, sd_claim) {
                continue;
            }

            let decoded = DecodedDisclosure::new(disclosure)?;

            match decoded.kind {
                DisclosureKind::Property { name, value } => {
                    let orig = verfied_claims.insert(name, value);

                    if orig.is_some() {
                        return Err(DecodeError::DisclosureUsedMultipleTimes);
                    }
                }
                DisclosureKind::ArrayItem(_) => {
                    return Err(DecodeError::ArrayDisclosureWhenExpectingProperty);
                }
            }
        }

        Ok(serde_json::Value::Object(verfied_claims))
    }

    fn disclosure_hash_exists_in_sd_claims(disclosure_hash: &str, sd_claim: &[&str]) -> bool {
        for sd_claim_item in sd_claim {
            if &disclosure_hash == sd_claim_item {
                return true;
            }
        }

        false
    }

    #[test]
    fn test_verify_disclosures() {
        const DISCLOSURES: [&str; 7] = [
            "WyJyU0x1em5oaUxQQkRSWkUxQ1o4OEtRIiwgInN1YiIsICJqb2huX2RvZV80MiJd",
            "WyJhYTFPYmdlUkJnODJudnpMYnRQTklRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
            "WyI2VWhsZU5HUmJtc0xDOFRndTh2OFdnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
            "WyJ2S0t6alFSOWtsbFh2OWVkNUJ1ZHZRIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ",
            "WyJVZEVmXzY0SEN0T1BpZDRFZmhPQWNRIiwgInBob25lX251bWJlciIsICIrMS0yMDItNTU1LTAxMDEiXQ",
            "WyJOYTNWb0ZGblZ3MjhqT0FyazdJTlZnIiwgImFkZHJlc3MiLCB7InN0cmVldF9hZGRyZXNzIjogIjEyMyBNYWluIFN0IiwgImxvY2FsaXR5IjogIkFueXRvd24iLCAicmVnaW9uIjogIkFueXN0YXRlIiwgImNvdW50cnkiOiAiVVMifV0",
            "WyJkQW9mNHNlZTFGdDBXR2dHanVjZ2pRIiwgImJpcnRoZGF0ZSIsICIxOTQwLTAxLTAxIl0",
        ];

        const SD_CLAIM: [&str; 7] = [
            "5nXy0Z3QiEba1V1lJzeKhAOGQXFlKLIWCLlhf_O-cmo",
            "9gZhHAhV7LZnOFZq_q7Fh8rzdqrrNM-hRWsVOlW3nuw",
            "S-JPBSkvqliFv1__thuXt3IzX5B_ZXm4W2qs4BoNFrA",
            "bviw7pWAkbzI078ZNVa_eMZvk0tdPa5w2o9R3Zycjo4",
            "o-LBCDrFF6tC9ew1vAlUmw6Y30CHZF5jOUFhpx5mogI",
            "pzkHIM9sv7oZH6YKDsRqNgFGLpEKIj3c5G6UKaTsAjQ",
            "rnAzCT6DTy4TsX9QCDv2wwAE4Ze20uRigtVNQkA52X0",
        ];

        let expected_claims: serde_json::Value = serde_json::json!({
            "sub": "john_doe_42",
            "given_name": "John",
            "family_name": "Doe",
            "email": "johndoe@example.com",
            "phone_number": "+1-202-555-0101",
            "address": {"street_address": "123 Main St", "locality": "Anytown", "region": "Anystate", "country": "US"},
            "birthdate": "1940-01-01"
        });

        let verified_claims =
            verify_sd_disclosures_array(SdAlg::Sha256, &DISCLOSURES, &SD_CLAIM).unwrap();

        assert_eq!(verified_claims, expected_claims)
    }

    #[test]
    fn test_verify_subset_of_disclosures() {
        const DISCLOSURES: [&str; 2] = [
            "WyJhYTFPYmdlUkJnODJudnpMYnRQTklRIiwgImdpdmVuX25hbWUiLCAiSm9obiJd",
            "WyI2VWhsZU5HUmJtc0xDOFRndTh2OFdnIiwgImZhbWlseV9uYW1lIiwgIkRvZSJd",
        ];

        const SD_CLAIM: [&str; 7] = [
            "5nXy0Z3QiEba1V1lJzeKhAOGQXFlKLIWCLlhf_O-cmo",
            "9gZhHAhV7LZnOFZq_q7Fh8rzdqrrNM-hRWsVOlW3nuw",
            "S-JPBSkvqliFv1__thuXt3IzX5B_ZXm4W2qs4BoNFrA",
            "bviw7pWAkbzI078ZNVa_eMZvk0tdPa5w2o9R3Zycjo4",
            "o-LBCDrFF6tC9ew1vAlUmw6Y30CHZF5jOUFhpx5mogI",
            "pzkHIM9sv7oZH6YKDsRqNgFGLpEKIj3c5G6UKaTsAjQ",
            "rnAzCT6DTy4TsX9QCDv2wwAE4Ze20uRigtVNQkA52X0",
        ];

        let expected_claims: serde_json::Value = serde_json::json!({
            "given_name": "John",
            "family_name": "Doe",
        });

        let verified_claims =
            verify_sd_disclosures_array(SdAlg::Sha256, &DISCLOSURES, &SD_CLAIM).unwrap();

        assert_eq!(verified_claims, expected_claims)
    }

    #[test]
    fn decode_array_disclosure() {
        assert_eq!(
            DecodedDisclosure {
                salt: "nPuoQnkRFq3BIeAm7AnXFA".to_owned(),
                kind: DisclosureKind::ArrayItem(serde_json::json!("DE"))
            },
            DecodedDisclosure::new("WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0").unwrap()
        )
    }
}
