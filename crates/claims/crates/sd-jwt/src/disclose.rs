use crate::{
    disclosure::{DecodedDisclosure, DisclosureDescription},
    utils::TryRetainMut,
    DecodedSdJwt, RevealedSdJwt, SdAlg, SdJwtPayload, ARRAY_CLAIM_ITEM_PROPERTY_NAME,
    SD_CLAIM_NAME,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use ssi_jwt::{DecodedJWT, JWTClaims};
use std::collections::BTreeMap;

/// Disclosing error.
///
/// Error type used by the [`DecodedSdJwtRef::disclose`] function.
#[derive(Debug, thiserror::Error)]
pub enum DiscloseError {
    #[error("unused disclosure")]
    UnusedDisclosure,

    #[error("claim collision")]
    Collision,

    #[error("_sd claim value is not an array")]
    SdClaimValueNotArray,

    #[error("invalid disclosure hash value")]
    InvalidDisclosureHash,

    #[error("disclosure is used multiple times")]
    DisclosureUsedMultipleTimes,

    #[error("expected property disclosure, found array item disclosure")]
    ExpectedPropertyDisclosure,

    #[error("expected array item disclosure, found property disclosure")]
    ExpectedArrayItemDisclosure,

    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl<'a> DecodedSdJwt<'a> {
    /// Discloses the decoded SD-JWT.
    pub fn disclose<T: DeserializeOwned>(self) -> Result<RevealedSdJwt<'a, T>, DiscloseError> {
        let jwt = self
            .jwt
            .try_map(|payload| payload.disclose(&self.disclosures))?;

        Ok(RevealedSdJwt {
            jwt,
            disclosures: self.disclosures,
        })
    }

    /// Discloses the decoded SD-JWT.
    pub fn disclose_any(self) -> Result<RevealedSdJwt<'a>, DiscloseError> {
        self.disclose()
    }
}

impl SdJwtPayload {
    /// Disclose the SD-JWT payload.
    fn disclose<T: DeserializeOwned>(
        &self,
        disclosures: &[DecodedDisclosure],
    ) -> Result<JWTClaims<T>, DiscloseError> {
        let mut disclosures: BTreeMap<_, _> = disclosures
            .iter()
            .map(|disclosure| {
                let in_progress = InProgressDisclosure::new(disclosure, self.sd_alg);
                (in_progress.hash.clone(), in_progress)
            })
            .collect();

        let mut disclosed_claims = serde_json::Map::new();
        for (key, value) in &self.claims {
            let mut value = value.clone();
            disclose_value(&mut value, &mut disclosures)?;
            disclosed_claims.insert(key.clone(), value);
        }

        for (_, disclosure) in disclosures {
            if !disclosure.found {
                return Err(DiscloseError::UnusedDisclosure);
            }
        }

        serde_json::from_value(Value::Object(disclosed_claims)).map_err(Into::into)
    }
}

#[derive(Debug)]
struct InProgressDisclosure<'a> {
    disclosure: &'a DecodedDisclosure<'a>,
    hash: String,
    found: bool,
}

impl<'a> InProgressDisclosure<'a> {
    fn new(disclosure: &'a DecodedDisclosure<'a>, sd_alg: SdAlg) -> Self {
        InProgressDisclosure {
            disclosure,
            hash: sd_alg.hash(&disclosure.encoded),
            found: false,
        }
    }
}

fn disclose_value(
    value: &mut Value,
    disclosures: &mut BTreeMap<String, InProgressDisclosure>,
) -> Result<(), DiscloseError> {
    match value {
        Value::Object(object) => {
            // Process `_sd` claim.
            if let Some(sd_claims) = object.remove(SD_CLAIM_NAME) {
                for (key, value) in disclose_sd_claim(&sd_claims, disclosures)? {
                    if object.insert(key, value).is_some() {
                        return Err(DiscloseError::Collision);
                    }
                }
            }

            // Visit sub-values.
            for sub_value in object.values_mut() {
                disclose_value(sub_value, disclosures)?
            }

            Ok(())
        }
        Value::Array(array) => array.try_retain_mut(|item| match as_undisclosed_array_item(item) {
            Some(hash) => match disclosures.get_mut(hash) {
                Some(in_progress_disclosure) => {
                    if in_progress_disclosure.found {
                        return Err(DiscloseError::DisclosureUsedMultipleTimes);
                    }

                    in_progress_disclosure.found = true;

                    match &in_progress_disclosure.disclosure.desc {
                        DisclosureDescription::ArrayItem(value) => {
                            *item = value.clone();
                            Ok(true)
                        }
                        DisclosureDescription::ObjectEntry { .. } => {
                            Err(DiscloseError::ExpectedArrayItemDisclosure)
                        }
                    }
                }
                None => Ok(false),
            },
            None => {
                disclose_value(item, disclosures)?;
                Ok(true)
            }
        }),
        _ => Ok(()),
    }
}

fn disclose_sd_claim(
    sd_claim: &serde_json::Value,
    disclosures: &mut BTreeMap<String, InProgressDisclosure>,
) -> Result<Vec<(String, serde_json::Value)>, DiscloseError> {
    let hashes = sd_claim
        .as_array()
        .ok_or(DiscloseError::SdClaimValueNotArray)?;

    let mut found_disclosures = vec![];

    for disclosure_hash in hashes {
        let disclosure_hash = disclosure_hash
            .as_str()
            .ok_or(DiscloseError::InvalidDisclosureHash)?;

        if let Some(in_progress_disclosure) = disclosures.get_mut(disclosure_hash) {
            if in_progress_disclosure.found {
                return Err(DiscloseError::DisclosureUsedMultipleTimes);
            }

            in_progress_disclosure.found = true;

            match &in_progress_disclosure.disclosure.desc {
                DisclosureDescription::ArrayItem(_) => {
                    return Err(DiscloseError::ExpectedPropertyDisclosure)
                }
                DisclosureDescription::ObjectEntry { key: name, value } => {
                    found_disclosures.push((name.clone(), value.clone()))
                }
            }
        }
    }

    Ok(found_disclosures)
}

fn as_undisclosed_array_item(item: &serde_json::Value) -> Option<&str> {
    let obj = item.as_object()?;

    if obj.len() != 1 {
        return None;
    }

    obj.get(ARRAY_CLAIM_ITEM_PROPERTY_NAME)?.as_str()
}

#[cfg(test)]
mod tests {
    use serde_json::json;
    use std::cell::LazyCell;

    use crate::SdJwt;

    const SD_JWT: &str = concat!(
        "eyJhbGciOiAiRVMyNTYifQ.eyJfc2QiOiBbIkM5aW5wNllvUmFFWFI0Mjd6WUpQN1Fya",
        "zFXSF84YmR3T0FfWVVyVW5HUVUiLCAiS3VldDF5QWEwSElRdlluT1ZkNTloY1ZpTzlVZ",
        "zZKMmtTZnFZUkJlb3d2RSIsICJNTWxkT0ZGekIyZDB1bWxtcFRJYUdlcmhXZFVfUHBZZ",
        "kx2S2hoX2ZfOWFZIiwgIlg2WkFZT0lJMnZQTjQwVjd4RXhad1Z3ejd5Um1MTmNWd3Q1R",
        "Ew4Ukx2NGciLCAiWTM0em1JbzBRTExPdGRNcFhHd2pCZ0x2cjE3eUVoaFlUMEZHb2ZSL",
        "WFJRSIsICJmeUdwMFdUd3dQdjJKRFFsbjFsU2lhZW9iWnNNV0ExMGJRNTk4OS05RFRzI",
        "iwgIm9tbUZBaWNWVDhMR0hDQjB1eXd4N2ZZdW8zTUhZS08xNWN6LVJaRVlNNVEiLCAic",
        "zBCS1lzTFd4UVFlVTh0VmxsdE03TUtzSVJUckVJYTFQa0ptcXhCQmY1VSJdLCAiaXNzI",
        "jogImh0dHBzOi8vZXhhbXBsZS5jb20vaXNzdWVyIiwgImlhdCI6IDE2ODMwMDAwMDAsI",
        "CJleHAiOiAxODgzMDAwMDAwLCAiYWRkcmVzcyI6IHsiX3NkIjogWyI2YVVoelloWjdTS",
        "jFrVm1hZ1FBTzN1MkVUTjJDQzFhSGhlWnBLbmFGMF9FIiwgIkF6TGxGb2JrSjJ4aWF1c",
        "FJFUHlvSnotOS1OU2xkQjZDZ2pyN2ZVeW9IemciLCAiUHp6Y1Z1MHFiTXVCR1NqdWxmZ",
        "Xd6a2VzRDl6dXRPRXhuNUVXTndrclEtayIsICJiMkRrdzBqY0lGOXJHZzhfUEY4WmN2b",
        "mNXN3p3Wmo1cnlCV3ZYZnJwemVrIiwgImNQWUpISVo4VnUtZjlDQ3lWdWIyVWZnRWs4a",
        "nZ2WGV6d0sxcF9KbmVlWFEiLCAiZ2xUM2hyU1U3ZlNXZ3dGNVVEWm1Xd0JUdzMyZ25Vb",
        "GRJaGk4aEdWQ2FWNCIsICJydkpkNmlxNlQ1ZWptc0JNb0d3dU5YaDlxQUFGQVRBY2k0M",
        "G9pZEVlVnNBIiwgInVOSG9XWWhYc1poVkpDTkUyRHF5LXpxdDd0NjlnSkt5NVFhRnY3R",
        "3JNWDQiXX0sICJfc2RfYWxnIjogInNoYS0yNTYifQ.rFsowW-KSZe7EITlWsGajR9nnG",
        "BLlQ78qgtdGIZg3FZuZnxtapP0H8CUMnffJAwPQJmGnpFpulTkLWHiI1kMmw~WyJHMDJ",
        "OU3JRZmpGWFE3SW8wOXN5YWpBIiwgInJlZ2lvbiIsICJcdTZlMmZcdTUzM2EiXQ~WyJs",
        "a2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgImNvdW50cnkiLCAiSlAiXQ~"
    );

    const DISCLOSED_CLAIMS: LazyCell<serde_json::Value> = LazyCell::new(|| {
        json!({
            "iss": "https://example.com/issuer",
            "iat": 1683000000,
            "exp": 1883000000,
            "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            "given_name": "太郎",
            "family_name": "山田",
            "email": "\"unusual email address\"@example.jp",
            "phone_number": "+81-80-1234-5678",
            "address": {
                "street_address": "東京都港区芝公園４丁目２−８",
                "locality": "東京都",
                "region": "港区",
                "country": "JP"
            },
            "birthdate": "1940-01-01"
        })
    });

    #[test]
    fn disclose() {
        let sd_jwt = SdJwt::new(SD_JWT).unwrap();
        let disclosed = sd_jwt.decode().unwrap().disclose_any().unwrap();
        let output = serde_json::to_value(disclosed.claims()).unwrap();
        assert_eq!(output, *DISCLOSED_CLAIMS)
    }
}
