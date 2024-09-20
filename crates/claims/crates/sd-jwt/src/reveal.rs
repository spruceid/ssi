use crate::{
    disclosure::{DecodedDisclosure, DisclosureDescription},
    utils::TryRetainMut,
    DecodeError, DecodedSdJwt, RevealedSdJwt, SdAlg, SdJwtPayload, ARRAY_CLAIM_ITEM_PROPERTY_NAME,
    SD_CLAIM_NAME,
};
use indexmap::IndexMap;
use serde::de::DeserializeOwned;
use serde_json::Value;
use ssi_core::{JsonPointer, JsonPointerBuf};
use ssi_jwt::JWTClaims;

/// Reveal error.
///
/// Error type used by the [`DecodedSdJwt::reveal`] function.
#[derive(Debug, thiserror::Error)]
pub enum RevealError {
    /// SD-JWT decoding failed.
    #[error(transparent)]
    Decode(#[from] DecodeError),

    /// Unused disclosure.
    #[error("unused disclosure `{0:?}`")]
    UnusedDisclosure(DecodedDisclosure<'static>),

    /// Claim collision.
    #[error("claim collision")]
    Collision,

    /// `_sd` claim value is not an array.
    #[error("`_sd` claim value is not an array")]
    SdClaimValueNotArray,

    /// Invalid disclosure hash.
    #[error("invalid disclosure hash value")]
    InvalidDisclosureHash,

    /// Disclosure used multiple times.
    #[error("disclosure is used multiple times")]
    DisclosureUsedMultipleTimes,

    /// Expected object entry, found array item disclosure.
    #[error("expected object entry disclosure, found array item disclosure")]
    ExpectedObjectEntryDisclosure,

    /// Expected array item disclosure, found object entry disclosure.
    #[error("expected array item disclosure, found object entry disclosure")]
    ExpectedArrayItemDisclosure,

    /// JSON deserialization failed.
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl<'a> DecodedSdJwt<'a> {
    /// Reveal the SD-JWT.
    pub fn reveal<T: DeserializeOwned>(self) -> Result<RevealedSdJwt<'a, T>, RevealError> {
        let mut pointers = Vec::with_capacity(self.disclosures.len());
        let jwt = self
            .jwt
            .try_map(|payload| payload.reveal(&self.disclosures, &mut pointers))?;

        Ok(RevealedSdJwt {
            jwt,
            disclosures: pointers.into_iter().zip(self.disclosures).collect(),
        })
    }

    /// Reveal the SD-JWT.
    pub fn reveal_any(self) -> Result<RevealedSdJwt<'a>, RevealError> {
        self.reveal()
    }
}

impl SdJwtPayload {
    /// Reveal the SD-JWT payload.
    fn reveal<T: DeserializeOwned>(
        &self,
        disclosures: &[DecodedDisclosure],
        pointers: &mut Vec<JsonPointerBuf>,
    ) -> Result<JWTClaims<T>, RevealError> {
        let mut disclosures: IndexMap<_, _> = disclosures
            .iter()
            .map(|disclosure| {
                let in_progress = InProgressDisclosure::new(disclosure, self.sd_alg);
                (in_progress.hash.clone(), in_progress)
            })
            .collect();

        let mut disclosed_claims = self.claims.clone();
        reveal_object(
            &JsonPointerBuf::default(),
            &mut disclosed_claims,
            &mut disclosures,
        )?;

        for (_, disclosure) in disclosures {
            pointers.push(disclosure.pointer.ok_or_else(|| {
                RevealError::UnusedDisclosure(disclosure.disclosure.clone().into_owned())
            })?);
        }

        serde_json::from_value(Value::Object(disclosed_claims)).map_err(Into::into)
    }
}

#[derive(Debug)]
struct InProgressDisclosure<'a> {
    disclosure: &'a DecodedDisclosure<'a>,
    hash: String,
    pointer: Option<JsonPointerBuf>,
}

impl<'a> InProgressDisclosure<'a> {
    fn new(disclosure: &'a DecodedDisclosure<'a>, sd_alg: SdAlg) -> Self {
        InProgressDisclosure {
            disclosure,
            hash: sd_alg.hash(&disclosure.encoded),
            pointer: None,
        }
    }
}

fn reveal_value(
    pointer: &JsonPointer,
    value: &mut Value,
    disclosures: &mut IndexMap<String, InProgressDisclosure>,
) -> Result<(), RevealError> {
    match value {
        Value::Object(object) => reveal_object(pointer, object, disclosures),
        Value::Array(array) => array.try_retain_mut(|i, item| {
            let mut pointer = pointer.to_owned();
            pointer.push_index(i);

            match as_concealed_array_item(item) {
                Some(hash) => match disclosures.get_mut(hash) {
                    Some(in_progress_disclosure) => match &in_progress_disclosure.disclosure.desc {
                        DisclosureDescription::ArrayItem(value) => {
                            if in_progress_disclosure
                                .pointer
                                .replace(pointer.clone())
                                .is_some()
                            {
                                return Err(RevealError::DisclosureUsedMultipleTimes);
                            }

                            *item = value.clone();
                            reveal_value(&pointer, item, disclosures)?;
                            Ok(true)
                        }
                        DisclosureDescription::ObjectEntry { .. } => {
                            Err(RevealError::ExpectedArrayItemDisclosure)
                        }
                    },
                    None => Ok(false),
                },
                None => {
                    reveal_value(&pointer, item, disclosures)?;
                    Ok(true)
                }
            }
        }),
        _ => Ok(()),
    }
}

fn reveal_object(
    pointer: &JsonPointer,
    object: &mut serde_json::Map<String, Value>,
    disclosures: &mut IndexMap<String, InProgressDisclosure>,
) -> Result<(), RevealError> {
    // Process `_sd` claim.
    if let Some(sd_claims) = object.remove(SD_CLAIM_NAME) {
        for (key, value) in reveal_sd_claim(pointer, &sd_claims, disclosures)? {
            if object.insert(key, value).is_some() {
                return Err(RevealError::Collision);
            }
        }
    }

    // Visit sub-values.
    for (key, sub_value) in object {
        let mut pointer = pointer.to_owned();
        pointer.push(key);
        reveal_value(&pointer, sub_value, disclosures)?
    }

    Ok(())
}

fn reveal_sd_claim(
    pointer: &JsonPointer,
    sd_claim: &serde_json::Value,
    disclosures: &mut IndexMap<String, InProgressDisclosure>,
) -> Result<Vec<(String, serde_json::Value)>, RevealError> {
    let hashes = sd_claim
        .as_array()
        .ok_or(RevealError::SdClaimValueNotArray)?;

    let mut found_disclosures = vec![];

    for disclosure_hash in hashes {
        let disclosure_hash = disclosure_hash
            .as_str()
            .ok_or(RevealError::InvalidDisclosureHash)?;

        if let Some(in_progress_disclosure) = disclosures.get_mut(disclosure_hash) {
            match &in_progress_disclosure.disclosure.desc {
                DisclosureDescription::ArrayItem(_) => {
                    return Err(RevealError::ExpectedObjectEntryDisclosure)
                }
                DisclosureDescription::ObjectEntry { key, value } => {
                    let mut pointer = pointer.to_owned();
                    pointer.push(key);

                    if in_progress_disclosure.pointer.replace(pointer).is_some() {
                        return Err(RevealError::DisclosureUsedMultipleTimes);
                    }

                    found_disclosures.push((key.clone(), value.clone()))
                }
            }
        }
    }

    Ok(found_disclosures)
}

fn as_concealed_array_item(item: &serde_json::Value) -> Option<&str> {
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
            // "sub": "6c5c0a49-b589-431d-bae7-219122a9ec2c",
            // "given_name": "太郎",
            // "family_name": "山田",
            // "email": "\"unusual email address\"@example.jp",
            // "phone_number": "+81-80-1234-5678",
            "address": {
                // "street_address": "東京都港区芝公園４丁目２−８",
                // "locality": "東京都",
                "region": "港区",
                "country": "JP"
            },
            // "birthdate": "1940-01-01"
        })
    });

    #[test]
    fn disclose() {
        let sd_jwt = SdJwt::new(SD_JWT).unwrap();
        let decoded = sd_jwt.decode().unwrap();
        let disclosed = decoded.reveal_any().unwrap();
        let output = serde_json::to_value(disclosed.claims()).unwrap();
        assert_eq!(output, *DISCLOSED_CLAIMS)
    }
}
