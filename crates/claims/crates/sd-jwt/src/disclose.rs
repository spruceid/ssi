use crate::{
    disclosure::{DecodedDisclosure, DisclosureKind},
    utils::TryRetainMut,
    DecodedSdJwtRef, DisclosedSdJwt, SdAlg, SdJwtPayload, ARRAY_CLAIM_ITEM_PROPERTY_NAME,
    SD_CLAIM_NAME,
};
use serde::de::DeserializeOwned;
use serde_json::Value;
use ssi_jwt::JWTClaims;
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

impl<'a> DecodedSdJwtRef<'a> {
    /// Discloses the decoded SD-JWT.
    pub fn disclose<T: DeserializeOwned>(self) -> Result<DisclosedSdJwt<'a, T>, DiscloseError> {
        let disclosed_claims = self.jwt.signing_bytes.payload.disclose(&self.disclosures)?;
        Ok(DisclosedSdJwt {
            undisclosed_jwt: self.jwt,
            claims: disclosed_claims,
        })
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

                    match &in_progress_disclosure.disclosure.kind {
                        DisclosureKind::ArrayItem(value) => {
                            *item = value.clone();
                            Ok(true)
                        }
                        DisclosureKind::Property { .. } => {
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

            match &in_progress_disclosure.disclosure.kind {
                DisclosureKind::ArrayItem(_) => {
                    return Err(DiscloseError::ExpectedPropertyDisclosure)
                }
                DisclosureKind::Property { name, value } => {
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
