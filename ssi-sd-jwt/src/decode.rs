use serde::de::DeserializeOwned;
use serde::Deserialize;
use ssi_jwk::JWK;
use ssi_jwt::NumericDate;
use std::collections::BTreeMap;

use crate::serialized::deserialize_string_format;
use crate::verify::{DecodedDisclosure, DisclosureKind};
use crate::*;

#[derive(Debug, Deserialize, PartialEq)]
pub struct ValidityClaims {
    pub nbf: Option<NumericDate>,
    pub iat: Option<NumericDate>,
    pub exp: Option<NumericDate>,
}

pub fn decode_verify<Claims: DeserializeOwned>(
    serialized: &str,
    key: &JWK,
) -> Result<(ValidityClaims, Claims), DecodeError> {
    let deserialized = deserialize_string_format(serialized)
        .ok_or(DecodeError::UnableToDeserializeStringFormat)?;

    decode_verify_disclosure_array(deserialized.jwt, key, &deserialized.disclosures)
}

pub fn decode_verify_disclosure_array<Claims: DeserializeOwned>(
    jwt: &str,
    key: &JWK,
    disclosures: &[&str],
) -> Result<(ValidityClaims, Claims), DecodeError> {
    let mut payload_claims: serde_json::Value = ssi_jwt::decode_verify(jwt, key)?;

    let validity_claims: ValidityClaims = serde_json::from_value(payload_claims.clone())?;

    let sd_alg = sd_alg(&payload_claims)?;
    let _ = payload_claims
        .as_object_mut()
        .unwrap()
        .remove(SD_ALG_CLAIM_NAME);

    let mut disclosures = translate_to_in_progress_disclosures(disclosures, sd_alg)?;

    visit_claims(&mut payload_claims, &mut disclosures)?;

    for (_, disclosure) in disclosures {
        if !disclosure.found {
            return Err(DecodeError::UnusedDisclosure);
        }
    }

    Ok((validity_claims, serde_json::from_value(payload_claims)?))
}

fn sd_alg(claims: &serde_json::Value) -> Result<SdAlg, DecodeError> {
    let alg_name = claims[SD_ALG_CLAIM_NAME]
        .as_str()
        .ok_or(DecodeError::MissingSdAlg)?;

    SdAlg::try_from(alg_name)
}

fn translate_to_in_progress_disclosures(
    disclosures: &[&str],
    sd_alg: SdAlg,
) -> Result<BTreeMap<String, InProgressDisclosure>, DecodeError> {
    let disclosure_vec: Result<Vec<_>, DecodeError> = disclosures
        .iter()
        .map(|disclosure| InProgressDisclosure::new(disclosure, sd_alg))
        .collect();

    let disclosure_vec = disclosure_vec?;

    let mut disclosure_map = BTreeMap::new();
    for disclosure in disclosure_vec {
        let prev = disclosure_map.insert(disclosure.hash.clone(), disclosure);

        if prev.is_some() {
            return Err(DecodeError::MultipleDisclosuresWithSameHash);
        }
    }

    Ok(disclosure_map)
}

#[derive(Debug)]
struct InProgressDisclosure {
    decoded: DecodedDisclosure,
    hash: String,
    found: bool,
}

impl InProgressDisclosure {
    fn new(disclosure: &str, sd_alg: SdAlg) -> Result<Self, DecodeError> {
        Ok(InProgressDisclosure {
            decoded: DecodedDisclosure::new(disclosure)?,
            hash: hash_encoded_disclosure(sd_alg, disclosure),
            found: false,
        })
    }
}

fn visit_claims(
    payload_claims: &mut serde_json::Value,
    disclosures: &mut BTreeMap<String, InProgressDisclosure>,
) -> Result<(), DecodeError> {
    let payload_claims = match payload_claims.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(()),
    };

    // Visit children
    for (_, child_claim) in payload_claims.iter_mut() {
        visit_claims(child_claim, disclosures)?
    }

    // Process _sd claim
    let new_claims = if let Some(sd_claims) = payload_claims.get(SD_CLAIM_NAME) {
        decode_sd_claims(sd_claims, disclosures)?
    } else {
        vec![]
    };

    if payload_claims.contains_key(SD_CLAIM_NAME) {
        payload_claims.remove(SD_CLAIM_NAME);
    }

    for (new_claim_name, mut new_claim_value) in new_claims {
        visit_claims(&mut new_claim_value, disclosures)?;

        let prev = payload_claims.insert(new_claim_name, new_claim_value);

        if prev.is_some() {
            return Err(DecodeError::DisclosureClaimCollidesWithJwtClaim);
        }
    }

    // Process array claims
    for (_, item) in payload_claims.iter_mut() {
        if let Some(array) = item.as_array_mut() {
            let mut new_array_items = decode_array_claims(array, disclosures)?;

            for item in new_array_items.iter_mut() {
                visit_claims(item, disclosures)?;
            }

            *array = new_array_items;
        }
    }

    Ok(())
}

fn decode_sd_claims(
    sd_claims: &serde_json::Value,
    disclosures: &mut BTreeMap<String, InProgressDisclosure>,
) -> Result<Vec<(String, serde_json::Value)>, DecodeError> {
    let sd_claims = sd_claims
        .as_array()
        .ok_or(DecodeError::SdPropertyNotArray)?;
    let mut found_disclosures = vec![];
    for disclosure_hash in sd_claims {
        let disclosure_hash = disclosure_hash
            .as_str()
            .ok_or(DecodeError::SdClaimNotString)?;

        if let Some(in_progress_disclosure) = disclosures.get_mut(disclosure_hash) {
            if in_progress_disclosure.found {
                return Err(DecodeError::DisclosureUsedMultipleTimes);
            }
            in_progress_disclosure.found = true;
            match in_progress_disclosure.decoded.kind {
                DisclosureKind::ArrayItem(_) => {
                    return Err(DecodeError::ArrayDisclosureWhenExpectingProperty)
                }
                DisclosureKind::Property {
                    ref name,
                    ref value,
                } => found_disclosures.push((name.clone(), value.clone())),
            }
        }
    }

    Ok(found_disclosures)
}

fn decode_array_claims(
    array: &[serde_json::Value],
    disclosures: &mut BTreeMap<String, InProgressDisclosure>,
) -> Result<Vec<serde_json::Value>, DecodeError> {
    let mut new_items = vec![];
    for item in array.iter() {
        if let Some(hash) = array_item_is_disclosure(item) {
            if let Some(in_progress_disclosure) = disclosures.get_mut(hash) {
                if in_progress_disclosure.found {
                    return Err(DecodeError::DisclosureUsedMultipleTimes);
                }
                in_progress_disclosure.found = true;
                match in_progress_disclosure.decoded.kind {
                    DisclosureKind::ArrayItem(ref value) => {
                        new_items.push(value.clone());
                    }
                    DisclosureKind::Property { .. } => {
                        return Err(DecodeError::PropertyDisclosureWhenExpectingArray)
                    }
                }
            }
        } else {
            new_items.push(item.clone());
        }
    }

    Ok(new_items)
}

fn array_item_is_disclosure(item: &serde_json::Value) -> Option<&str> {
    let obj = item.as_object()?;

    if obj.len() != 1 {
        return None;
    }

    obj.get(ARRAY_CLAIM_ITEM_PROPERTY_NAME)?.as_str()
}
