use serde::de::DeserializeOwned;
use ssi_jwk::JWK;
use std::collections::BTreeMap;

use crate::disclosure::{DecodedDisclosure, DisclosureKind};
use crate::serialized::deserialize_string_format;
use crate::*;

/// High level API to decode a fully encoded SD-JWT.  That is a JWT and selective
/// disclosures separated by tildes
pub fn decode_verify<Claims: DeserializeOwned>(
    serialized: &str,
    key: &JWK,
) -> Result<Claims, DecodeError> {
    let deserialized = deserialize_string_format(serialized)
        .ok_or(DecodeError::UnableToDeserializeStringFormat)?;

    decode_verify_disclosure_array(deserialized, key)
}

/// Lower level API to decode an SD-JWT that has already been split into its
/// JWT and disclosure components
pub fn decode_verify_disclosure_array<Claims: DeserializeOwned>(
    deserialized: Deserialized<'_>,
    key: &JWK,
) -> Result<Claims, DecodeError> {
    let mut payload_claims: serde_json::Value = ssi_jwt::decode_verify(deserialized.jwt, key)?;

    let sd_alg = extract_sd_alg(&mut payload_claims)?;

    let mut disclosures = translate_to_in_progress_disclosures(&deserialized.disclosures, sd_alg)?;

    visit_claims(&mut payload_claims, &mut disclosures)?;

    for (_, disclosure) in disclosures {
        if !disclosure.found {
            return Err(DecodeError::UnusedDisclosure);
        }
    }

    Ok(serde_json::from_value(payload_claims)?)
}

fn extract_sd_alg(claims: &mut serde_json::Value) -> Result<SdAlg, DecodeError> {
    let claims = claims.as_object_mut().ok_or(DecodeError::ClaimsWrongType)?;

    let sd_alg_claim = claims
        .remove(SD_ALG_CLAIM_NAME)
        .ok_or(DecodeError::MissingSdAlg)?;

    let sd_alg = sd_alg_claim.as_str().ok_or(DecodeError::SdAlgWrongType)?;

    SdAlg::try_from(sd_alg)
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
    let new_claims = if let Some(sd_claims) = payload_claims.remove(SD_CLAIM_NAME) {
        decode_sd_claims(&sd_claims, disclosures)?
    } else {
        vec![]
    };

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
