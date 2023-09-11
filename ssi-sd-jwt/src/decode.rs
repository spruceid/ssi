use serde::de::DeserializeOwned;
use serde::Deserialize;
use ssi_jwk::JWK;
use ssi_jwt::NumericDate;
use std::collections::BTreeMap;

use crate::verify::{DecodedDisclosure, DisclosureKind};
use crate::*;

#[derive(Debug, Deserialize, PartialEq)]
pub struct ValidityClaims {
    pub nbf: Option<NumericDate>,
    pub iat: Option<NumericDate>,
    pub exp: Option<NumericDate>,
}

pub fn decode_verify<Claims: DeserializeOwned>(
    jwt: &str,
    key: &JWK,
    disclosures: &[&str],
) -> Result<(ValidityClaims, Claims), Error> {
    let mut payload_claims: serde_json::Value = ssi_jwt::decode_verify(jwt, key)?;

    let validity_claims: ValidityClaims = serde_json::from_value(payload_claims.clone())?;

    let sd_alg = sd_alg(&payload_claims)?;
    let _ = payload_claims
        .as_object_mut()
        .unwrap()
        .remove(SD_ALG_CLAIM_NAME);

    let mut disclosures = translate_to_in_progress_disclosures(disclosures, sd_alg)?;

    visit_claims(&mut payload_claims, &mut disclosures)?;

    Ok((validity_claims, serde_json::from_value(payload_claims)?))
}

fn sd_alg(claims: &serde_json::Value) -> Result<SdAlg, Error> {
    let alg_name = claims[SD_ALG_CLAIM_NAME]
        .as_str()
        .ok_or(Error::MissingSdAlg)?;

    SdAlg::try_from(alg_name)
}

fn translate_to_in_progress_disclosures(
    disclosures: &[&str],
    sd_alg: SdAlg,
) -> Result<BTreeMap<String, InProgressDisclosure>, Error> {
    let disclosure_vec: Result<Vec<_>, Error> = disclosures
        .iter()
        .map(|disclosure| InProgressDisclosure::new(disclosure, sd_alg))
        .collect();

    let disclosure_vec = disclosure_vec?;

    let mut disclosure_map = BTreeMap::new();
    for disclosure in disclosure_vec {
        let prev = disclosure_map.insert(disclosure.hash.clone(), disclosure);

        if prev.is_some() {
            return Err(Error::MultipleDisclosuresWithSameHash);
        }
    }

    Ok(disclosure_map)
}

struct InProgressDisclosure {
    decoded: DecodedDisclosure,
    hash: String,
    found: bool,
}

impl InProgressDisclosure {
    fn new(disclosure: &str, sd_alg: SdAlg) -> Result<Self, Error> {
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
) -> Result<(), Error> {
    let payload_claims = match payload_claims.as_object_mut() {
        Some(obj) => obj,
        None => return Ok(()),
    };

    // Visit children
    for (_, child_claim) in payload_claims.iter_mut() {
        visit_claims(child_claim, disclosures)?
    }

    // Process _sd claim
    let new_claims = if let Some(sd) = payload_claims[SD_CLAIM_NAME].as_array() {
        decode_sd_claims(sd, disclosures)?
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
            return Err(Error::DisclosureClaimCollidesWithJwtClaim);
        }
    }

    // Process array claims
    for (_, item) in payload_claims.iter_mut() {
        if let Some(array) = item.as_array_mut() {
            let new_array_items = decode_array_claims(array, disclosures)?;
            *array = new_array_items;
        }
    }

    Ok(())
}

fn decode_sd_claims(
    sd_claims: &Vec<serde_json::Value>,
    disclosures: &mut BTreeMap<String, InProgressDisclosure>,
) -> Result<Vec<(String, serde_json::Value)>, Error> {
    let mut found_disclosures = vec![];
    for disclosure_hash in sd_claims {
        let disclosure_hash = disclosure_hash.as_str().ok_or(Error::SdClaimNotString)?;

        if let Some(in_progress_disclosure) = disclosures.get_mut(disclosure_hash) {
            if in_progress_disclosure.found {
                return Err(Error::DisclosureUsedMultipleTimes);
            }
            in_progress_disclosure.found = true;
            match in_progress_disclosure.decoded.kind {
                DisclosureKind::ArrayItem(_) => {
                    return Err(Error::ArrayDisclosureWhenExpectingProperty)
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
) -> Result<Vec<serde_json::Value>, Error> {
    let mut new_items = vec![];
    for item in array.iter() {
        if let Some(hash) = array_item_is_disclosure(item) {
            if let Some(in_progress_disclosure) = disclosures.get_mut(hash) {
                if in_progress_disclosure.found {
                    return Err(Error::DisclosureUsedMultipleTimes);
                }
                in_progress_disclosure.found = true;
                match in_progress_disclosure.decoded.kind {
                    DisclosureKind::ArrayItem(ref value) => {
                        new_items.push(value.clone());
                    }
                    DisclosureKind::Property { .. } => {
                        return Err(Error::PropertyDisclosureWhenExpectingArray)
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
