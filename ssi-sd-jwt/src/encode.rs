use base64::URL_SAFE_NO_PAD;
use rand::{CryptoRng, Rng};
use serde::Serialize;
use ssi_jwk::{Algorithm, JWK};

use crate::*;

/// Disclosure as encoded
#[derive(Debug, PartialEq)]
pub struct Disclosure {
    /// Base 64 of disclosure object
    pub encoded: String,

    /// Base 64 of hash of disclosure object
    pub hash: String,
}

fn encode_disclosure_with_salt<ClaimValue: Serialize>(
    salt: &str,
    claim_name: Option<&str>,
    claim_value: &ClaimValue,
) -> Result<String, serde_json::Error> {
    let disclosure = match claim_name {
        Some(claim_name) => serde_json::json!([salt, claim_name, claim_value]),
        None => serde_json::json!([salt, claim_value]),
    };

    let json_string = serde_json::to_string(&disclosure)?;

    Ok(base64::encode_config(json_string, URL_SAFE_NO_PAD))
}

pub fn encode_disclosure_with_rng<ClaimValue: Serialize, Rand: Rng + CryptoRng>(
    rng: &mut Rand,
    claim_name: Option<&str>,
    claim_value: &ClaimValue,
) -> Result<String, serde_json::Error> {
    // TODO: link to rfc wrt suggested bit size of salt
    const DEFAULT_SALT_SIZE: usize = 128 / 8;

    let mut salt_bytes = [0u8; DEFAULT_SALT_SIZE];

    rng.fill_bytes(&mut salt_bytes);

    let salt = base64::encode_config(salt_bytes, URL_SAFE_NO_PAD);

    encode_disclosure_with_salt(&salt, claim_name, claim_value)
}

fn encode_disclosure<ClaimValue: Serialize>(
    claim_name: Option<&str>,
    claim_value: &ClaimValue,
) -> Result<String, serde_json::Error> {
    let mut rng = rand::rngs::OsRng {};
    encode_disclosure_with_rng(&mut rng, claim_name, claim_value)
}

/// Lower level API to create a property style disclosure
pub fn encode_property_disclosure<ClaimValue: Serialize>(
    sd_alg: SdAlg,
    claim_name: &str,
    claim_value: &ClaimValue,
) -> Result<Disclosure, serde_json::Error> {
    let encoded = encode_disclosure(Some(claim_name), claim_value)?;
    let hash = hash_encoded_disclosure(sd_alg, &encoded);

    Ok(Disclosure { encoded, hash })
}

/// Lower level API to create an array style disclosure
pub fn encode_array_disclosure<ClaimValue: Serialize>(
    sd_alg: SdAlg,
    claim_value: &ClaimValue,
) -> Result<Disclosure, serde_json::Error> {
    let encoded = encode_disclosure(None, claim_value)?;
    let hash = hash_encoded_disclosure(sd_alg, &encoded);

    Ok(Disclosure { encoded, hash })
}

/// High level API to create most SD-JWTs
pub fn encode_sign<Claims: Serialize>(
    algorithm: Algorithm,
    base_claims: &Claims,
    key: &JWK,
    sd_alg: SdAlg,
    disclosures: Vec<UnencodedDisclosure>,
) -> Result<(String, Vec<FullDisclosure>), EncodeError> {
    let mut base_claims_json = serde_json::to_value(base_claims)?;

    let post_encoded_disclosures: Result<Vec<_>, EncodeError> = disclosures
        .iter()
        .map(|disclosure| {
            let encoded = disclosure.encode()?;
            let hash = hash_encoded_disclosure(sd_alg, &encoded);
            Ok(FullDisclosure {
                encoded,
                hash,
                unencoded: disclosure.clone(),
            })
        })
        .collect();

    let post_encoded_disclosures = post_encoded_disclosures?;

    {
        let base_claims_obj = base_claims_json
            .as_object_mut()
            .ok_or(EncodeError::EncodedAsNonObject)?;

        let prev_sd_alg = base_claims_obj.insert(
            SD_ALG_CLAIM_NAME.to_owned(),
            serde_json::json!(sd_alg.to_str()),
        );

        if prev_sd_alg.is_some() {
            return Err(EncodeError::EncodedClaimsContainsReservedProperty);
        }

        let mut sd_claim = vec![];

        for disclosure in post_encoded_disclosures.iter() {
            match disclosure.unencoded {
                UnencodedDisclosure::Property(ref claim_name, _) => {
                    sd_claim.push(serde_json::Value::String(disclosure.hash.clone()));
                    base_claims_obj.remove(claim_name);
                }
                UnencodedDisclosure::ArrayItem(ref claim_name, _) => {
                    if !base_claims_obj.contains_key(claim_name) {
                        let _ = base_claims_obj.insert(claim_name.clone(), serde_json::json!([]));
                    }

                    // unwrap() justified as id statement above adds claim_name to the map if it
                    // doesn't previously exist
                    let array = base_claims_obj.get_mut(claim_name).unwrap();
                    let array = array.as_array_mut().ok_or(EncodeError::ExpectedArray)?;

                    array.push(serde_json::json!({ARRAY_CLAIM_ITEM_PROPERTY_NAME: disclosure.hash.clone()}));
                }
            }
        }

        let prev_sd =
            base_claims_obj.insert(SD_CLAIM_NAME.to_owned(), serde_json::Value::Array(sd_claim));

        if prev_sd.is_some() {
            return Err(EncodeError::EncodedClaimsContainsReservedProperty);
        }
    }

    let jwt = ssi_jwt::encode_sign(algorithm, &base_claims_json, key)?;

    Ok((jwt, post_encoded_disclosures))
}

/// Represents a disclosure before encoding
#[derive(Clone, Debug)]
pub enum UnencodedDisclosure {
    /// Property style disclosure
    Property(String, serde_json::Value),

    /// Array style disclosure
    ArrayItem(String, serde_json::Value),
}

impl UnencodedDisclosure {
    /// Create a new property style UnencodedDisclosure
    pub fn new_property<S: AsRef<str>, Value: Serialize>(
        name: S,
        value: &Value,
    ) -> Result<Self, serde_json::Error> {
        Ok(UnencodedDisclosure::Property(
            name.as_ref().to_owned(),
            serde_json::to_value(value)?,
        ))
    }

    /// Create a new array style UnencodedDisclosure
    pub fn new_array_item<S: AsRef<str>, Value: Serialize>(
        parent: S,
        value: &Value,
    ) -> Result<Self, serde_json::Error> {
        Ok(UnencodedDisclosure::ArrayItem(
            parent.as_ref().to_owned(),
            serde_json::to_value(value)?,
        ))
    }

    /// Obtain reference to the disclosure's JSON object
    pub fn claim_value_as_ref(&self) -> &serde_json::Value {
        match self {
            UnencodedDisclosure::ArrayItem(_, value) => value,
            UnencodedDisclosure::Property(_, value) => value,
        }
    }

    /// Obtain reference to the disclosure's name if it is an array style
    /// disclosure
    pub fn encoded_claim_name(&self) -> Option<&str> {
        match self {
            UnencodedDisclosure::Property(name, _) => Some(name),
            UnencodedDisclosure::ArrayItem(_, _) => None,
        }
    }

    /// Encode the disclosure into the plaintext base64 string encoding
    pub fn encode(&self) -> Result<String, serde_json::Error> {
        encode_disclosure(self.encoded_claim_name(), self.claim_value_as_ref())
    }
}

#[derive(Debug)]
pub struct FullDisclosure {
    pub encoded: String,
    pub hash: String,
    pub unencoded: UnencodedDisclosure,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_disclosure() {
        assert_eq!(
            encode_disclosure_with_salt(
                "_26bc4LT-ac6q2KI6cBW5es",
                Some("family_name"),
                &"Möbius".to_owned(),
            )
            .unwrap(),
            "WyJfMjZiYzRMVC1hYzZxMktJNmNCVzVlcyIsImZhbWlseV9uYW1lIiwiTcO2Yml1cyJd",
        )
    }

    #[test]
    fn test_encode_array_disclosure() {
        assert_eq!(
            encode_disclosure_with_salt("nPuoQnkRFq3BIeAm7AnXFA", None, &"DE".to_owned()).unwrap(),
            "WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwiREUiXQ"
        )
    }
}
