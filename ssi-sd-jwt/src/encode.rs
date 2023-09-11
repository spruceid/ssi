use jose_b64::base64ct::{Base64UrlUnpadded, Encoding};
use rand::{CryptoRng, Rng};
use serde::Serialize;
use ssi_jwk::{Algorithm, JWK};

use crate::*;

fn encode_disclosure_with_salt<ClaimValue: Serialize>(
    salt: &str,
    claim_name: Option<&str>,
    claim_value: &ClaimValue,
) -> Result<String, serde_json::Error> {
    let disclosure = match claim_name {
        Some(claim_name) => serde_json::json!([salt, claim_name, claim_value]),
        None => serde_json::json!([salt, claim_value]),
    };

    let json_bytes = jose_b64::serde::Json::<serde_json::Value>::new(disclosure)?;

    Ok(Base64UrlUnpadded::encode_string(json_bytes.as_ref()))
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

    let salt = Base64UrlUnpadded::encode_string(&salt_bytes);

    encode_disclosure_with_salt(&salt, claim_name, claim_value)
}

pub fn encode_disclosure<ClaimValue: Serialize>(
    claim_name: Option<&str>,
    claim_value: &ClaimValue,
) -> Result<String, serde_json::Error> {
    let mut rng = rand::rngs::OsRng {};
    encode_disclosure_with_rng(&mut rng, claim_name, claim_value)
}

pub fn encode_sign<Claims: Serialize>(
    algorithm: Algorithm,
    base_claims: &Claims,
    key: &JWK,
    sd_alg: SdAlg,
    disclosures: Vec<UnencodedDisclosure>,
) -> Result<(String, Vec<PostEncodedDisclosure>), Error> {
    let mut base_claims_json = serde_json::to_value(base_claims)?;

    let post_encoded_disclosures: Result<Vec<_>, Error> = disclosures
        .iter()
        .map(|disclosure| {
            let encoded = disclosure.encode()?;
            let hash = hash_encoded_disclosure(sd_alg, &encoded);
            Ok(PostEncodedDisclosure {
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
            .ok_or(Error::EncodedAsNonObject)?;

        let prev_sd_alg = base_claims_obj.insert(
            SD_ALG_CLAIM_NAME.to_owned(),
            serde_json::json!(sd_alg.to_str()),
        );

        if prev_sd_alg.is_some() {
            return Err(Error::EncodedClaimsContainsReservedProperty);
        }

        let mut sd_claim = vec![];

        for disclosure in post_encoded_disclosures.iter() {
            match disclosure.unencoded {
                UnencodedDisclosure::Claim(ref claim_name, _) => {
                    sd_claim.push(serde_json::Value::String(disclosure.hash.clone()));
                    base_claims_obj.remove(claim_name);
                }
                UnencodedDisclosure::ArrayItem(ref claim_name, _) => {
                    if !base_claims_obj.contains_key(claim_name) {
                        let _ = base_claims_obj.insert(claim_name.clone(), serde_json::json!([]));
                    }

                    let array = base_claims_obj.get_mut(claim_name).unwrap();
                    let array = array.as_array_mut().ok_or(Error::ExpectedArray)?;

                    array.push(serde_json::json!({ARRAY_CLAIM_ITEM_PROPERTY_NAME: disclosure.hash.clone()}));
                }
            }
        }

        let prev_sd =
            base_claims_obj.insert(SD_CLAIM_NAME.to_owned(), serde_json::Value::Array(sd_claim));

        if prev_sd.is_some() {
            return Err(Error::EncodedClaimsContainsReservedProperty);
        }
    }

    let jwt = ssi_jwt::encode_sign(algorithm, &base_claims_json, key)?;

    Ok((jwt, post_encoded_disclosures))
}

#[derive(Clone, Debug)]
pub enum UnencodedDisclosure {
    Claim(String, serde_json::Value),
    ArrayItem(String, serde_json::Value),
}

impl UnencodedDisclosure {
    pub fn claim_value_as_ref(&self) -> &serde_json::Value {
        match self {
            UnencodedDisclosure::ArrayItem(_, value) => value,
            UnencodedDisclosure::Claim(_, value) => value,
        }
    }

    pub fn encoded_claim_name(&self) -> Option<&str> {
        match self {
            UnencodedDisclosure::Claim(name, _) => Some(name),
            UnencodedDisclosure::ArrayItem(_, _) => None,
        }
    }

    pub fn encode(&self) -> Result<String, serde_json::Error> {
        encode_disclosure(self.encoded_claim_name(), self.claim_value_as_ref())
    }
}

#[derive(Debug)]
pub struct PostEncodedDisclosure {
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
