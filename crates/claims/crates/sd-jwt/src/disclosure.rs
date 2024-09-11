use crate::{utils::is_url_safe_base64_char, DecodeError};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde_json::Value;
use std::{
    borrow::{Borrow, Cow},
    fmt,
};

/// Invalid SD-JWT disclosure.
#[derive(Debug, thiserror::Error)]
#[error("invalid SD-JWT disclosure: `{0}`")]
pub struct InvalidDisclosure<T>(pub T);

/// Encoded disclosure.
///
/// An encoded disclosure is a url-safe base-64 string encoding (without
/// padding) an array containing the disclosure's parameters.
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-12.html#section-5>
#[derive(PartialEq)]
pub struct Disclosure([u8]);

impl Disclosure {
    /// Parses the given `disclosure` bytes.
    ///
    /// Returns an error if the input value is not a valid url-safe base64
    /// string without padding.
    pub fn new<T: ?Sized + AsRef<[u8]>>(disclosure: &T) -> Result<&Self, InvalidDisclosure<&T>> {
        let bytes = disclosure.as_ref();
        if bytes.iter().copied().all(is_url_safe_base64_char) {
            Ok(unsafe { Self::new_unchecked(bytes) })
        } else {
            Err(InvalidDisclosure(disclosure))
        }
    }

    /// Creates a new disclosure out of the given `bytes` without validation.
    ///
    /// # Safety
    ///
    /// The input bytes **must** be a valid url-safe base64 string without
    /// padding.
    pub unsafe fn new_unchecked(bytes: &[u8]) -> &Self {
        std::mem::transmute(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: disclosures are url-safe base-64 strings.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    /// Decode this disclosure.
    pub fn decode(&self) -> Result<DecodedDisclosure, DecodeError> {
        DecodedDisclosure::new(self)
    }
}

impl AsRef<[u8]> for Disclosure {
    fn as_ref(&self) -> &[u8] {
        self.as_bytes()
    }
}

impl AsRef<str> for Disclosure {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

impl fmt::Display for Disclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for Disclosure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl ToOwned for Disclosure {
    type Owned = DisclosureBuf;

    fn to_owned(&self) -> Self::Owned {
        DisclosureBuf(self.as_bytes().to_owned())
    }
}

pub struct DisclosureBuf(Vec<u8>);

impl DisclosureBuf {
    pub fn encode_from_parts(salt: &str, kind: &DisclosureKind) -> Self {
        Self(
            BASE64_URL_SAFE_NO_PAD
                .encode(kind.to_value(salt).to_string())
                .into_bytes(),
        )
    }

    pub fn as_disclosure(&self) -> &Disclosure {
        unsafe {
            // SAFETY: `self.0` is a disclosure by construction.
            Disclosure::new_unchecked(&self.0)
        }
    }
}

impl Borrow<Disclosure> for DisclosureBuf {
    fn borrow(&self) -> &Disclosure {
        self.as_disclosure()
    }
}

impl fmt::Display for DisclosureBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_disclosure().fmt(f)
    }
}

impl fmt::Debug for DisclosureBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_disclosure().fmt(f)
    }
}

/// Decoded disclosure.
#[derive(Debug, PartialEq)]
pub struct DecodedDisclosure<'a> {
    /// Encoded disclosure.
    pub encoded: Cow<'a, Disclosure>,
    pub salt: String,
    pub kind: DisclosureKind,
}

impl<'a> DecodedDisclosure<'a> {
    pub fn new(encoded: &'a (impl ?Sized + AsRef<[u8]>)) -> Result<Self, DecodeError> {
        let base64 = encoded.as_ref();
        let bytes = BASE64_URL_SAFE_NO_PAD
            .decode(base64)
            .map_err(|_| DecodeError::DisclosureMalformed)?;

        let encoded = unsafe {
            // SAFETY: by decoding `base64` we validated the disclosure.
            Disclosure::new_unchecked(base64)
        };

        let json: serde_json::Value = serde_json::from_slice(&bytes)?;

        match json {
            serde_json::Value::Array(values) => match values.as_slice() {
                [salt, name, value] => Ok(DecodedDisclosure {
                    encoded: Cow::Borrowed(encoded),
                    salt: salt
                        .as_str()
                        .ok_or(DecodeError::DisclosureMalformed)?
                        .to_owned(),
                    kind: DisclosureKind::Property {
                        name: name
                            .as_str()
                            .ok_or(DecodeError::DisclosureMalformed)?
                            .to_owned(),
                        value: value.clone(),
                    },
                }),
                [salt, value] => Ok(DecodedDisclosure {
                    encoded: Cow::Borrowed(encoded),
                    salt: salt
                        .as_str()
                        .ok_or(DecodeError::DisclosureMalformed)?
                        .to_owned(),
                    kind: DisclosureKind::ArrayItem(value.clone()),
                }),
                _ => Err(DecodeError::DisclosureMalformed),
            },
            _ => Err(DecodeError::DisclosureMalformed),
        }
    }

    pub fn from_parts(salt: String, kind: DisclosureKind) -> Self {
        Self {
            encoded: Cow::Owned(DisclosureBuf::encode_from_parts(&salt, &kind)),
            salt,
            kind,
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum DisclosureKind {
    Property {
        name: String,
        value: serde_json::Value,
    },
    ArrayItem(serde_json::Value),
}

impl DisclosureKind {
    pub fn to_value(&self, salt: &str) -> Value {
        match self {
            Self::Property { name, value } => {
                Value::Array(vec![salt.into(), name.to_owned().into(), value.clone()])
            }
            Self::ArrayItem(value) => Value::Array(vec![salt.into(), value.clone()]),
        }
    }
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
            DecodedDisclosure::from_parts(
                "nPuoQnkRFq3BIeAm7AnXFA".to_owned(),
                DisclosureKind::ArrayItem(serde_json::json!("DE"))
            ),
            DecodedDisclosure::new("WyJuUHVvUW5rUkZxM0JJZUFtN0FuWEZBIiwgIkRFIl0").unwrap()
        )
    }
}
