use std::convert::TryFrom;
use std::result::Result;

use crate::der::{Integer, RSAPrivateKey, ASN1};
use crate::error::Error;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header as HeaderLite, Validation};
use serde::{Deserialize, Serialize};

// RFC 7515 - JSON Web Signature (JWS)
// RFC 7516 - JSON Web Encryption (JWE)
// RFC 7517 - JSON Web Key (JWK)
// RFC 7518 - JSON Web Algorithms (JWA)
// RFC 7519 - JSON Web Token (JWT)
// RFC 7797 - JSON Web Signature (JWS) Unencoded Payload Option

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTKeys {
    #[serde(rename = "es256kPrivateKeyJwk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub es256k_private_key: Option<JWK>,
    #[serde(rename = "rs256PrivateKeyJwk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rs256_private_key: Option<JWK>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct JWK {
    #[serde(rename = "crv")]
    pub public_key_use: Option<String>,
    #[serde(rename = "key_ops")]
    pub key_operations: Option<Vec<String>>,
    #[serde(rename = "alg")]
    pub algorithm: Option<String>,
    #[serde(rename = "kid")]
    pub key_id: Option<String>,
    #[serde(rename = "x5u")]
    pub x509_url: Option<String>,
    #[serde(rename = "x5c")]
    pub x509_certificate_chain: Option<Vec<String>>,
    #[serde(rename = "x5t")]
    pub x509_thumbprint_sha1: Option<Base64urlUInt>,
    #[serde(rename = "x5t#S256")]
    pub x509_thumbprint_sha256: Option<Base64urlUInt>,
    #[serde(flatten)]
    pub params: Params,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(tag = "kty")]
pub enum Params {
    EC(ECParams),
    RSA(RSAParams),
    Symmetric(SymmetricParams),
    // @TODO: OKP (RFC 8037)
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ECParams {
    // Parameters for Elliptic Curve Public Keys
    #[serde(rename = "crv")]
    pub curve: Option<String>,
    #[serde(rename = "x")]
    pub x_coordinate: Option<Base64urlUInt>,
    #[serde(rename = "y")]
    pub y_coordinate: Option<Base64urlUInt>,

    // Parameters for Elliptic Curve Private Keys
    #[serde(rename = "d")]
    pub ecc_private_key: Option<Base64urlUInt>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct RSAParams {
    // Parameters for RSA Public Keys
    #[serde(rename = "n")]
    // modulus and exponent are Base64urlUInt, but also needed as strings
    // for DecodingKey::from_rsa_components
    pub modulus: Option<String>,
    #[serde(rename = "e")]
    pub exponent: Option<String>,

    // Parameters for RSA Private Keys
    #[serde(rename = "d")]
    pub private_exponent: Option<Base64urlUInt>,
    #[serde(rename = "p")]
    pub first_prime_factor: Option<Base64urlUInt>,
    #[serde(rename = "q")]
    pub second_prime_factor: Option<Base64urlUInt>,
    #[serde(rename = "dp")]
    pub first_prime_factor_crt_exponent: Option<Base64urlUInt>,
    #[serde(rename = "dq")]
    pub second_prime_factor_crt_exponent: Option<Base64urlUInt>,
    #[serde(rename = "qi")]
    pub first_crt_coefficient: Option<Base64urlUInt>,
    #[serde(rename = "oth")]
    pub other_primes_info: Option<Vec<Prime>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(rename = "oct")]
pub struct SymmetricParams {
    // Parameters for Symmetric Keys
    #[serde(rename = "k")]
    pub key_value: Option<Base64urlUInt>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Prime {
    #[serde(rename = "r")]
    pub prime_factor: String, // Base64urlUInt
    #[serde(rename = "d")]
    pub factor_crt_exponent: String, // Base64urlUInt
    #[serde(rename = "t")]
    pub factor_crt_coefficient: String, // Base64urlUInt
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(try_from = "String")]
pub struct Base64urlUInt(pub Vec<u8>);

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct Header {
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "jku")]
    pub jwk_set_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<JWK>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "kid")]
    pub key_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5u")]
    pub x509_url: Option<String>,

    #[serde(rename = "x5c")]
    pub x509_certificate_chain: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t")]
    pub x509_thumbprint_sha1: Option<Base64urlUInt>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t#S256")]
    pub x509_thumbprint_sha256: Option<Base64urlUInt>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "typ")]
    pub type_: Option<String>,

    #[serde(rename = "cty")]
    pub content_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "crit")]
    pub critical: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "b64")]
    pub base64urlencode_payload: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(flatten)]
    pub additional_params: Option<std::collections::HashMap<String, serde_json::Value>>,
}

impl JWK {
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        match &self.params {
            // EC(params) => params.to_der(),
            Params::RSA(params) => params.to_der(),
            // Symmetric(params) => params.to_der(),
            _ => Err(Error::KeyTypeNotImplemented),
        }
    }

    pub fn to_jwt_encoding_key(&self) -> Result<EncodingKey, Error> {
        match &self.params {
            Params::RSA(rsa_params) => {
                let der = rsa_params.to_der()?;
                Ok(EncodingKey::from_rsa_der(&der))
            }
            _ => return Err(Error::KeyTypeNotImplemented),
        }
    }

    pub fn to_decoding_key(&self) -> Result<DecodingKey, Error> {
        match &self.params {
            Params::RSA(rsa_params) => {
                let modulus = match &rsa_params.modulus {
                    Some(n) => n,
                    None => return Err(Error::MissingKeyParameters),
                };
                let exponent = match &rsa_params.exponent {
                    Some(n) => n,
                    None => return Err(Error::MissingKeyParameters),
                };
                Ok(DecodingKey::from_rsa_components(modulus, exponent))
            }
            _ => Err(Error::KeyTypeNotImplemented),
        }
    }

    pub fn to_algorithm(&self) -> Result<Algorithm, Error> {
        if let Some(ref algorithm) = self.algorithm {
            match algorithm.as_ref() {
                "RS256" => Ok(Algorithm::RS256),
                _ => return Err(Error::AlgorithmNotImplemented),
            }
        } else {
            return Err(Error::MissingAlgorithm);
        }
    }

    pub fn to_validation(&self) -> Result<Validation, Error> {
        let algorithm = self.to_algorithm()?;
        Ok(Validation::new(algorithm))
    }

    pub fn to_jwt_header(&self) -> Result<HeaderLite, Error> {
        let mut header = HeaderLite::default();
        header.alg = self.to_algorithm()?;
        if let Some(ref key_id) = self.key_id {
            header.kid = Some(key_id.clone());
        }
        Ok(header)
    }

    pub fn to_jwt_header_unencoded(&self) -> Result<Header, Error> {
        let mut header = Header::default();
        header.algorithm = self.to_algorithm()?;
        if let Some(ref key_id) = self.key_id {
            header.key_id = Some(key_id.clone());
        }
        header.base64urlencode_payload = Some(false);
        header.critical = Some(vec!["b64".to_string()]);
        Ok(header)
    }
}

impl Header {
    pub fn from_b64(b64: &str) -> Result<Self, Error> {
        let json = base64::decode_config(b64, base64::URL_SAFE)?;
        let header: Self = serde_json::from_slice(&json)?;

        if let Some(crit) = &header.critical {
            if crit.is_empty() {
                return Err(Error::InvalidCriticalHeader);
            }
            for name in crit {
                match name.as_str() {
                    "alg" | "jku" | "jwk" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "typ"
                    | "cty" | "crit" => return Err(Error::InvalidCriticalHeader),
                    "b64" => {
                        if !header.base64urlencode_payload.is_some() {
                            return Err(Error::InvalidCriticalHeader);
                        }
                    }
                    _ => {
                        let has_param = match &header.additional_params {
                            Some(params) => params.contains_key(name),
                            None => false,
                        };
                        if !has_param {
                            return Err(Error::InvalidCriticalHeader);
                        }
                    }
                }
            }
        }

        Ok(header)
    }
}

impl Default for Header {
    fn default() -> Self {
        Header {
            algorithm: Algorithm::default(),
            jwk_set_url: None,
            jwk: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
            type_: Some("JWT".to_string()),
            content_type: None,
            critical: None,
            base64urlencode_payload: None,
            additional_params: None,
        }
    }
}

impl RSAParams {
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let key = RSAPrivateKey {
            modulus: match &self.modulus {
                Some(integer) => Integer(Base64urlUInt::try_from(integer.clone())?.0),
                None => return Err(Error::MissingModulus),
            },
            public_exponent: match &self.exponent {
                Some(integer) => Integer(Base64urlUInt::try_from(integer.clone())?.0),
                None => return Err(Error::MissingExponent),
            },
            private_exponent: match &self.private_exponent {
                Some(integer) => Integer(integer.0.clone()),
                None => Integer(vec![]),
            },
            prime1: match &self.first_prime_factor {
                Some(integer) => Integer(integer.0.clone()),
                None => Integer(vec![]),
            },
            prime2: match &self.second_prime_factor {
                Some(integer) => Integer(integer.0.clone()),
                None => Integer(vec![]),
            },
            exponent1: match &self.first_prime_factor_crt_exponent {
                Some(integer) => Integer(integer.0.clone()),
                None => Integer(vec![]),
            },
            exponent2: match &self.second_prime_factor_crt_exponent {
                Some(integer) => Integer(integer.0.clone()),
                None => Integer(vec![]),
            },
            coefficient: match &self.first_crt_coefficient {
                Some(integer) => Integer(integer.0.clone()),
                None => Integer(vec![0]),
            },
            other_prime_infos: None,
        };
        Ok(key.as_bytes())
    }
}

impl TryFrom<String> for Base64urlUInt {
    type Error = Error;
    fn try_from(data: String) -> Result<Self, Self::Error> {
        match base64::decode_config(data, base64::URL_SAFE) {
            Ok(bytes) => Ok(Base64urlUInt(bytes)),
            Err(err) => Err(Error::Base64(err)),
        }
    }
}

impl From<&Base64urlUInt> for String {
    fn from(data: &Base64urlUInt) -> String {
        base64::encode_config(&data.0, base64::URL_SAFE_NO_PAD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jwk_to_der_rsa() {
        const JSON: &'static [u8] = include_bytes!("../tests/rsa2048-2020-08-25.json");
        const DER: &'static [u8] = include_bytes!("../tests/rsa2048-2020-08-25.der");

        let key: JWK = serde_json::from_slice(JSON).unwrap();
        let der = key.to_der().unwrap();
        assert_eq!(der, DER);
    }
}
