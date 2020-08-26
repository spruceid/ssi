use std::convert::TryFrom;
use std::result::Result;

use crate::der::{Integer, RSAPrivateKey, ASN1};
use crate::error::Error;

use serde::{Deserialize, Serialize};

// RFC 7515 - JSON Web Signature (JWS)
// RFC 7516 - JSON Web Encryption (JWE)
// RFC 7517 - JSON Web Key (JWK)
// RFC 7518 - JSON Web Algorithms (JWA)
// RFC 7519 - JSON Web Token (JWT)

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTKeys {
    #[serde(rename = "es256kPrivateKeyJwk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub es256k_private_key: Option<JWK>,
    #[serde(rename = "rs256PrivateKeyJwk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rs256_private_key: Option<JWK>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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
    pub x509_certificate_chain: Option<String>,
    #[serde(rename = "x5t")]
    pub x509_certificate_sha1: Option<String>,
    #[serde(rename = "x5t#S256")]
    pub x509_certificate_sha256: Option<String>,
    #[serde(flatten)]
    pub params: Params,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(tag = "kty")]
pub enum Params {
    EC(ECParams),
    RSA(RSAParams),
    Symmetric(SymmetricParams),
    // @TODO: OKP (RFC 8037)
}

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct RSAParams {
    // Parameters for RSA Public Keys
    #[serde(rename = "n")]
    pub modulus: Option<Base64urlUInt>,
    #[serde(rename = "e")]
    pub exponent: Option<Base64urlUInt>,

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

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(rename = "oct")]
pub struct SymmetricParams {
    // Parameters for Symmetric Keys
    #[serde(rename = "k")]
    pub key_value: Option<Base64urlUInt>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Prime {
    #[serde(rename = "r")]
    pub prime_factor: String, // Base64urlUInt
    #[serde(rename = "d")]
    pub factor_crt_exponent: String, // Base64urlUInt
    #[serde(rename = "t")]
    pub factor_crt_coefficient: String, // Base64urlUInt
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(try_from = "String")]
pub struct Base64urlUInt(pub Vec<u8>);

impl JWK {
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        match &self.params {
            // EC(params) => params.to_der(),
            Params::RSA(params) => params.to_der(),
            // Symmetric(params) => params.to_der(),
            _ => Err(Error::KeyTypeNotImplemented),
        }
    }
}

impl RSAParams {
    pub fn to_der(&self) -> Result<Vec<u8>, Error> {
        let key = RSAPrivateKey {
            modulus: match &self.modulus {
                Some(integer) => Integer(integer.0.clone()),
                None => Integer(vec![]),
            },
            public_exponent: match &self.exponent {
                Some(integer) => Integer(integer.0.clone()),
                None => Integer(vec![]),
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
