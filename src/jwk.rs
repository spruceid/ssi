use ring::signature::{Ed25519KeyPair, KeyPair};
use std::convert::TryFrom;
use std::result::Result;

use crate::der::{
    BitString, Ed25519PrivateKey, Ed25519PublicKey, Integer, OctetString, RSAPrivateKey,
    RSAPublicKey, DER,
};
use crate::error::Error;

use jsonwebtoken::{Algorithm, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};

// RFC 7515 - JSON Web Signature (JWS)
// RFC 7516 - JSON Web Encryption (JWE)
// RFC 7517 - JSON Web Key (JWK)
// RFC 7518 - JSON Web Algorithms (JWA)
// RFC 7519 - JSON Web Token (JWT)
// RFC 7797 - JSON Web Signature (JWS) Unencoded Payload Option
// RFC 8037 - CFRG ECDH and Signatures in JOSE

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
    #[serde(rename = "use")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key_use: Option<String>,
    #[serde(rename = "key_ops")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_operations: Option<Vec<String>>,
    #[serde(rename = "alg")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub algorithm: Option<Algorithm>,
    #[serde(rename = "kid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_id: Option<String>,
    #[serde(rename = "x5u")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_url: Option<String>,
    #[serde(rename = "x5c")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_certificate_chain: Option<Vec<String>>,
    #[serde(rename = "x5t")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub x509_thumbprint_sha1: Option<Base64urlUInt>,
    #[serde(rename = "x5t#S256")]
    #[serde(skip_serializing_if = "Option::is_none")]
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
    OKP(OctetParams),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub struct ECParams {
    // Parameters for Elliptic Curve Public Keys
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
#[serde(rename = "OKP")]
pub struct OctetParams {
    // Parameters for Octet Key Pair Public Keys
    #[serde(rename = "crv")]
    pub curve: String,
    #[serde(rename = "x")]
    pub public_key: Base64urlUInt,

    // Parameters for Octet Key Pair Private Keys
    #[serde(rename = "d")]
    pub private_key: Option<Base64urlUInt>,
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
#[serde(into = "Base64urlUIntString")]
pub struct Base64urlUInt(pub Vec<u8>);
type Base64urlUIntString = String;

const DID_KEY_ED25519_PREFIX: [u8; 2] = [0xed, 0x01];

impl JWK {
    pub fn to_jwt_header(&self) -> Result<Header, Error> {
        let mut header = Header::default();
        header.alg = Algorithm::try_from(self)?;
        if let Some(ref key_id) = self.key_id {
            header.kid = Some(key_id.clone());
        }
        Ok(header)
    }

    // TODO: Use TryFrom
    pub fn from_did_key(did: &str) -> Result<JWK, Error> {
        if did.len() < 8 {
            return Err(Error::InvalidKeyLength);
        }
        if &did[..8] != "did:key:" {
            return Err(Error::Key);
        }
        let (_base, data) = multibase::decode(&did[8..])?;
        if data.len() < 2 {
            return Err(Error::InvalidKeyLength);
        }
        if data[0] == DID_KEY_ED25519_PREFIX[0] && data[1] == DID_KEY_ED25519_PREFIX[1] {
            if data.len() - 2 != 32 {
                return Err(Error::InvalidKeyLength);
            }
            return Ok(JWK {
                params: Params::OKP(OctetParams {
                    curve: "Ed25519".to_string(),
                    public_key: Base64urlUInt(data[2..].to_vec()),
                    private_key: None,
                }),
                public_key_use: None,
                key_operations: None,
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_certificate_chain: None,
                x509_thumbprint_sha1: None,
                x509_thumbprint_sha256: None,
            });
        }
        return Err(Error::KeyTypeNotImplemented);
    }

    pub fn to_did(&self) -> Result<String, Error> {
        self.params.to_did()
    }

    pub fn generate_ed25519() -> Result<JWK, Error> {
        let rng = ring::rand::SystemRandom::new();
        let doc = Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key_pkcs8 = doc.as_ref();
        let keypair = Ed25519KeyPair::from_pkcs8(key_pkcs8)?;
        let public_key = keypair.public_key().as_ref();
        // reference: ring/src/ec/curve25519/ed25519/signing.rs
        let private_key = &key_pkcs8[0x10..0x30];
        return Ok(JWK {
            params: Params::OKP(OctetParams {
                curve: "Ed25519".to_string(),
                public_key: Base64urlUInt(public_key.to_vec()),
                private_key: Some(Base64urlUInt(private_key.to_vec())),
            }),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        });
    }
}

impl Params {
    pub fn to_did(&self) -> Result<String, Error> {
        match self {
            Self::OKP(okp) => okp.to_did(),
            _ => return Err(Error::UnsupportedKeyType),
        }
    }
}

impl OctetParams {
    pub fn to_did(&self) -> Result<String, Error> {
        match &self.curve[..] {
            "Ed25519" => Ok("did:key:".to_string()
                + &multibase::encode(
                    multibase::Base::Base58Btc,
                    [DID_KEY_ED25519_PREFIX.to_vec(), self.public_key.0.clone()].concat(),
                )),
            _ => {
                return Err(Error::UnsupportedKeyType);
            }
        }
    }
}

impl TryFrom<&JWK> for DER {
    type Error = Error;
    fn try_from(jwk: &JWK) -> Result<Self, Self::Error> {
        match &jwk.params {
            // EC(params) => DER::try_from(params),
            Params::RSA(params) => DER::try_from(params),
            // Symmetric(params) => DER::try_from(params),
            _ => Err(Error::KeyTypeNotImplemented),
        }
    }
}

impl TryFrom<&JWK> for EncodingKey {
    type Error = Error;
    fn try_from(jwk: &JWK) -> Result<Self, Self::Error> {
        match &jwk.params {
            Params::RSA(rsa_params) => {
                let der = DER::try_from(rsa_params)?;
                Ok(EncodingKey::from_rsa_der(&der))
            }
            Params::OKP(okp_params) => {
                let der = DER::try_from(okp_params)?;
                Ok(EncodingKey::from_ed_der(&der))
            }
            _ => return Err(Error::KeyTypeNotImplemented),
        }
    }
}

impl<'a> TryFrom<&'a JWK> for DecodingKey<'a> {
    type Error = Error;
    fn try_from(jwk: &'a JWK) -> Result<Self, Self::Error> {
        match &jwk.params {
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
            Params::OKP(okp) => {
                if okp.curve != "Ed25519".to_string() {
                    return Err(Error::KeyTypeNotImplemented);
                }
                Ok(DecodingKey::from_ed_der(&okp.public_key.0))
            }
            _ => Err(Error::KeyTypeNotImplemented),
        }
    }
}

impl TryFrom<&JWK> for Algorithm {
    type Error = Error;
    fn try_from(jwk: &JWK) -> Result<Self, Self::Error> {
        if let Some(algorithm) = jwk.algorithm {
            Ok(algorithm)
        } else {
            Err(Error::MissingAlgorithm)
        }
    }
}

impl TryFrom<&JWK> for Validation {
    type Error = Error;
    fn try_from(jwk: &JWK) -> Result<Self, Self::Error> {
        let algorithm = Algorithm::try_from(jwk)?;
        Ok(Validation::new(algorithm))
    }
}

impl TryFrom<&RSAParams> for DER {
    type Error = Error;
    fn try_from(params: &RSAParams) -> Result<Self, Self::Error> {
        let modulus = match &params.modulus {
            Some(integer) => Integer(Base64urlUInt::try_from(integer.clone())?.0),
            None => return Err(Error::MissingModulus),
        };
        let public_exponent = match &params.exponent {
            Some(integer) => Integer(Base64urlUInt::try_from(integer.clone())?.0),
            None => return Err(Error::MissingExponent),
        };
        if let Some(ref private_exponent) = params.private_exponent {
            let key = RSAPrivateKey {
                modulus,
                public_exponent,
                private_exponent: Integer(private_exponent.0.clone()),
                prime1: match &params.first_prime_factor {
                    Some(integer) => Integer(integer.0.clone()),
                    None => Integer(vec![]),
                },
                prime2: match &params.second_prime_factor {
                    Some(integer) => Integer(integer.0.clone()),
                    None => Integer(vec![]),
                },
                exponent1: match &params.first_prime_factor_crt_exponent {
                    Some(integer) => Integer(integer.0.clone()),
                    None => Integer(vec![]),
                },
                exponent2: match &params.second_prime_factor_crt_exponent {
                    Some(integer) => Integer(integer.0.clone()),
                    None => Integer(vec![]),
                },
                coefficient: match &params.first_crt_coefficient {
                    Some(integer) => Integer(integer.0.clone()),
                    None => Integer(vec![0]),
                },
                other_prime_infos: None,
            };
            Ok(key.into())
        } else {
            let key = RSAPublicKey {
                modulus,
                public_exponent,
            };
            Ok(key.into())
        }
    }
}

impl TryFrom<&OctetParams> for DER {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != "Ed25519".to_string() {
            return Err(Error::KeyTypeNotImplemented);
        }
        let public_key = BitString(params.public_key.0.clone());
        if let Some(private_key) = match &params.private_key {
            Some(private_key) => Some(OctetString(private_key.0.clone())),
            None => None,
        } {
            let key = Ed25519PrivateKey {
                public_key,
                private_key,
            };
            Ok(key.into())
        } else {
            let key = Ed25519PublicKey { public_key };
            Ok(key.into())
        }
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

impl From<Base64urlUInt> for Base64urlUIntString {
    fn from(data: Base64urlUInt) -> Base64urlUIntString {
        String::from(&data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RSA_JSON: &'static str = include_str!("../tests/rsa2048-2020-08-25.json");
    const RSA_DER: &'static [u8] = include_bytes!("../tests/rsa2048-2020-08-25.der");

    #[test]
    fn jwk_to_der_rsa() {
        let key: JWK = serde_json::from_str(RSA_JSON).unwrap();
        let der = DER::try_from(&key).unwrap();
        assert_eq!(der, RSA_DER);
    }

    #[test]
    fn from_did_key() {
        JWK::from_did_key("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap();
    }

    #[test]
    fn ed25519_from_str() {
        let json = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"tfh77YHchREL9WbreVu87Q5P_puHaXGMtLEcmiQSSco\",\"d\":\"KZFPt0DnxRNBdRBQxMJGBUzEt1CgdVqRm-qs474IIlw\"}";
        let _jwk: JWK = serde_json::from_str(&json).unwrap();
    }

    #[test]
    fn generate_ed25519_sign_verify() {
        let key = JWK::generate_ed25519().unwrap();
        let encoding_key = EncodingKey::try_from(&key).unwrap();
        let decoding_key = DecodingKey::try_from(&key).unwrap();
        let message = "asdf".as_bytes();
        let signature =
            jsonwebtoken::crypto::sign_bytes(&message, &encoding_key, Algorithm::EdDSA).unwrap();
        assert!(jsonwebtoken::crypto::verify_bytes(
            &signature,
            &message,
            &decoding_key,
            Algorithm::EdDSA
        )
        .unwrap());
    }
}
