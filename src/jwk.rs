use num_bigint::{BigInt, Sign};
use simple_asn1::{ASN1Block, ASN1Class, ToASN1};
use std::convert::TryFrom;
use std::result::Result;
use std::str::FromStr;

use crate::der::{
    BitString, Ed25519PrivateKey, Ed25519PublicKey, Integer, OctetString, RSAPrivateKey,
    RSAPublicKey,
};
use crate::error::Error;

use serde::{Deserialize, Serialize};

// RFC 7516 - JSON Web Encryption (JWE)
// RFC 7517 - JSON Web Key (JWK)
// RFC 7518 - JSON Web Algorithms (JWA)
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
    pub prime_factor: Base64urlUInt,
    #[serde(rename = "d")]
    pub factor_crt_exponent: Base64urlUInt,
    #[serde(rename = "t")]
    pub factor_crt_coefficient: Base64urlUInt,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
#[serde(try_from = "String")]
#[serde(into = "Base64urlUIntString")]
pub struct Base64urlUInt(pub Vec<u8>);
type Base64urlUIntString = String;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq)]
pub enum Algorithm {
    HS256,
    HS384,
    HS512,
    RS256,
    RS384,
    RS512,
    PS256,
    PS384,
    PS512,
    EdDSA,
    ES256K,
    None,
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::None
    }
}

const DID_KEY_ED25519_PREFIX: [u8; 2] = [0xed, 0x01];

impl JWK {
    // TODO: Use TryFrom
    pub fn from_did_key(mut did: &str) -> Result<JWK, Error> {
        if did.len() < 8 {
            return Err(Error::InvalidKeyLength);
        }
        if &did[..8] != "did:key:" {
            return Err(Error::Key);
        }
        // Match "did:key:<data>#<data>"
        if let Some(i) = did.find('#') {
            let begin = &did[8..i];
            let end = &did[(i + 1)..];
            if begin != end {
                return Err(Error::InconsistentDIDKey);
            }
            did = &did[0..i];
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

    pub fn to_verification_method(&self) -> Result<String, Error> {
        let did = self.to_did()?;
        if !did.starts_with("did:key") {
            return Err(Error::UnsupportedKeyType);
        }
        Ok(did.clone() + "#" + &did[8..])
    }

    pub fn generate_ed25519() -> Result<JWK, Error> {
        use ring::signature::KeyPair;
        let rng = ring::rand::SystemRandom::new();
        let doc = ring::signature::Ed25519KeyPair::generate_pkcs8(&rng)?;
        let key_pkcs8 = doc.as_ref();
        let keypair = ring::signature::Ed25519KeyPair::from_pkcs8(key_pkcs8)?;
        let public_key = keypair.public_key().as_ref();
        // reference: ring/src/ec/curve25519/ed25519/signing.rs
        let private_key = &key_pkcs8[0x10..0x30];
        Ok(JWK {
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
        })
    }

    pub fn get_algorithm(&self) -> Option<Algorithm> {
        if let Some(algorithm) = self.algorithm {
            return Some(algorithm);
        }
        match &self.params {
            Params::OKP(okp_params) if okp_params.curve == "Ed25519" => {
                return Some(Algorithm::EdDSA);
            }
            _ => {}
        };
        None
    }
}

impl Params {
    pub fn to_did(&self) -> Result<String, Error> {
        match self {
            Self::OKP(okp) => okp.to_did(),
            _ => Err(Error::UnsupportedKeyType),
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

impl ToASN1 for JWK {
    type Error = Error;
    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        match &self.params {
            // EC(params) => params.to_asn1_class(class),
            Params::RSA(params) => params.to_asn1_class(class),
            // Symmetric(params) => params.to_asn1_class(class),
            Params::OKP(params) => params.to_asn1_class(class),
            _ => Err(Error::KeyTypeNotImplemented),
        }
    }
}

impl ToASN1 for RSAParams {
    type Error = Error;
    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let modulus = match &self.modulus {
            Some(integer) => Integer(BigInt::from_bytes_be(Sign::Plus, &integer.0)),
            None => return Err(Error::MissingModulus),
        };
        let public_exponent = match &self.exponent {
            Some(integer) => Integer(BigInt::from_bytes_be(Sign::Plus, &integer.0)),
            None => return Err(Error::MissingExponent),
        };
        if let Some(ref private_exponent) = self.private_exponent {
            let key = RSAPrivateKey {
                modulus,
                public_exponent,
                private_exponent: Integer(BigInt::from_bytes_be(Sign::Plus, &private_exponent.0)),
                prime1: match &self.first_prime_factor {
                    Some(integer) => Integer(BigInt::from_bytes_be(Sign::Plus, &integer.0)),
                    None => Integer(BigInt::new(Sign::NoSign, vec![])),
                },
                prime2: match &self.second_prime_factor {
                    Some(integer) => Integer(BigInt::from_bytes_be(Sign::Plus, &integer.0)),
                    None => Integer(BigInt::new(Sign::NoSign, vec![])),
                },
                exponent1: match &self.first_prime_factor_crt_exponent {
                    Some(integer) => Integer(BigInt::from_bytes_be(Sign::Plus, &integer.0)),
                    None => Integer(BigInt::new(Sign::NoSign, vec![])),
                },
                exponent2: match &self.second_prime_factor_crt_exponent {
                    Some(integer) => Integer(BigInt::from_bytes_be(Sign::Plus, &integer.0)),
                    None => Integer(BigInt::new(Sign::NoSign, vec![])),
                },
                coefficient: match &self.first_crt_coefficient {
                    Some(integer) => Integer(BigInt::from_bytes_be(Sign::Plus, &integer.0)),
                    None => Integer(BigInt::new(Sign::NoSign, vec![0])),
                },
                other_prime_infos: None,
            };
            key.to_asn1_class(class)
        } else {
            let key = RSAPublicKey {
                modulus,
                public_exponent,
            };
            key.to_asn1_class(class)
        }
    }
}

impl ToASN1 for OctetParams {
    type Error = Error;
    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        if self.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(self.curve.to_string()));
        }
        let public_key = BitString(self.public_key.0.clone());
        if let Some(private_key) = match &self.private_key {
            Some(private_key) => Some(OctetString(private_key.0.clone())),
            None => None,
        } {
            let key = Ed25519PrivateKey {
                public_key,
                private_key,
            };
            key.to_asn1_class(class)
        } else {
            let key = Ed25519PublicKey { public_key };
            key.to_asn1_class(class)
        }
    }
}

impl FromStr for Algorithm {
    type Err = Error;
    fn from_str(algorithm: &str) -> Result<Self, Self::Err> {
        match algorithm {
            "HS256" => Ok(Self::HS256),
            "HS384" => Ok(Self::HS384),
            "HS512" => Ok(Self::HS512),
            "RS256" => Ok(Self::RS256),
            "RS384" => Ok(Self::RS384),
            "RS512" => Ok(Self::RS512),
            "PS256" => Ok(Self::PS256),
            "PS384" => Ok(Self::PS384),
            "PS512" => Ok(Self::PS512),
            "EdDSA" => Ok(Self::EdDSA),
            "ES256K" => Ok(Self::ES256K),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

impl<'a> TryFrom<&'a RSAParams> for ring::signature::RsaPublicKeyComponents<&'a [u8]> {
    type Error = Error;
    fn try_from(params: &'a RSAParams) -> Result<Self, Self::Error> {
        fn trim_bytes(bytes: &[u8]) -> &[u8] {
            const ZERO: [u8; 1] = [0];
            // Remove leading zeros
            match bytes.iter().position(|&x| x != 0) {
                Some(n) => &bytes[n..],
                None => &ZERO,
            }
        }
        let n = trim_bytes(&params.modulus.as_ref().ok_or(Error::MissingModulus)?.0);
        let e = trim_bytes(&params.exponent.as_ref().ok_or(Error::MissingExponent)?.0);
        Ok(Self { n, e })
    }
}

impl TryFrom<&RSAParams> for ring::signature::RsaKeyPair {
    type Error = Error;
    fn try_from(params: &RSAParams) -> Result<Self, Self::Error> {
        let der = simple_asn1::der_encode(params)?;
        let keypair = Self::from_der(&der)?;
        Ok(keypair)
    }
}

impl TryFrom<&OctetParams> for &ring::signature::EdDSAParameters {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        Ok(&ring::signature::ED25519)
    }
}

impl TryFrom<&OctetParams> for ring::signature::Ed25519KeyPair {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        params
            .private_key
            .as_ref()
            .ok_or(Error::MissingPrivateKey)?;
        let der = simple_asn1::der_encode(params)?;
        let keypair = Self::from_pkcs8_maybe_unchecked(&der)?;
        Ok(keypair)
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
    const ED25519_JSON: &'static str = include_str!("../tests/ed25519-2020-10-18.json");

    #[test]
    fn jwk_to_der_rsa() {
        let key: JWK = serde_json::from_str(RSA_JSON).unwrap();
        let der = simple_asn1::der_encode(&key).unwrap();
        assert_eq!(der, RSA_DER);
    }

    #[test]
    fn from_did_key() {
        JWK::from_did_key("did:key:z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH#z6MkpTHR8VNsBxYAAWHut2Geadd9jSwuBV8xRoAnwWsdvktH").unwrap();
    }

    #[test]
    fn rsa_from_str() {
        let _key: JWK = serde_json::from_str(RSA_JSON).unwrap();
    }

    #[test]
    fn ed25519_from_str() {
        let _jwk: JWK = serde_json::from_str(ED25519_JSON).unwrap();
    }

    #[test]
    fn generate_ed25519() {
        let _key = JWK::generate_ed25519().unwrap();
    }
}
