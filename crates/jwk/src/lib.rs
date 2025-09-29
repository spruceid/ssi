// RFC 7516 - JSON Web Encryption (JWE)
// RFC 7517 - JSON Web Key (JWK)
// RFC 7518 - JSON Web Algorithms (JWA)
// RFC 7638 - JSON Web Key (JWK) Thumbprint
// RFC 8037 - CFRG ECDH and Signatures in JOSE
// RFC 8812 - CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption
//  (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
use core::fmt;
use serde::{Deserialize, Serialize};
use std::result::Result;
use std::{convert::TryFrom, str::FromStr};

mod utils;
pub use utils::*;

mod r#type;
pub use r#type::*;

pub mod error;
pub use error::Error;

mod hash;
pub use hash::*;

pub mod algorithm;
pub use algorithm::Algorithm;

mod resolver;
pub use resolver::*;

mod multicodec;
pub use multicodec::*;

pub(crate) mod der;

// Re-export legacy de/serialization functions.
#[cfg(feature = "rsa")]
pub use crate::rsa::rsa_x509_pub_parse;
#[cfg(feature = "bbs")]
pub use ec::bbs::bls12381g2_parse;
#[cfg(feature = "secp256k1")]
pub use ec::k256::{secp256k1_parse, secp256k1_parse_private, serialize_secp256k1};
#[cfg(feature = "secp256r1")]
pub use ec::p256::{p256_parse, p256_parse_private, serialize_p256};
#[cfg(feature = "secp384r1")]
pub use ec::p384::{p384_parse, p384_parse_private, serialize_p384};
#[cfg(feature = "ed25519")]
pub use okp::curve25519::{ed25519_parse, ed25519_parse_private};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
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

impl FromStr for JWK {
    type Err = serde_json::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        serde_json::from_str(s)
    }
}

impl TryFrom<&[u8]> for JWK {
    type Error = serde_json::Error;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        serde_json::from_slice(bytes)
    }
}

impl TryFrom<serde_json::Value> for JWK {
    type Error = serde_json::Error;

    fn try_from(value: serde_json::Value) -> Result<Self, Self::Error> {
        serde_json::from_value(value)
    }
}

impl fmt::Display for JWK {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        serde_jcs::to_string(self).unwrap().fmt(f)
    }
}

linked_data::json_literal!(JWK);

impl JWK {
    pub fn get_algorithm(&self) -> Option<Algorithm> {
        if let Some(algorithm) = self.algorithm {
            return Some(algorithm);
        }
        match &self.params {
            Params::RSA(_) => {
                return Some(Algorithm::PS256);
            }
            Params::OKP(okp_params) if okp_params.curve == "Ed25519" => {
                return Some(Algorithm::EdDSA);
            }
            #[cfg(feature = "aleo")]
            Params::OKP(okp_params) if okp_params.curve == crate::okp::aleo::OKP_CURVE => {
                return Some(Algorithm::AleoTestnet1Signature);
            }
            Params::EC(ec_params) => {
                let curve = match &ec_params.curve {
                    Some(curve) => curve,
                    None => return None,
                };
                match &curve[..] {
                    "secp256k1" => {
                        return Some(Algorithm::ES256K);
                    }
                    "P-256" => {
                        return Some(Algorithm::ES256);
                    }
                    "P-384" => {
                        return Some(Algorithm::ES384);
                    }
                    _ => {}
                }
            }
            _ => {}
        };
        None
    }

    /// Strip private key material
    // TODO: use separate type
    pub fn to_public(&self) -> Self {
        let mut key = self.clone();
        key.params = key.params.to_public();
        key
    }

    pub fn is_public(&self) -> bool {
        self.params.is_public()
    }

    /// Compare JWK equality by public key properties.
    /// Equivalent to comparing by [JWK Thumbprint][Self::thumbprint].
    pub fn equals_public(&self, other: &JWK) -> bool {
        match (&self.params, &other.params) {
            (
                Params::RSA(RSAParams {
                    modulus: Some(n1),
                    exponent: Some(e1),
                    ..
                }),
                Params::RSA(RSAParams {
                    modulus: Some(n2),
                    exponent: Some(e2),
                    ..
                }),
            ) => n1 == n2 && e1 == e2,
            (Params::OKP(okp1), Params::OKP(okp2)) => {
                okp1.curve == okp2.curve && okp1.public_key == okp2.public_key
            }
            (
                Params::EC(ECParams {
                    curve: Some(crv1),
                    x_coordinate: Some(x1),
                    y_coordinate: Some(y1),
                    ..
                }),
                Params::EC(ECParams {
                    curve: Some(crv2),
                    x_coordinate: Some(x2),
                    y_coordinate: Some(y2),
                    ..
                }),
            ) => crv1 == crv2 && x1 == x2 && y1 == y2,
            (
                Params::Symmetric(SymmetricParams {
                    key_value: Some(kv1),
                }),
                Params::Symmetric(SymmetricParams {
                    key_value: Some(kv2),
                }),
            ) => kv1 == kv2,
            _ => false,
        }
    }

    pub fn thumbprint(&self) -> Result<String, Error> {
        // JWK parameters for thumbprint hashing must be in lexicographical order, and without
        // string escaping.
        // https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
        let json_string = match &self.params {
            Params::RSA(rsa_params) => {
                let n = rsa_params.modulus.as_ref().ok_or(Error::MissingModulus)?;
                let e = rsa_params.exponent.as_ref().ok_or(Error::MissingExponent)?;
                format!(
                    r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                    String::from(e),
                    String::from(n)
                )
            }
            Params::OKP(okp_params) => {
                format!(
                    r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
                    okp_params.curve.clone(),
                    String::from(okp_params.public_key.clone())
                )
            }
            Params::EC(ec_params) => {
                let curve = ec_params.curve.as_ref().ok_or(Error::MissingCurve)?;
                let x = ec_params.x_coordinate.as_ref().ok_or(Error::MissingPoint)?;
                let y = ec_params.y_coordinate.as_ref().ok_or(Error::MissingPoint)?;
                format!(
                    r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                    curve.clone(),
                    String::from(x),
                    String::from(y)
                )
            }
            Params::Symmetric(sym_params) => {
                let k = sym_params
                    .key_value
                    .as_ref()
                    .ok_or(Error::MissingKeyValue)?;
                format!(r#"{{"k":"{}","kty":"oct"}}"#, String::from(k))
            }
        };
        let hash = ssi_crypto::hashes::sha256::sha256(json_string.as_bytes());
        let thumbprint = String::from(Base64urlUInt(hash.to_vec()));
        Ok(thumbprint)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const JWK_JCS_JSON: &[u8] = include_bytes!("../../../tests/jwk_jcs-pub.json");

    #[test]
    fn jwk_try_from_bytes() {
        let actual_jwk: JWK = JWK::try_from(JWK_JCS_JSON).unwrap();
        let actual_params: Params = actual_jwk.params;
        if let Params::EC(ref ec_params) = actual_params {
            assert_eq!(ec_params.curve.as_deref(), Some("P-256"));
        } else {
            panic!("actual_params is not of type Params::EC");
        }
    }

    #[test]
    fn jwk_thumbprint() {
        // https://tools.ietf.org/html/rfc7638#section-3.1
        let key: JWK = serde_json::from_value(serde_json::json!({
            "kty": "RSA",
            "n": "0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
            "e": "AQAB",
            "alg": "RS256",
            "kid": "2011-04-29"
        }))
        .unwrap();
        let thumbprint = key.thumbprint().unwrap();
        assert_eq!(thumbprint, "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");

        // https://tools.ietf.org/html/rfc8037#appendix-A.3
        let key: JWK = serde_json::from_value(serde_json::json!({
            "crv": "Ed25519",
            "kty": "OKP",
            "x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }))
        .unwrap();
        let thumbprint = key.thumbprint().unwrap();
        assert_eq!(thumbprint, "kPrK_qmxVWaYVA9wwBF6Iuo3vVzz7TxHCTwXBygrS4k");

        // This EC JWK is from RFC 7518, its thumbprint is not.
        // https://datatracker.ietf.org/doc/html/rfc7518#appendix-C
        let key: JWK = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ",
            "y": "e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck",
        }))
        .unwrap();
        let thumbprint = key.thumbprint().unwrap();
        assert_eq!(thumbprint, "Vy57XrArUrW0NbpI12tEzDHABxMwrTh6HHXRenSpnCo");

        // Reuse the octet sequence from the Ed25519 example
        let key: JWK = serde_json::from_value(serde_json::json!({
            "kty": "oct",
            "k": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"
        }))
        .unwrap();
        let thumbprint = key.thumbprint().unwrap();
        assert_eq!(thumbprint, "kcfv_I8tB4KY_ljAlRa1ip-y7jzbPdH0sUlCGb-1Jx8");
    }
}
