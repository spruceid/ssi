#![cfg_attr(docsrs, feature(doc_auto_cfg))]
use core::fmt;
pub use ssi_crypto::{self, key::KeyConversionError, KeyType, SigningKey, VerifyingKey};
use std::result::Result;
use std::{convert::TryFrom, str::FromStr};

mod utils;
pub use utils::Base64urlUInt;

pub mod algorithm;
pub use algorithm::Algorithm;

mod multicodec;

pub mod hash;

// pub mod der;

use serde::{Deserialize, Serialize};

mod r#type;
pub use r#type::*;

// RFC 7516 - JSON Web Encryption (JWE)
// RFC 7517 - JSON Web Key (JWK)
// RFC 7518 - JSON Web Algorithms (JWA)
// RFC 7638 - JSON Web Key (JWK) Thumbprint
// RFC 8037 - CFRG ECDH and Signatures in JOSE
// RFC 8812 - CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption
//  (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms

/// Deprecated
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JWTKeys {
    #[serde(rename = "es256kPrivateKeyJwk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub es256k_private_key: Option<JWK>,
    #[serde(rename = "rs256PrivateKeyJwk")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rs256_private_key: Option<JWK>,
}

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
    pub fn r#type(&self) -> Option<KeyType> {
        self.params.r#type()
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
                Params::Rsa(RsaParams {
                    modulus: Some(n1),
                    exponent: Some(e1),
                    ..
                }),
                Params::Rsa(RsaParams {
                    modulus: Some(n2),
                    exponent: Some(e2),
                    ..
                }),
            ) => n1 == n2 && e1 == e2,
            (Params::Okp(okp1), Params::Okp(okp2)) => {
                okp1.curve == okp2.curve && okp1.public_key == okp2.public_key
            }
            (
                Params::Ec(EcParams {
                    curve: Some(crv1),
                    x_coordinate: Some(x1),
                    y_coordinate: Some(y1),
                    ..
                }),
                Params::Ec(EcParams {
                    curve: Some(crv2),
                    x_coordinate: Some(x2),
                    y_coordinate: Some(y2),
                    ..
                }),
            ) => crv1 == crv2 && x1 == x2 && y1 == y2,
            (
                Params::Oct(OctParams {
                    key_value: Some(kv1),
                }),
                Params::Oct(OctParams {
                    key_value: Some(kv2),
                }),
            ) => kv1 == kv2,
            _ => false,
        }
    }

    pub fn thumbprint(&self) -> Result<String, KeyConversionError> {
        // JWK parameters for thumbprint hashing must be in lexicographical order, and without
        // string escaping.
        // https://datatracker.ietf.org/doc/html/rfc7638#section-3.1
        let json_string = match &self.params {
            Params::Rsa(rsa_params) => {
                let n = rsa_params
                    .modulus
                    .as_ref()
                    .ok_or(KeyConversionError::Invalid)?;
                let e = rsa_params
                    .exponent
                    .as_ref()
                    .ok_or(KeyConversionError::Invalid)?;
                format!(
                    r#"{{"e":"{}","kty":"RSA","n":"{}"}}"#,
                    String::from(e),
                    String::from(n)
                )
            }
            Params::Okp(okp_params) => {
                format!(
                    r#"{{"crv":"{}","kty":"OKP","x":"{}"}}"#,
                    okp_params.curve.clone(),
                    String::from(okp_params.public_key.clone())
                )
            }
            Params::Ec(ec_params) => {
                let curve = ec_params
                    .curve
                    .as_ref()
                    .ok_or(KeyConversionError::Invalid)?;
                let x = ec_params
                    .x_coordinate
                    .as_ref()
                    .ok_or(KeyConversionError::Invalid)?;
                let y = ec_params
                    .y_coordinate
                    .as_ref()
                    .ok_or(KeyConversionError::Invalid)?;
                format!(
                    r#"{{"crv":"{}","kty":"EC","x":"{}","y":"{}"}}"#,
                    curve.clone(),
                    String::from(x),
                    String::from(y)
                )
            }
            Params::Oct(sym_params) => {
                let k = sym_params
                    .key_value
                    .as_ref()
                    .ok_or(KeyConversionError::Invalid)?;
                format!(r#"{{"k":"{}","kty":"oct"}}"#, String::from(k))
            }
        };
        let hash = ssi_crypto::hashes::sha256::sha256(json_string.as_bytes());
        let thumbprint = String::from(Base64urlUInt(hash.to_vec()));
        Ok(thumbprint)
    }
}

impl TryFrom<&JWK> for ssi_crypto::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: &JWK) -> Result<Self, Self::Error> {
        (&value.params).try_into()
    }
}

impl TryFrom<JWK> for ssi_crypto::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: JWK) -> Result<Self, Self::Error> {
        value.params.try_into()
    }
}

impl TryFrom<&JWK> for ssi_crypto::SecretKey {
    type Error = KeyConversionError;

    fn try_from(value: &JWK) -> Result<Self, Self::Error> {
        (&value.params).try_into()
    }
}

impl TryFrom<JWK> for ssi_crypto::SecretKey {
    type Error = KeyConversionError;

    fn try_from(value: JWK) -> Result<Self, Self::Error> {
        value.params.try_into()
    }
}

impl SigningKey for JWK {
    fn sign_bytes(
        &self,
        algorithm: impl Into<ssi_crypto::AlgorithmInstance>,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, ssi_crypto::Error> {
        let secret_key: ssi_crypto::SecretKey = self.try_into()?;
        secret_key.sign_bytes(algorithm, signing_bytes)
    }
}

impl ssi_crypto::Signer for JWK {
    fn key_metadata(&self) -> ssi_crypto::key::KeyMetadata {
        ssi_crypto::key::KeyMetadata::new(
            self.key_id.clone().map(String::into_bytes),
            self.r#type(),
            self.algorithm.map(Into::into),
        )
    }

    async fn sign(
        &self,
        algorithm: ssi_crypto::AlgorithmInstance,
        signing_bytes: &[u8],
    ) -> Result<Box<[u8]>, ssi_crypto::Error> {
        <Self as SigningKey>::sign_bytes(self, algorithm, signing_bytes)
    }
}

impl VerifyingKey for JWK {
    fn key_metadata(&self) -> ssi_crypto::key::KeyMetadata {
        ssi_crypto::key::KeyMetadata::new(
            self.key_id.clone().map(String::into_bytes),
            self.r#type(),
            self.algorithm.map(Into::into),
        )
    }

    fn verify_bytes(
        &self,
        algorithm: impl Into<ssi_crypto::AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
    ) -> Result<ssi_crypto::SignatureVerification, ssi_crypto::Error> {
        let public_key: ssi_crypto::PublicKey = self.try_into()?;
        public_key.verify_bytes(algorithm, signing_bytes, signature)
    }
}

impl ssi_crypto::Verifier for JWK {
    type VerifyingKey = Self;

    async fn get_verifying_key_with(
        &self,
        _key_id: Option<&[u8]>,
        _options: &ssi_crypto::Options,
    ) -> Result<Option<Self::VerifyingKey>, ssi_crypto::Error> {
        Ok(Some(self.clone()))
    }

    async fn verify_with(
        &self,
        _key_id: Option<&[u8]>,
        algorithm: Option<ssi_crypto::AlgorithmInstance>,
        signing_bytes: &[u8],
        signature: &[u8],
        _options: &ssi_crypto::Options,
    ) -> Result<ssi_crypto::SignatureVerification, ssi_crypto::Error> {
        let algorithm = algorithm
            .or_else(|| self.algorithm.map(Into::into))
            .or_else(|| self.r#type().and_then(|ty| ty.default_algorithm_params()))
            .ok_or(ssi_crypto::Error::AlgorithmMissing)?;
        <Self as VerifyingKey>::verify_bytes(self, algorithm, signing_bytes, signature)
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
        if let Params::Ec(ref ec_params) = actual_params {
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
