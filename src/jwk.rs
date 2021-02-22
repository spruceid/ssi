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
// RFC 8812 - CBOR Object Signing and Encryption (COSE) and JSON Object Signing and Encryption
//  (JOSE) Registrations for Web Authentication (WebAuthn) Algorithms

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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[serde(tag = "kty")]
pub enum Params {
    EC(ECParams),
    RSA(RSAParams),
    Symmetric(SymmetricParams),
    OKP(OctetParams),
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
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
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_private_key: Option<Base64urlUInt>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default, Hash, Eq)]
pub struct RSAParams {
    // Parameters for RSA Public Keys
    #[serde(rename = "n")]
    pub modulus: Option<Base64urlUInt>,
    #[serde(rename = "e")]
    pub exponent: Option<Base64urlUInt>,

    // Parameters for RSA Private Keys
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_exponent: Option<Base64urlUInt>,
    #[serde(rename = "p")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_prime_factor: Option<Base64urlUInt>,
    #[serde(rename = "q")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second_prime_factor: Option<Base64urlUInt>,
    #[serde(rename = "dp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_prime_factor_crt_exponent: Option<Base64urlUInt>,
    #[serde(rename = "dq")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub second_prime_factor_crt_exponent: Option<Base64urlUInt>,
    #[serde(rename = "qi")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub first_crt_coefficient: Option<Base64urlUInt>,
    #[serde(rename = "oth")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub other_primes_info: Option<Vec<Prime>>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[serde(rename = "oct")]
pub struct SymmetricParams {
    // Parameters for Symmetric Keys
    #[serde(rename = "k")]
    pub key_value: Option<Base64urlUInt>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[serde(rename = "OKP")]
pub struct OctetParams {
    // Parameters for Octet Key Pair Public Keys
    #[serde(rename = "crv")]
    pub curve: String,
    #[serde(rename = "x")]
    pub public_key: Base64urlUInt,

    // Parameters for Octet Key Pair Private Keys
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Base64urlUInt>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
pub struct Prime {
    #[serde(rename = "r")]
    pub prime_factor: Base64urlUInt,
    #[serde(rename = "d")]
    pub factor_crt_exponent: Base64urlUInt,
    #[serde(rename = "t")]
    pub factor_crt_coefficient: Base64urlUInt,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[serde(try_from = "String")]
#[serde(into = "Base64urlUIntString")]
pub struct Base64urlUInt(pub Vec<u8>);
type Base64urlUIntString = String;

#[derive(Debug, Serialize, Deserialize, Clone, Copy, PartialEq, Hash, Eq)]
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
    /// https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r
    #[serde(rename = "ES256K-R")]
    ES256KR,
    None,
}

impl Default for Algorithm {
    fn default() -> Self {
        Self::None
    }
}

impl JWK {
    #[cfg(feature = "ring")]
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

    #[cfg(feature = "ed25519-dalek")]
    pub fn generate_ed25519() -> Result<JWK, Error> {
        let mut csprng = rand::rngs::OsRng {};
        let keypair = ed25519_dalek::Keypair::generate(&mut csprng);
        let sk_bytes = keypair.secret.to_bytes();
        let pk_bytes = keypair.public.to_bytes();
        Ok(JWK {
            params: Params::OKP(OctetParams {
                curve: "Ed25519".to_string(),
                public_key: Base64urlUInt(pk_bytes.to_vec()),
                private_key: Some(Base64urlUInt(sk_bytes.to_vec())),
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

    #[cfg(feature = "libsecp256k1")]
    pub fn generate_secp256k1() -> Result<JWK, Error> {
        let mut rng = rand::rngs::OsRng {};
        let secret_key = secp256k1::SecretKey::random(&mut rng);
        let sk_bytes = secret_key.serialize();
        let public_key = secp256k1::PublicKey::from_secret_key(&secret_key);
        Ok(JWK {
            params: Params::EC(ECParams {
                ecc_private_key: Some(Base64urlUInt(sk_bytes.to_vec())),
                ..ECParams::try_from(&public_key)?
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
            Params::RSA(_) => {
                return Some(Algorithm::RS256);
            }
            Params::OKP(okp_params) if okp_params.curve == "Ed25519" => {
                return Some(Algorithm::EdDSA);
            }
            Params::EC(ec_params) if ec_params.curve == Some("secp256k1".to_string()) => {
                return Some(Algorithm::ES256K);
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

impl Params {
    /// Strip private key material
    pub fn to_public(&self) -> Self {
        match self {
            Self::EC(params) => Self::EC(params.to_public()),
            Self::RSA(params) => Self::RSA(params.to_public()),
            Self::Symmetric(params) => Self::Symmetric(params.to_public()),
            Self::OKP(params) => Self::OKP(params.to_public()),
        }
    }
}

impl ECParams {
    /// Strip private key material
    pub fn to_public(&self) -> Self {
        Self {
            curve: self.curve.clone(),
            x_coordinate: self.x_coordinate.clone(),
            y_coordinate: self.y_coordinate.clone(),
            ecc_private_key: None,
        }
    }
}

impl RSAParams {
    /// Strip private key material
    pub fn to_public(&self) -> Self {
        Self {
            modulus: self.modulus.clone(),
            exponent: self.modulus.clone(),
            ..Default::default()
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

impl SymmetricParams {
    /// Strip private key material
    pub fn to_public(&self) -> Self {
        Self { key_value: None }
    }
}

impl OctetParams {
    /// Strip private key material
    pub fn to_public(&self) -> Self {
        Self {
            curve: self.curve.clone(),
            public_key: self.public_key.clone(),
            private_key: None,
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
            "ES256K-R" => Ok(Self::ES256KR),
            _ => Err(Error::UnsupportedAlgorithm),
        }
    }
}

#[cfg(feature = "rsa")]
impl From<&Base64urlUInt> for rsa::BigUint {
    fn from(uint: &Base64urlUInt) -> Self {
        Self::from_bytes_be(&uint.0)
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&RSAParams> for rsa::RSAPublicKey {
    type Error = Error;
    fn try_from(params: &RSAParams) -> Result<Self, Self::Error> {
        let n = params.modulus.as_ref().ok_or(Error::MissingModulus)?;
        let e = params.exponent.as_ref().ok_or(Error::MissingExponent)?;
        Ok(Self::new(n.into(), e.into())?)
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&RSAParams> for rsa::RSAPrivateKey {
    type Error = Error;
    #[allow(clippy::many_single_char_names)]
    fn try_from(params: &RSAParams) -> Result<Self, Self::Error> {
        let n = params.modulus.as_ref().ok_or(Error::MissingModulus)?;
        let e = params.exponent.as_ref().ok_or(Error::MissingExponent)?;
        let d = params
            .private_exponent
            .as_ref()
            .ok_or(Error::MissingExponent)?;
        let p = params
            .first_prime_factor
            .as_ref()
            .ok_or(Error::MissingPrime)?;
        let q = params
            .second_prime_factor
            .as_ref()
            .ok_or(Error::MissingPrime)?;
        let mut primes = vec![p.into(), q.into()];
        for prime in params.other_primes_info.iter().flatten() {
            primes.push((&prime.prime_factor).into());
        }
        Ok(Self::from_components(n.into(), e.into(), d.into(), primes))
    }
}

#[cfg(feature = "ring")]
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

#[cfg(feature = "ring")]
impl TryFrom<&RSAParams> for ring::signature::RsaKeyPair {
    type Error = Error;
    fn try_from(params: &RSAParams) -> Result<Self, Self::Error> {
        let der = simple_asn1::der_encode(params)?;
        let keypair = Self::from_der(&der)?;
        Ok(keypair)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl TryFrom<&OctetParams> for ed25519_dalek::PublicKey {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        Ok(Self::from_bytes(&params.public_key.0)?)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl TryFrom<&OctetParams> for ed25519_dalek::SecretKey {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        let private_key = params
            .private_key
            .as_ref()
            .ok_or(Error::MissingPrivateKey)?;
        Ok(Self::from_bytes(&private_key.0)?)
    }
}

#[cfg(feature = "ed25519-dalek")]
impl TryFrom<&OctetParams> for ed25519_dalek::Keypair {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        let public = ed25519_dalek::PublicKey::try_from(params)?;
        let secret = ed25519_dalek::SecretKey::try_from(params)?;
        Ok(ed25519_dalek::Keypair { secret, public })
    }
}

#[cfg(feature = "ring")]
impl TryFrom<&OctetParams> for &ring::signature::EdDSAParameters {
    type Error = Error;
    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(Error::CurveNotImplemented(params.curve.to_string()));
        }
        Ok(&ring::signature::ED25519)
    }
}

#[cfg(feature = "ring")]
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

#[cfg(feature = "libsecp256k1")]
impl TryFrom<&ECParams> for secp256k1::SecretKey {
    type Error = Error;
    fn try_from(params: &ECParams) -> Result<Self, Self::Error> {
        let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
        if curve != "secp256k1" {
            return Err(Error::CurveNotImplemented(curve.to_string()));
        }
        let private_key = params
            .ecc_private_key
            .as_ref()
            .ok_or(Error::MissingPrivateKey)?;
        let secret_key = secp256k1::SecretKey::parse_slice(&private_key.0)?;
        Ok(secret_key)
    }
}

#[cfg(feature = "libsecp256k1")]
impl TryFrom<&ECParams> for secp256k1::PublicKey {
    type Error = Error;
    fn try_from(params: &ECParams) -> Result<Self, Self::Error> {
        let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
        if curve != "secp256k1" {
            return Err(Error::CurveNotImplemented(curve.to_string()));
        }
        let x = &params.x_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
        let y = &params.y_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
        // TODO: add sign byte?
        let pk_data = [x.as_slice(), y.as_slice()].concat();
        let public_key =
            secp256k1::PublicKey::parse_slice(&pk_data, Some(secp256k1::PublicKeyFormat::Raw))?;
        Ok(public_key)
    }
}

#[cfg(feature = "libsecp256k1")]
impl TryFrom<&secp256k1::PublicKey> for ECParams {
    type Error = Error;
    fn try_from(pk: &secp256k1::PublicKey) -> Result<Self, Self::Error> {
        let pk_bytes = pk.serialize();
        if pk_bytes[0] != secp256k1::util::TAG_PUBKEY_FULL {
            return Err(Error::UnsupportedKeyType);
        }
        Ok(ECParams {
            curve: Some("secp256k1".to_string()),
            x_coordinate: Some(Base64urlUInt(pk_bytes[1..33].to_vec())),
            y_coordinate: Some(Base64urlUInt(pk_bytes[33..65].to_vec())),
            ecc_private_key: None,
        })
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

    #[test]
    #[cfg(feature = "libsecp256k1")]
    fn secp256k1_generate() {
        let _jwk = JWK::generate_secp256k1().unwrap();
    }
}
