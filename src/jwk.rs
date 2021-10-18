use num_bigint::{BigInt, Sign};
use simple_asn1::{ASN1Block, ASN1Class, ToASN1};
use std::convert::TryFrom;
use std::result::Result;

use crate::der::{
    BitString, Ed25519PrivateKey, Ed25519PublicKey, Integer, OctetString, RSAPrivateKey,
    RSAPublicKey,
};
use crate::error::Error;

use serde::{Deserialize, Serialize};

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

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[serde(tag = "kty")]
pub enum Params {
    EC(ECParams),
    RSA(RSAParams),
    #[serde(rename = "oct")]
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
pub struct SymmetricParams {
    // Parameters for Symmetric Keys
    #[serde(rename = "k")]
    pub key_value: Option<Base64urlUInt>,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
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
    EdBlake2b,
    ES256,
    ES256K,
    /// https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r
    #[serde(rename = "ES256K-R")]
    ES256KR,
    ESBlake2b,
    ESBlake2bK,
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
        let mut csprng = rand_old::rngs::OsRng {};
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

    #[cfg(feature = "k256")]
    pub fn generate_secp256k1() -> Result<JWK, Error> {
        let mut rng = rand::rngs::OsRng {};
        let secret_key = k256::SecretKey::random(&mut rng);
        let sk_bytes = secret_key.to_bytes();
        let public_key = secret_key.public_key();
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

    #[cfg(feature = "p256")]
    pub fn generate_p256() -> Result<JWK, Error> {
        let mut rng = rand::rngs::OsRng {};
        let secret_key = p256::SecretKey::random(&mut rng);
        use p256::elliptic_curve::ff::PrimeField;
        let sk_bytes = secret_key.secret_scalar().to_repr();
        let public_key: p256::PublicKey = secret_key.public_key();
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
                return Some(Algorithm::PS256);
            }
            Params::OKP(okp_params) if okp_params.curve == "Ed25519" => {
                return Some(Algorithm::EdDSA);
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

    /// Compare JWK equality by public key properties.
    /// Equivalent to comparing by [JWK Thumbprint][thumbprint].
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
        let hash = crate::hash::sha256(json_string.as_bytes())?;
        let thumbprint = String::from(Base64urlUInt(hash.to_vec()));
        Ok(thumbprint)
    }
}

impl From<Params> for JWK {
    fn from(params: Params) -> Self {
        Self {
            params,
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
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
            exponent: self.exponent.clone(),
            ..Default::default()
        }
    }

    /// Validate key size is at least 2048 bits, per [RFC 7518 section 3.3](https://www.rfc-editor.org/rfc/rfc7518#section-3.3).
    pub fn validate_key_size(&self) -> Result<(), Error> {
        let n = &self.modulus.as_ref().ok_or(Error::MissingModulus)?.0;
        if n.len() < 256 {
            return Err(Error::InvalidKeyLength);
        }
        Ok(())
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
        if let Some(private_key) = self
            .private_key
            .as_ref()
            .map(|private_key| OctetString(private_key.0.clone()))
        {
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

#[cfg(feature = "k256")]
pub fn secp256k1_parse(data: &[u8]) -> Result<JWK, String> {
    let pk = match k256::PublicKey::from_sec1_bytes(data) {
        Ok(pk) => pk,
        Err(err) => {
            return Err(format!("Error parsing key: {}", err));
        }
    };
    let jwk = JWK {
        params: Params::EC(ECParams::try_from(&pk)?),
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
    };
    Ok(jwk)
}

#[cfg(feature = "p256")]
pub fn p256_parse(pk_bytes: &[u8]) -> Result<JWK, Error> {
    let (x, y) = match pk_bytes.len() {
        64 => (pk_bytes[0..32].to_vec(), pk_bytes[32..64].to_vec()),
        33 | 65 => {
            use p256::elliptic_curve::sec1::EncodedPoint;
            let encoded_point: EncodedPoint<p256::NistP256> = EncodedPoint::from_bytes(&pk_bytes)?
                .decompress()
                .ok_or(Error::ECDecompress)?;
            (
                encoded_point.x().ok_or(Error::MissingPoint)?.to_vec(),
                encoded_point.y().ok_or(Error::MissingPoint)?.to_vec(),
            )
        }
        _ => {
            return Err(Error::P256KeyLength(pk_bytes.len()));
        }
    };
    let jwk = JWK {
        params: Params::EC(ECParams {
            curve: Some("P-256".to_string()),
            x_coordinate: Some(Base64urlUInt(x)),
            y_coordinate: Some(Base64urlUInt(y)),
            ecc_private_key: None,
        }),
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
    };
    Ok(jwk)
}

#[cfg(feature = "k256")]
impl TryFrom<&ECParams> for k256::SecretKey {
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
        let secret_key = k256::SecretKey::from_bytes(&private_key.0)?;
        Ok(secret_key)
    }
}

#[cfg(feature = "p256")]
impl TryFrom<&ECParams> for p256::SecretKey {
    type Error = Error;
    fn try_from(params: &ECParams) -> Result<Self, Self::Error> {
        let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
        if curve != "P-256" {
            return Err(Error::CurveNotImplemented(curve.to_string()));
        }
        let private_key = params
            .ecc_private_key
            .as_ref()
            .ok_or(Error::MissingPrivateKey)?;
        let secret_key = p256::SecretKey::from_bytes(&private_key.0)?;
        Ok(secret_key)
    }
}

#[cfg(feature = "k256")]
impl TryFrom<&ECParams> for k256::PublicKey {
    type Error = Error;
    fn try_from(params: &ECParams) -> Result<Self, Self::Error> {
        let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
        if curve != "secp256k1" {
            return Err(Error::CurveNotImplemented(curve.to_string()));
        }
        const EC_UNCOMPRESSED_POINT_TAG: &[u8] = &[0x04];
        let x = &params.x_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
        let y = &params.y_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
        let pk_data = [EC_UNCOMPRESSED_POINT_TAG, x.as_slice(), y.as_slice()].concat();
        let public_key = k256::PublicKey::from_sec1_bytes(&pk_data)?;
        Ok(public_key)
    }
}

#[cfg(feature = "p256")]
impl TryFrom<&ECParams> for p256::PublicKey {
    type Error = Error;
    fn try_from(params: &ECParams) -> Result<Self, Self::Error> {
        let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
        if curve != "P-256" {
            return Err(Error::CurveNotImplemented(curve.to_string()));
        }
        const EC_UNCOMPRESSED_POINT_TAG: &[u8] = &[0x04];
        let x = &params.x_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
        let y = &params.y_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
        let pk_data = [EC_UNCOMPRESSED_POINT_TAG, x.as_slice(), y.as_slice()].concat();
        let public_key = p256::PublicKey::from_sec1_bytes(&pk_data)?;
        Ok(public_key)
    }
}

#[cfg(feature = "k256")]
impl TryFrom<&k256::PublicKey> for ECParams {
    type Error = Error;
    fn try_from(pk: &k256::PublicKey) -> Result<Self, Self::Error> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let ec_points = pk.to_encoded_point(false);
        let x = ec_points.x().ok_or(Error::MissingPoint)?;
        let y = ec_points.y().ok_or(Error::MissingPoint)?;
        Ok(ECParams {
            // TODO according to https://tools.ietf.org/id/draft-jones-webauthn-secp256k1-00.html#rfc.section.2 it should be P-256K?
            curve: Some("secp256k1".to_string()),
            x_coordinate: Some(Base64urlUInt(x.to_vec())),
            y_coordinate: Some(Base64urlUInt(y.to_vec())),
            ecc_private_key: None,
        })
    }
}

#[cfg(feature = "p256")]
impl TryFrom<&p256::PublicKey> for ECParams {
    type Error = Error;
    fn try_from(pk: &p256::PublicKey) -> Result<Self, Self::Error> {
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let encoded_point = pk.to_encoded_point(false);
        let x = encoded_point.x().ok_or(Error::MissingPoint)?;
        let y = encoded_point.y().ok_or(Error::MissingPoint)?;
        Ok(ECParams {
            curve: Some("P-256".to_string()),
            x_coordinate: Some(Base64urlUInt(x.to_vec())),
            y_coordinate: Some(Base64urlUInt(y.to_vec())),
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
    #[cfg(feature = "k256")]
    fn secp256k1_generate() {
        let _jwk = JWK::generate_secp256k1().unwrap();
    }

    #[test]
    #[cfg(feature = "p256")]
    fn p256_generate() {
        let _jwk = JWK::generate_p256().unwrap();
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
