use serde::{Deserialize, Serialize};
use ssi_crypto::key::KeyConversionError;
#[cfg(feature = "rsa")]
use ssi_crypto::rsa::{
    self,
    pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey},
    traits::PublicKeyParts,
};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{Base64urlUInt, JWK};

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default, Hash, Eq, ZeroizeOnDrop)]
pub struct RsaParams {
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

impl RsaParams {
    /// Construct a RSA public key
    pub fn new_public(exponent: &[u8], modulus: &[u8]) -> Self {
        Self {
            modulus: Some(Base64urlUInt(modulus.to_vec())),
            exponent: Some(Base64urlUInt(exponent.to_vec())),
            private_exponent: None,
            first_prime_factor: None,
            second_prime_factor: None,
            first_prime_factor_crt_exponent: None,
            second_prime_factor_crt_exponent: None,
            first_crt_coefficient: None,
            other_primes_info: None,
        }
    }

    pub fn is_public(&self) -> bool {
        self.private_exponent.is_none()
            && self.first_prime_factor.is_none()
            && self.second_prime_factor.is_none()
            && self.first_prime_factor_crt_exponent.is_none()
            && self.second_prime_factor_crt_exponent.is_none()
            && self.first_crt_coefficient.is_none()
            && self.other_primes_info.is_none()
    }

    /// Strip private key material
    pub fn to_public(&self) -> Self {
        Self {
            modulus: self.modulus.clone(),
            exponent: self.exponent.clone(),
            private_exponent: None,
            first_prime_factor: None,
            second_prime_factor: None,
            first_prime_factor_crt_exponent: None,
            second_prime_factor_crt_exponent: None,
            first_crt_coefficient: None,
            other_primes_info: None,
        }
    }

    #[cfg(feature = "rsa")]
    pub fn from_public_rsa(key: &rsa::RsaPublicKey) -> Result<Self, KeyConversionError> {
        Ok(Self {
            modulus: Some(Base64urlUInt(key.n().to_bytes_be())),
            exponent: Some(Base64urlUInt(key.e().to_bytes_be())),
            private_exponent: None,
            first_prime_factor: None,
            second_prime_factor: None,
            first_prime_factor_crt_exponent: None,
            second_prime_factor_crt_exponent: None,
            first_crt_coefficient: None,
            other_primes_info: None,
        })
    }

    /// Deserialize object from ASN.1 DER-encoded `RsaPublicKey` (binary format).
    #[cfg(feature = "rsa")]
    pub fn from_rsa_public_pkcs1_der_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        let key =
            rsa::RsaPublicKey::from_pkcs1_der(bytes).map_err(|_| KeyConversionError::Invalid)?;
        Self::from_public_rsa(&key)
    }

    #[cfg(feature = "rsa")]
    pub fn to_rsa_public_key(&self) -> Result<rsa::RsaPublicKey, KeyConversionError> {
        let n = self.modulus.as_ref().ok_or(KeyConversionError::Invalid)?;
        let e = self.exponent.as_ref().ok_or(KeyConversionError::Invalid)?;
        rsa::RsaPublicKey::new(n.into(), e.into()).map_err(|_| KeyConversionError::Invalid)
    }

    #[cfg(feature = "rsa")]
    pub fn to_rsa_public_pkcs1_der_bytes(&self) -> Result<Box<[u8]>, KeyConversionError> {
        let key = self.to_rsa_public_key()?;
        key.to_pkcs1_der()
            .map(|b| b.as_ref().into())
            .map_err(|_| KeyConversionError::Invalid)
    }

    #[cfg(feature = "rsa")]
    pub fn to_rsa_secret_key(&self) -> Result<rsa::RsaPrivateKey, KeyConversionError> {
        let n = self.modulus.as_ref().ok_or(KeyConversionError::Invalid)?;
        let e = self.exponent.as_ref().ok_or(KeyConversionError::Invalid)?;
        let d = self
            .private_exponent
            .as_ref()
            .ok_or(KeyConversionError::Invalid)?;
        let p = self
            .first_prime_factor
            .as_ref()
            .ok_or(KeyConversionError::Invalid)?;
        let q = self
            .second_prime_factor
            .as_ref()
            .ok_or(KeyConversionError::Invalid)?;
        let mut primes = vec![p.into(), q.into()];
        for prime in self.other_primes_info.iter().flatten() {
            primes.push((&prime.prime_factor).into());
        }
        rsa::RsaPrivateKey::from_components(n.into(), e.into(), d.into(), primes)
            .map_err(|_| KeyConversionError::Invalid)
    }

    /// Validate key size is at least 2048 bits, per [RFC 7518 section 3.3](https://www.rfc-editor.org/rfc/rfc7518#section-3.3).
    pub fn validate_key_size(&self) -> Result<(), KeyConversionError> {
        let n = &self.modulus.as_ref().ok_or(KeyConversionError::Invalid)?.0;

        if n.len() < 256 {
            return Err(KeyConversionError::Invalid);
        }

        Ok(())
    }
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct Prime {
    #[serde(rename = "r")]
    pub prime_factor: Base64urlUInt,
    #[serde(rename = "d")]
    pub factor_crt_exponent: Base64urlUInt,
    #[serde(rename = "t")]
    pub factor_crt_coefficient: Base64urlUInt,
}

#[cfg(feature = "rsa")]
impl From<&Base64urlUInt> for rsa::BigUint {
    fn from(uint: &Base64urlUInt) -> Self {
        Self::from_bytes_be(&uint.0)
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&RsaParams> for rsa::RsaPublicKey {
    type Error = KeyConversionError;

    fn try_from(params: &RsaParams) -> Result<Self, Self::Error> {
        params.to_rsa_public_key()
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&RsaParams> for rsa::RsaPrivateKey {
    type Error = KeyConversionError;

    #[allow(clippy::many_single_char_names)]
    fn try_from(params: &RsaParams) -> Result<Self, Self::Error> {
        params.to_rsa_secret_key()
    }
}

impl TryFrom<&RsaParams> for ssi_crypto::PublicKey {
    type Error = KeyConversionError;

    #[cfg(feature = "rsa")]
    fn try_from(params: &RsaParams) -> Result<Self, Self::Error> {
        params.to_rsa_public_key().map(ssi_crypto::PublicKey::Rsa)
    }

    #[cfg(not(feature = "rsa"))]
    fn try_from(_params: &RsaParams) -> Result<Self, Self::Error> {
        Err(KeyConversionError::Unsupported)
    }
}

impl TryFrom<&RsaParams> for ssi_crypto::SecretKey {
    type Error = KeyConversionError;

    #[cfg(feature = "rsa")]
    fn try_from(params: &RsaParams) -> Result<Self, Self::Error> {
        params.to_rsa_secret_key().map(ssi_crypto::SecretKey::Rsa)
    }

    #[cfg(not(feature = "rsa"))]
    fn try_from(_params: &RsaParams) -> Result<Self, Self::Error> {
        Err(KeyConversionError::Unsupported)
    }
}

impl JWK {
    /// Deserialize object from ASN.1 DER-encoded `RsaPublicKey` (binary format).
    #[cfg(feature = "rsa")]
    pub fn from_rsa_public_pkcs1_der_bytes(bytes: &[u8]) -> Result<JWK, KeyConversionError> {
        RsaParams::from_rsa_public_pkcs1_der_bytes(bytes).map(Into::into)
    }
}

#[cfg(feature = "ring")]
mod ring {
    use ssi_crypto::key::KeyConversionError;

    use super::RsaParams;

    impl<'a> TryFrom<&'a RsaParams> for ssi_crypto::ring::signature::RsaPublicKeyComponents<&'a [u8]> {
        type Error = KeyConversionError;

        fn try_from(params: &'a RsaParams) -> Result<Self, Self::Error> {
            fn trim_bytes(bytes: &[u8]) -> &[u8] {
                const ZERO: [u8; 1] = [0];
                // Remove leading zeros
                match bytes.iter().position(|&x| x != 0) {
                    Some(n) => &bytes[n..],
                    None => &ZERO,
                }
            }
            let n = trim_bytes(
                &params
                    .modulus
                    .as_ref()
                    .ok_or(KeyConversionError::Invalid)?
                    .0,
            );
            let e = trim_bytes(
                &params
                    .exponent
                    .as_ref()
                    .ok_or(KeyConversionError::Invalid)?
                    .0,
            );
            Ok(Self { n, e })
        }
    }

    // impl TryFrom<&RsaParams> for ssi_crypto::ring::signature::RsaKeyPair {
    //     type Error = KeyConversionError;

    //     fn try_from(params: &RsaParams) -> Result<Self, Self::Error> {
    //         let der = simple_asn1::der_encode(params).map_err(|_| KeyConversionError::Invalid)?;
    //         let keypair = Self::from_der(&der).map_err(|_| KeyConversionError::Invalid)?;
    //         Ok(keypair)
    //     }
    // }
}

#[cfg(test)]
mod tests {
    use crate::JWK;

    const RSA_JSON: &str = include_str!("../../../../tests/rsa2048-2020-08-25.json");

    #[test]
    fn rsa_from_str() {
        let _key: JWK = serde_json::from_str(RSA_JSON).unwrap();
    }
}
