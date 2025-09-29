use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::{Base64urlUInt, Error};

mod der;
pub use der::*;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default, Hash, Eq, Zeroize)]
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

impl RSAParams {
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

    /// Validate key size is at least 2048 bits, per [RFC 7518 section 3.3](https://www.rfc-editor.org/rfc/rfc7518#section-3.3).
    pub fn validate_key_size(&self) -> Result<(), Error> {
        let n = &self.modulus.as_ref().ok_or(Error::MissingModulus)?.0;
        if n.len() < 256 {
            return Err(Error::InvalidKeyLength(n.len()));
        }
        Ok(())
    }
}

impl Drop for RSAParams {
    fn drop(&mut self) {
        // Zeroize private key fields
        if let Some(ref mut d) = self.private_exponent {
            d.zeroize();
        }
        if let Some(ref mut p) = self.first_prime_factor {
            p.zeroize();
        }
        if let Some(ref mut q) = self.second_prime_factor {
            q.zeroize();
        }
        if let Some(ref mut dp) = self.first_prime_factor_crt_exponent {
            dp.zeroize();
        }
        if let Some(ref mut dq) = self.second_prime_factor_crt_exponent {
            dq.zeroize();
        }
        if let Some(ref mut qi) = self.first_crt_coefficient {
            qi.zeroize();
        }
        if let Some(ref mut primes) = self.other_primes_info {
            for prime in primes {
                prime.zeroize();
            }
        }
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
impl TryFrom<&RSAParams> for rsa::RsaPublicKey {
    type Error = Error;
    fn try_from(params: &RSAParams) -> Result<Self, Self::Error> {
        let n = params.modulus.as_ref().ok_or(Error::MissingModulus)?;
        let e = params.exponent.as_ref().ok_or(Error::MissingExponent)?;
        Ok(Self::new(n.into(), e.into())?)
    }
}

#[cfg(feature = "rsa")]
impl TryFrom<&RSAParams> for rsa::RsaPrivateKey {
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
        Self::from_components(n.into(), e.into(), d.into(), primes)
            // NOTE it's not the correct error type, but it'll be replaced soon
            //      anyway.
            .map_err(|_| Error::InvalidCoordinates)
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

#[cfg(test)]
mod tests {
    use crate::JWK;

    const RSA_JSON: &str = include_str!("../../../../../tests/rsa2048-2020-08-25.json");

    #[test]
    fn rsa_from_str() {
        let _key: JWK = serde_json::from_str(RSA_JSON).unwrap();
    }
}
