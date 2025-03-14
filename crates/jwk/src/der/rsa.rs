use num_bigint::{BigInt, Sign};
use simple_asn1::{ASN1Block, ASN1Class, ASN1DecodeErr, ASN1EncodeErr, FromASN1, ToASN1};
use ssi_crypto::key::KeyConversionError;

use crate::RsaParams;

use super::{Asn1KeyConversionError, Integer};

/// RSA private key for ASN.1 encoding, as specified in [RFC 8017].
///
/// [RFC 8017]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.2 "RFC 8017 PKCS #1 v2.2 - A.1.2. RSA Private Key Syntax"
#[derive(Debug, Clone)]
pub struct RSAPrivateKey {
    pub modulus: Integer,
    pub public_exponent: Integer,
    pub private_exponent: Integer,
    pub prime1: Integer,
    pub prime2: Integer,
    pub exponent1: Integer,
    pub exponent2: Integer,
    pub coefficient: Integer,
    pub other_prime_infos: Option<OtherPrimeInfos>,
}

/// RSA public key for ASN.1 encoding, as specified in [RFC 8017].
///
/// [RFC 8017]: https://datatracker.ietf.org/doc/html/rfc8017#appendix-A.1.1 "RFC 8017 PKCS #1 v2.2 - A.1.1. RSA Public Key Syntax"
#[derive(Debug, Clone)]
// https://datatracker.ietf.org/doc/html/rfc3447#appendix-A.1.1
pub struct RSAPublicKey {
    pub modulus: Integer,
    pub public_exponent: Integer,
}

/// Additional primes in a [RSA private key][RSAPrivateKey], as specified in [RFC 8017].
///
/// [RFC 8017]: https://datatracker.ietf.org/doc/html/rfc8017#page-56 "RFC 8017 PKCS #1 v2.2 - Page 56"
#[derive(Debug, Clone)]
pub struct OtherPrimeInfos(pub Vec<OtherPrimeInfo>);

/// Additional prime in a [RSA private key][RSAPrivateKey], as specified in [RFC 8017].
///
/// [RFC 8017]: https://datatracker.ietf.org/doc/html/rfc8017#page-56 "RFC 8017 PKCS #1 v2.2 - Page 56"
#[derive(Debug, Clone)]
pub struct OtherPrimeInfo {
    pub prime: Integer,
    pub exponent: Integer,
    pub coefficient: Integer,
}

impl ToASN1 for RSAPrivateKey {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let multiprime = self.other_prime_infos.is_some();
        let version = Integer(BigInt::new(Sign::Plus, vec![u32::from(multiprime)]));
        Ok(vec![ASN1Block::Sequence(
            0,
            [
                version.to_asn1_class(class)?,
                self.modulus.to_asn1_class(class)?,
                self.public_exponent.to_asn1_class(class)?,
                self.private_exponent.to_asn1_class(class)?,
                self.prime1.to_asn1_class(class)?,
                self.prime2.to_asn1_class(class)?,
                self.exponent1.to_asn1_class(class)?,
                self.exponent2.to_asn1_class(class)?,
                self.coefficient.to_asn1_class(class)?,
                match self.other_prime_infos {
                    Some(ref infos) => infos.to_asn1_class(class)?,
                    None => Vec::new(),
                },
            ]
            .concat(),
        )])
    }
}

impl ToASN1 for RSAPublicKey {
    type Error = ASN1EncodeErr;
    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::Sequence(
            0,
            [
                self.modulus.to_asn1_class(class)?,
                self.public_exponent.to_asn1_class(class)?,
            ]
            .concat(),
        )])
    }
}

#[derive(thiserror::Error, Debug)]
pub enum RSAPublicKeyFromASN1Error {
    #[error("Expected single sequence")]
    ExpectedSingleSequence,
    #[error("Expected two integers")]
    ExpectedTwoIntegers,
    #[error("ASN1 decoding error: {0:?}")]
    ASN1Decode(#[from] ASN1DecodeErr),
}

impl FromASN1 for RSAPublicKey {
    type Error = RSAPublicKeyFromASN1Error;

    fn from_asn1(v: &[ASN1Block]) -> Result<(Self, &[ASN1Block]), Self::Error> {
        let vec = match v {
            [ASN1Block::Sequence(_, vec)] => vec,
            _ => return Err(RSAPublicKeyFromASN1Error::ExpectedSingleSequence),
        };
        let (n, e) = match vec.as_slice() {
            [ASN1Block::Integer(_, n), ASN1Block::Integer(_, e)] => (n, e),
            _ => return Err(RSAPublicKeyFromASN1Error::ExpectedTwoIntegers),
        };
        let pk = Self {
            modulus: Integer(n.clone()),
            public_exponent: Integer(e.clone()),
        };
        Ok((pk, &[]))
    }
}

impl ToASN1 for OtherPrimeInfos {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::Sequence(
            0,
            self.0
                .iter()
                .map(|x| x.to_asn1_class(class))
                .collect::<Result<Vec<Vec<ASN1Block>>, ASN1EncodeErr>>()?
                .concat(),
        )])
    }
}

impl ToASN1 for OtherPrimeInfo {
    type Error = ASN1EncodeErr;

    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::Sequence(
            0,
            [
                self.prime.to_asn1_class(class)?,
                self.exponent.to_asn1_class(class)?,
                self.coefficient.to_asn1_class(class)?,
            ]
            .concat(),
        )])
    }
}

impl ToASN1 for RsaParams {
    type Error = Asn1KeyConversionError;

    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let modulus = match &self.modulus {
            Some(integer) => Integer(BigInt::from_bytes_be(Sign::Plus, &integer.0)),
            None => Err(KeyConversionError::Invalid)?,
        };
        let public_exponent = match &self.exponent {
            Some(integer) => Integer(BigInt::from_bytes_be(Sign::Plus, &integer.0)),
            None => Err(KeyConversionError::Invalid)?,
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
            Ok(key.to_asn1_class(class)?)
        } else {
            let key = RSAPublicKey {
                modulus,
                public_exponent,
            };
            Ok(key.to_asn1_class(class)?)
        }
    }
}

// #[derive(thiserror::Error, Debug)]
// pub enum RSAParamsFromPublicKeyError {
//     #[error("RSA Public Key from ASN1 error: {0:?}")]
//     RSAPublicKeyFromASN1(RSAPublicKeyFromASN1Error),
//     #[error("Expected positive integer in RSA key")]
//     ExpectedPlus,
// }

// #[derive(thiserror::Error, Debug)]
// pub enum RsaX509PubParseError {
//     #[error("RSAPublicKey from ASN1: {0:?}")]
//     RSAPublicKeyFromASN1(#[from] RSAPublicKeyFromASN1Error),
//     #[error("RSA JWK params from RSAPublicKey: {0:?}")]
//     RSAParamsFromPublicKey(#[from] RSAParamsFromPublicKeyError),
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Params, JWK};

    const RSA_JSON: &str = include_str!("../../../../tests/rsa2048-2020-08-25.json");
    const RSA_DER: &[u8] = include_bytes!("../../../../tests/rsa2048-2020-08-25.der");
    const RSA_PK_DER: &[u8] = include_bytes!("../../../../tests/rsa2048-2020-08-25-pk.der");

    #[test]
    fn jwk_to_from_der_rsa() {
        let key: JWK = serde_json::from_str(RSA_JSON).unwrap();
        let der = simple_asn1::der_encode(&key).unwrap();
        assert_eq!(der, RSA_DER);
        let rsa_pk: RSAPublicKey = simple_asn1::der_decode(RSA_PK_DER).unwrap();
        let rsa_params = RsaParams::try_from(&rsa_pk).unwrap();
        assert_eq!(key.to_public().params, Params::Rsa(rsa_params));
    }

    #[test]
    fn rsa_from_str() {
        let _key: JWK = serde_json::from_str(RSA_JSON).unwrap();
    }
}
