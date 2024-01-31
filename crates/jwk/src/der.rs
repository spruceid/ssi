//! DER (Distinguished Encoding Rules) and ASN.1
//!
//! This module provides various cryptographic data structures and their [ASN.1] (de)serialization
//! using [simple_asn1].
//!
//! [ASN.1]: https://www.iso.org/standard/81420.html "ISO/IEC 8825-1:2021"
//! [simple_asn1]: https://crates.io/crates/simple_asn1
//!
// http://luca.ntop.org/Teaching/Appunti/asn1.html
// https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
// https://en.wikipedia.org/wiki/Distinguished_Encoding_Rules#BER_encoding
// https://serde.rs/impl-serializer.html
// ISO/IEC 8825-1:2015 (E)
// https://tools.ietf.org/html/rfc8017#page-55
// https://tools.ietf.org/html/rfc8410

use num_bigint::{BigInt, Sign};
use simple_asn1::{
    der_encode, ASN1Block, ASN1Class, ASN1DecodeErr, ASN1EncodeErr, FromASN1, ToASN1,
};

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

/// Ed25519 public key for ASN.1 encoding, as specified in [RFC 8410].
///
/// [RFC 8410]: https://datatracker.ietf.org/doc/html/rfc8410#section-10.1 "RFC 8410 Safe Curves for X.509 - 10.1. Example Ed25519 Public Key"
#[derive(Debug, Clone)]
pub struct Ed25519PublicKey {
    pub public_key: BitString,
}

/// Ed25519 private key for ASN.1 encoding, as specified in [RFC 8410].
///
/// [RFC 8410]: https://datatracker.ietf.org/doc/html/rfc8410#section-10.3 "RFC 8410 Safe Curves for X.509 - 10.3. Examples of Ed25519 Private Key"
#[derive(Debug, Clone)]
pub struct Ed25519PrivateKey {
    pub public_key: BitString,
    pub private_key: OctetString,
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

#[derive(Debug, Clone)]
/// An integer value, for encoding in [ASN.1][ITU X.690]
///
/// [ITU X.690]: https://www.itu.int/rec/T-REC-X.690-202102-I/en
pub struct Integer(pub BigInt);

#[derive(Debug, Clone)]
/// An octetstring from [ASN.1][ITU X.690]
///
/// [ITU X.690]: https://www.itu.int/rec/T-REC-X.690-202102-I/en
pub struct OctetString(pub Vec<u8>);

#[derive(Debug, Clone)]
// TODO: support bitstrings not bytes-aligned
/// A bitstring from [ASN.1][ITU X.690]
///
/// Note: only byte-aligned bitstrings are supported.
///
/// [ITU X.690]: https://www.itu.int/rec/T-REC-X.690-202102-I/en
pub struct BitString(pub Vec<u8>);

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
            vec![
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

impl Ed25519PrivateKey {
    fn oid() -> ASN1Block {
        use simple_asn1::BigUint;
        // id-Ed25519 1.3.101.112
        let oid = simple_asn1::OID::new(vec![
            BigUint::new(vec![1]),
            BigUint::new(vec![3]),
            BigUint::new(vec![101]),
            BigUint::new(vec![112]),
        ]);
        ASN1Block::Sequence(0, vec![ASN1Block::ObjectIdentifier(0, oid)])
    }
}

impl ToASN1 for Ed25519PrivateKey {
    type Error = ASN1EncodeErr;
    fn to_asn1_class(&self, _class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        let version = 0;
        // TODO: include public key
        Ok(vec![ASN1Block::Sequence(
            0,
            vec![
                ASN1Block::Integer(0, BigInt::new(Sign::NoSign, vec![version])),
                Ed25519PrivateKey::oid(),
                ASN1Block::OctetString(0, der_encode(&self.private_key)?),
            ],
        )])
    }
}

impl ToASN1 for Ed25519PublicKey {
    type Error = ASN1EncodeErr;
    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::Sequence(
            0,
            self.public_key.to_asn1_class(class)?,
        )])
    }
}

impl ToASN1 for Integer {
    type Error = ASN1EncodeErr;
    fn to_asn1_class(&self, _: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::Integer(0, self.0.clone())])
    }
}

impl ToASN1 for OctetString {
    type Error = ASN1EncodeErr;
    fn to_asn1_class(&self, _: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::OctetString(0, self.0.clone())])
    }
}

impl ToASN1 for BitString {
    type Error = ASN1EncodeErr;
    fn to_asn1_class(&self, _: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        Ok(vec![ASN1Block::BitString(0, 0, self.0.clone())])
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
            vec![
                self.prime.to_asn1_class(class)?,
                self.exponent.to_asn1_class(class)?,
                self.coefficient.to_asn1_class(class)?,
            ]
            .concat(),
        )])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_oid() {
        let expected = vec![0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
        let asn1 = Ed25519PrivateKey::oid();
        let der = simple_asn1::to_der(&asn1).unwrap();
        assert_eq!(der, expected);
    }

    #[test]
    fn encode_integer() {
        let integer = Integer(BigInt::new(Sign::Plus, vec![5]));
        // 0x02: Integer type
        // 0x01: Content length of one byte
        // 0x05: The integer 5
        let expected = vec![0x02, 0x01, 0x05];
        let der = der_encode(&integer).unwrap();
        assert_eq!(der, expected);
    }

    #[test]
    fn encode_ed25519_private_key() {
        let key = Ed25519PrivateKey {
            public_key: BitString(vec![]),
            private_key: OctetString(vec![
                0xD4, 0xEE, 0x72, 0xDB, 0xF9, 0x13, 0x58, 0x4A, 0xD5, 0xB6, 0xD8, 0xF1, 0xF7, 0x69,
                0xF8, 0xAD, 0x3A, 0xFE, 0x7C, 0x28, 0xCB, 0xF1, 0xD4, 0xFB, 0xE0, 0x97, 0xA8, 0x8F,
                0x44, 0x75, 0x58, 0x42,
            ]),
        };
        let expected_b64 = "MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC";
        let expected_key = base64::decode(expected_b64).unwrap();
        let key_der = der_encode(&key).unwrap();
        assert_eq!(key_der, expected_key);
    }
}
