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
use num_bigint::BigInt;
use simple_asn1::{ASN1Block, ASN1Class, ASN1EncodeErr, ToASN1};

mod rsa;
pub use rsa::*;

mod okp;
pub use okp::*;
use ssi_crypto::key::KeyConversionError;

use crate::{Params, JWK};

#[derive(Debug, thiserror::Error)]
#[error(transparent)]
pub struct Asn1KeyConversionError(#[from] pub KeyConversionError);

impl From<ASN1EncodeErr> for Asn1KeyConversionError {
    fn from(_value: ASN1EncodeErr) -> Self {
        Self(KeyConversionError::Invalid)
    }
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

impl ToASN1 for JWK {
    type Error = Asn1KeyConversionError;

    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        match &self.params {
            // EC(params) => params.to_asn1_class(class),
            Params::Rsa(params) => params.to_asn1_class(class),
            // Symmetric(params) => params.to_asn1_class(class),
            Params::Okp(params) => params.to_asn1_class(class),
            _ => Err(KeyConversionError::Unsupported)?,
        }
    }
}

#[cfg(test)]
mod tests {
    use num_bigint::Sign;
    use simple_asn1::der_encode;

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
}
