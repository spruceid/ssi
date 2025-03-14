use num_bigint::{BigInt, Sign};
use simple_asn1::{der_encode, ASN1Block, ASN1Class, ASN1EncodeErr, ToASN1};
use ssi_crypto::key::KeyConversionError;

use crate::{okp::curve::ED25519, OkpParams};

use super::{Asn1KeyConversionError, BitString, OctetString};

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

impl Ed25519PrivateKey {
    pub(crate) fn oid() -> ASN1Block {
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

impl ToASN1 for OkpParams {
    type Error = Asn1KeyConversionError;

    fn to_asn1_class(&self, class: ASN1Class) -> Result<Vec<ASN1Block>, Self::Error> {
        if self.curve != *ED25519 {
            Err(KeyConversionError::Unsupported)?;
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
            Ok(key.to_asn1_class(class)?)
        } else {
            let key = Ed25519PublicKey { public_key };
            Ok(key.to_asn1_class(class)?)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;

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
        let expected_key = base64::prelude::BASE64_STANDARD
            .decode(expected_b64)
            .unwrap();
        let key_der = der_encode(&key).unwrap();
        assert_eq!(key_der, expected_key);
    }
}
