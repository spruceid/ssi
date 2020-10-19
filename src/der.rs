// http://luca.ntop.org/Teaching/Appunti/asn1.html
// https://tls.mbed.org/kb/cryptography/asn1-key-structures-in-der-and-pem
// https://en.wikipedia.org/wiki/Distinguished_Encoding_Rules#BER_encoding
// https://serde.rs/impl-serializer.html
// ISO/IEC 8825-1:2015 (E)
// https://tools.ietf.org/html/rfc8017#page-55
// https://tools.ietf.org/html/rfc8410

use std::convert::From;

const TAG_INTEGER: u8 = 0x02;
const TAG_OCTETSTRING: u8 = 0x04;
const TAG_BITSTRING: u8 = 0x03;
const TAG_SEQUENCE: u8 = 0x10;

pub type DER = Vec<u8>;

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

#[derive(Debug, Clone)]
pub struct RSAPublicKey {
    pub modulus: Integer,
    pub public_exponent: Integer,
}

#[derive(Debug, Clone)]
pub struct Ed25519PublicKey {
    pub public_key: BitString,
}

#[derive(Debug, Clone)]
pub struct Ed25519PrivateKey {
    pub public_key: BitString,
    pub private_key: OctetString,
}

#[derive(Debug, Clone)]
pub struct OtherPrimeInfos(pub Vec<OtherPrimeInfo>);

#[derive(Debug, Clone)]
pub struct OtherPrimeInfo {
    pub prime: Integer,
    pub exponent: Integer,
    pub coefficient: Integer,
}

#[derive(Debug, Clone)]
pub struct Integer(pub Vec<u8>);

#[derive(Debug, Clone)]
pub struct OctetString(pub Vec<u8>);

#[derive(Debug, Clone)]
// TODO: support bitstrings not bytes-aligned
pub struct BitString(pub Vec<u8>);

fn trim_bytes(bytes: &[u8]) -> Vec<u8> {
    // Remove leading zeros from an array.
    match bytes.into_iter().position(|&x| x != 0) {
        Some(n) => bytes[n..].to_vec(),
        None => vec![0],
    }
}

fn encode(tag: u8, constructed: bool, contents: Vec<u8>) -> Vec<u8> {
    // prepare an ASN1 tag-length-value
    let id = tag
        // set bit for constructed (vs primitive)
        | match constructed {
            true => 0x20,
            false => 0,
        };
    let len = contents.len();
    let len_bytes = trim_bytes(&len.to_be_bytes());
    if len <= 127 {
        return [vec![id, len_bytes[0]], contents].concat();
    }
    let len_len = len_bytes.len();
    if len_len >= 127 {
        // This can't really happen, since to_be_bytes returns an array of length 2, 4, or 8.
        panic!("Key data too large");
    }
    let len_len_bytes = trim_bytes(&len_len.to_be_bytes());
    [vec![id, 0x80 | len_len_bytes[0]], len_bytes, contents].concat()
}

impl From<RSAPrivateKey> for DER {
    fn from(key: RSAPrivateKey) -> Self {
        let multiprime = key.other_prime_infos.is_some();
        let version = Integer(vec![if multiprime { 1 } else { 0 }]);
        encode(
            TAG_SEQUENCE,
            true,
            [
                DER::from(version),
                DER::from(key.modulus),
                DER::from(key.public_exponent),
                DER::from(key.private_exponent),
                DER::from(key.prime1),
                DER::from(key.prime2),
                DER::from(key.exponent1),
                DER::from(key.exponent2),
                DER::from(key.coefficient),
                match key.other_prime_infos {
                    Some(infos) => DER::from(infos),
                    None => Vec::new(),
                },
            ]
            .concat(),
        )
    }
}

impl From<RSAPublicKey> for DER {
    fn from(key: RSAPublicKey) -> Self {
        encode(
            TAG_SEQUENCE,
            true,
            [DER::from(key.modulus), DER::from(key.public_exponent)].concat(),
        )
    }
}

impl Ed25519PrivateKey {
    fn oid() -> Vec<u8> {
        // id-Ed25519 1.3.101.112
        return vec![0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
    }
}

impl From<Ed25519PrivateKey> for DER {
    fn from(key: Ed25519PrivateKey) -> Self {
        let version = Integer(vec![0]);
        // TODO: include public key
        encode(
            TAG_SEQUENCE,
            true,
            [
                DER::from(version),
                Ed25519PrivateKey::oid(),
                DER::from(key.private_key),
            ]
            .concat(),
        )
    }
}

impl From<Ed25519PublicKey> for DER {
    fn from(key: Ed25519PublicKey) -> Self {
        DER::from(key.public_key)
    }
}

impl From<Integer> for DER {
    fn from(key: Integer) -> Self {
        encode(TAG_INTEGER, false, key.0)
    }
}

impl From<OctetString> for DER {
    fn from(octets: OctetString) -> Self {
        encode(
            TAG_OCTETSTRING,
            false,
            encode(TAG_OCTETSTRING, false, octets.0),
        )
    }
}

impl From<BitString> for DER {
    fn from(data: BitString) -> Self {
        encode(TAG_BITSTRING, false, [vec![0], data.0].concat())
    }
}

impl From<OtherPrimeInfos> for DER {
    fn from(infos: OtherPrimeInfos) -> Self {
        encode(
            TAG_SEQUENCE,
            true,
            infos.0.into_iter().flat_map(DER::from).collect(),
        )
    }
}

impl From<OtherPrimeInfo> for DER {
    fn from(info: OtherPrimeInfo) -> Self {
        encode(
            TAG_SEQUENCE,
            true,
            [
                DER::from(info.prime),
                DER::from(info.exponent),
                DER::from(info.coefficient),
            ]
            .concat(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_integer() {
        let integer = Integer(vec![5]);
        // 0x02: Integer type
        // 0x01: Content length of one byte
        // 0x05: The integer 5
        let expected = vec![0x02, 0x01, 0x05];
        assert_eq!(DER::from(integer), expected);
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
        assert_eq!(DER::from(key), expected_key);
    }
}
