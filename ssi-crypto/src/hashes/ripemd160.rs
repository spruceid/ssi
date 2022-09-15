use crate::hashes::sha256::sha256;

use k256::{elliptic_curve::sec1::ToEncodedPoint, PublicKey};
use ripemd160::{Digest, Ripemd160};

pub fn hash_public_key(pk: &PublicKey, version: u8) -> String {
    let pk_bytes = pk.to_encoded_point(true);
    // as long as its a PublicKey input, I think we can skip the len check
    let pk_sha256 = sha256(pk_bytes.as_bytes());
    let pk_ripemd160 = Ripemd160::digest(&pk_sha256);
    let mut extended_ripemd160 = Vec::with_capacity(21);
    extended_ripemd160.extend_from_slice(&[version]);
    extended_ripemd160.extend_from_slice(&pk_ripemd160);
    bs58::encode(&extended_ripemd160).with_check().into_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash() {
        // https://en.bitcoin.it/wiki/Technical_background_of_version_1_Bitcoin_addresses#How_to_create_Bitcoin_Address
        let pk_hex = "0250863ad64a87ae8a2fe83c1af1a8403cb53f53e486d8511dad8a04887e5b2352";
        let pk_bytes = hex::decode(pk_hex).unwrap();
        let pk = k256::PublicKey::from_sec1_bytes(&pk_bytes).unwrap();
        let hash = hash_public_key(&pk, 0);
        assert_eq!(hash, "1PMycacnJaSqwwJqjawXBErnLsZ7RkXUAs");
    }
}
