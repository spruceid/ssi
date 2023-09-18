use keccak_hash::keccak;

pub fn bytes_to_lowerhex(bytes: &[u8]) -> String {
    "0x".to_string()
        + &bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
}

/// Compute a hash of a public key as an Ethereum address.
///
/// The hash is of the public key (64 bytes), using Keccak. The hash is truncated to the last 20
/// bytes, lowercase-hex-encoded, and prefixed with "0x" to form the resulting string.
#[cfg(feature = "secp256k1")]
pub fn hash_public_key(k: &k256::PublicKey) -> String {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let pk_ec = k.to_encoded_point(false);
    let pk_bytes = pk_ec.as_bytes();
    let hash = keccak(&pk_bytes[1..65]).to_fixed_bytes();
    let hash_last20 = &hash[12..32];
    bytes_to_lowerhex(hash_last20)
}

/// Compute a hash of a public key as an Ethereum address, with EIP-55 checksum.
///
/// Same as [`hash_public_key_lowercase`], but with [EIP-55] mixed-case checksum encoding (using [`eip55_checksum_addr`]).
/// [EIP-55]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
#[cfg(feature = "secp256k1")]
pub fn hash_public_key_eip55(k: &k256::PublicKey) -> Result<String, Eip155Error> {
    let hash_lowercase = hash_public_key(k);
    eip55_checksum_addr(&hash_lowercase)
}

#[derive(thiserror::Error, Debug)]
pub enum Eip155Error {
    #[error("Missing 0x prefix")]
    HexString,
    #[error("Expected lower case hex string")]
    ExpectedLowerCase,
}

/// Convert an Ethereum address into a mixed-case Ethereum address using [EIP-55] checksum
/// encoding.
/// Input string must begin with "0x" and be in lowercase.
/// Output string begins with "0x".
/// [EIP-55]: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md
pub fn eip55_checksum_addr(addr: &str) -> Result<String, Eip155Error> {
    let addr = addr.strip_prefix("0x").ok_or(Eip155Error::HexString)?;
    if addr.contains(|c: char| c.is_ascii_uppercase()) {
        return Err(Eip155Error::ExpectedLowerCase);
    }
    let eip55_hash = keccak(addr.as_bytes()).to_fixed_bytes();
    let checksummed_addr = addr
        .chars()
        .enumerate()
        .map(|(i, c)| {
            if matches!(c, 'a' | 'b' | 'c' | 'd' | 'e' | 'f')
                && (eip55_hash[i >> 1] & if i % 2 == 0 { 128 } else { 8 } != 0)
            {
                c.to_ascii_uppercase()
            } else {
                c
            }
        })
        .collect::<String>();
    Ok("0x".to_string() + &checksummed_addr)
}

pub fn prefix_personal_message(msg: &str) -> Vec<u8> {
    let msg_bytes = msg.as_bytes();
    let prefix = format!("\x19Ethereum Signed Message:\n{}", msg_bytes.len());
    [prefix.as_bytes().to_vec(), msg_bytes.to_vec()].concat()
}

pub fn hash_personal_message(msg: &str) -> Vec<u8> {
    let data = prefix_personal_message(msg);
    keccak(data).to_fixed_bytes().to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_personal_message() {
        let msg = "Hello world";
        let hash = hash_personal_message(msg);
        let hash_hex = bytes_to_lowerhex(&hash);
        assert_eq!(
            hash_hex,
            "0x8144a6fa26be252b86456491fbcd43c1de7e022241845ffea1c3df066f7cfede"
        );
    }

    #[test]
    fn test_eip55() {
        // https://github.com/ethereum/EIPs/blob/master/EIPS/eip-55.md#test-cases
        // All caps
        assert_eq!(
            eip55_checksum_addr("0x52908400098527886e0f7030069857d2e4169ee7").unwrap(),
            "0x52908400098527886E0F7030069857D2E4169EE7"
        );
        assert_eq!(
            eip55_checksum_addr("0x8617e340b3d01fa5f11f306f4090fd50e238070d").unwrap(),
            "0x8617E340B3D01FA5F11F306F4090FD50E238070D"
        );
        // All Lower
        assert_eq!(
            eip55_checksum_addr("0xde709f2102306220921060314715629080e2fb77").unwrap(),
            "0xde709f2102306220921060314715629080e2fb77"
        );
        assert_eq!(
            eip55_checksum_addr("0x27b1fdb04752bbc536007a920d24acb045561c26").unwrap(),
            "0x27b1fdb04752bbc536007a920d24acb045561c26"
        );
        // Normal
        assert_eq!(
            eip55_checksum_addr("0x5aaeb6053f3e94c9b9a09f33669435e7ef1beaed").unwrap(),
            "0x5aAeb6053F3E94C9b9A09f33669435E7Ef1BeAed"
        );
        assert_eq!(
            eip55_checksum_addr("0xfb6916095ca1df60bb79ce92ce3ea74c37c5d359").unwrap(),
            "0xfB6916095ca1df60bB79Ce92cE3Ea74c37c5d359"
        );
        assert_eq!(
            eip55_checksum_addr("0xdbf03b407c01e7cd3cbea99509d93f8dddc8c6fb").unwrap(),
            "0xdbF03B407c01E7cD3CBea99509d93f8DDDC8C6FB"
        );
        assert_eq!(
            eip55_checksum_addr("0xd1220a0cf47c7b9be7a2e6ba89f429762e7b9adb").unwrap(),
            "0xD1220A0cf47c7B9Be7A2E6BA89F429762e7b9aDb"
        );
    }
}
