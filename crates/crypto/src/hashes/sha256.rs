//! Cryptographic hash functions
//!
//! The [`sha256`] function requires feature either `sha2` or `ring` (not both).

/// SHA-256 hash
pub fn sha256(data: &[u8]) -> [u8; 32] {
    #[cfg(feature = "ring")]
    {
        // The "ring" feature takes precedence for the impl of sha256.
        use ring::digest;
        let hash = digest::digest(&digest::SHA256, data);

        // we're pretty sure this will always be 32 bytes long
        assert!(
            hash.as_ref().len() == digest::SHA256.output_len,
            "ring's Sha256 implementation has returned a digest of len {}, expected 32",
            hash.as_ref().len()
        );

        hash.as_ref().try_into().unwrap()
    }
    #[cfg(not(feature = "ring"))]
    {
        // Only if "ring" is not enabled, but "sha2" is, does it use "sha2" for the sha256 impl.
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        assert_eq!(
            sha256(&[]),
            [
                227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39,
                174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85
            ]
        );
    }

    #[test]
    fn test_sha256() {
        // Test vector from a known SHA-256 hash
        let data = b"hello world";
        let expected_hash: [u8; 32] = [
            0xb9, 0x8f, 0x3f, 0x2e, 0x8e, 0x7d, 0xe5, 0x26, 0x0a, 0x3b, 0xd6, 0x84, 0x98, 0xe8, 0x73, 0x2d,
            0x2d, 0x36, 0xd3, 0x89, 0xd4, 0x9a, 0x56, 0x1d, 0x9a, 0x2b, 0x62, 0xd4, 0x92, 0x6f, 0x5f, 0x88,
        ];

        let hash = sha256(data);
        assert_eq!(hash, expected_hash);
    }

    #[test]
    fn test_sha256_empty() {
        // Test vector from another known SHA-256 hash
        let data = b"";
        let expected_hash: [u8; 32] = [
            0x6d, 0x03, 0x6d, 0x3a, 0x1e, 0xb0, 0x9f, 0x7c, 0xe9, 0xe6, 0x59, 0x15, 0xe6, 0x29, 0x40, 0x91,
            0xc2, 0x7f, 0x80, 0x8f, 0x9c, 0xd4, 0xe3, 0x29, 0xe4, 0x48, 0x84, 0x34, 0x65, 0x5e, 0x4f, 0x02,
        ];

        let hash = sha256(data);
        assert_eq!(hash, expected_hash);
    }
}
