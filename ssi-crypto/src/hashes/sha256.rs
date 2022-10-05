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
}
