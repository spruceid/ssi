//! Cryptographic hash functions
//!
//! The [`sha256`] function requires feature either `sha2` or `ring` (not both).

use crate::error::Error;

/// SHA-256 hash
pub fn sha256(data: &[u8]) -> Result<[u8; 32], Error> {
    #[cfg(feature = "ring")]
    {
        // The "ring" feature takes precedence for the impl of sha256.
        use ring::digest;
        use std::convert::TryInto;
        let hash = digest::digest(&digest::SHA256, data).as_ref().try_into()?;
        return Ok(hash);
    }
    #[cfg(all(not(feature = "ring"), feature = "sha2"))]
    {
        // Only if "ring" is not enabled, but "sha2" is, does it use "sha2" for the sha256 impl.
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize().into();
        return Ok(hash);
    }
    #[cfg(all(not(feature = "ring"), not(feature = "sha2")))]
    {
        // If neither "ring" nor "sha2" are enabled, no sha256 impl is possible.
        let _ = data;
        compile_error!("The [`sha256`] function requires feature either `sha2` or `ring` but not both (and neither are currently enabled).");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha256_empty() {
        assert_eq!(
            sha256(&[]).unwrap(),
            [
                227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39,
                174, 65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85
            ]
        );
    }
}
