use crate::error::Error;

#[cfg(any(feature = "sha2", feature = "ring"))]
pub fn sha256(data: &[u8]) -> Result<[u8; 32], Error> {
    #[cfg(feature = "sha2")]
    {
        use sha2::Digest;
        let mut hasher = sha2::Sha256::new();
        hasher.update(data);
        let hash = hasher.finalize().into();
        Ok(hash)
    }
    #[cfg(feature = "ring")]
    {
        use ring::digest;
        use std::convert::TryInto;
        let hash = digest::digest(&digest::SHA256, data).as_ref().try_into()?;
        Ok(hash)
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
