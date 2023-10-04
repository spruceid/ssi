use jose_b64::base64ct::{Base64UrlUnpadded, Encoding};
use sha2::Digest;

use crate::DecodeError;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SdAlg {
    Sha256,
}

impl SdAlg {
    const SHA256_STR: &'static str = "sha-256";
}

impl SdAlg {
    pub fn to_str(&self) -> &'static str {
        match self {
            SdAlg::Sha256 => Self::SHA256_STR,
        }
    }
}

impl TryFrom<&str> for SdAlg {
    type Error = DecodeError;

    fn try_from(value: &str) -> Result<Self, Self::Error> {
        Ok(match value {
            Self::SHA256_STR => SdAlg::Sha256,
            other => return Err(DecodeError::UnknownSdAlg(other.to_owned())),
        })
    }
}

impl From<SdAlg> for &'static str {
    fn from(value: SdAlg) -> Self {
        value.to_str()
    }
}

pub fn hash_encoded_disclosure(digest_algo: SdAlg, disclosure: &str) -> String {
    match digest_algo {
        SdAlg::Sha256 => {
            let digest = sha2::Sha256::digest(disclosure.as_bytes());
            Base64UrlUnpadded::encode_string(&digest)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disclosure_hashing() {
        assert_eq!(
            hash_encoded_disclosure(
                SdAlg::Sha256,
                "WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0"
            ),
            "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY",
        );
    }
}
