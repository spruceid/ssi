use std::str::FromStr;

use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use serde::{Deserialize, Serialize};
use sha2::Digest;
use ssi_jwt::Claim;

use crate::{disclosure::Disclosure, DecodeError, SD_ALG_CLAIM_NAME};

/// Elements of the _sd_alg claim
#[non_exhaustive]
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum SdAlg {
    /// SHA-256 Algortim for hashing disclosures
    Sha256,
}

impl SdAlg {
    const SHA256_STR: &'static str = "sha-256";

    /// String encoding of _sd_alg field
    pub fn to_str(&self) -> &'static str {
        match self {
            SdAlg::Sha256 => Self::SHA256_STR,
        }
    }

    /// Hash the given disclosure.
    pub fn hash(&self, disclosure: &Disclosure) -> String {
        match self {
            Self::Sha256 => {
                let digest = sha2::Sha256::digest(disclosure.as_bytes());
                BASE64_URL_SAFE_NO_PAD.encode(digest)
            }
        }
    }
}

impl Claim for SdAlg {
    const JWT_CLAIM_NAME: &'static str = SD_ALG_CLAIM_NAME;
}

impl FromStr for SdAlg {
    type Err = DecodeError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        SdAlg::try_from(s)
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

impl Serialize for SdAlg {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.to_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for SdAlg {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_disclosure_hashing() {
        assert_eq!(
            SdAlg::Sha256.hash(
                Disclosure::new("WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0").unwrap()
            ),
            "uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY",
        );
    }
}
