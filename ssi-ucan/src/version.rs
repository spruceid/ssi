use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};

#[derive(
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Debug,
    SerializeDisplay,
    DeserializeFromStr,
    Default,
)]
pub struct SemanticVersion;

impl Display for SemanticVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "0.2.0")
    }
}

#[derive(thiserror::Error, Debug)]
pub enum VersionError {
    #[error("Invalid version: expected {0}, found {1}")]
    InvalidVersion(&'static str, String),
}

impl FromStr for SemanticVersion {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "0.2.0" {
            Ok(Self)
        } else {
            Err(VersionError::InvalidVersion("0.2.0", s.to_string()))
        }
    }
}

#[derive(
    Clone,
    PartialEq,
    Eq,
    Hash,
    PartialOrd,
    Ord,
    Debug,
    SerializeDisplay,
    DeserializeFromStr,
    Default,
)]
pub struct RevocationSemanticVersion;

impl Display for RevocationSemanticVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "1.0.0-rc1")
    }
}

impl FromStr for RevocationSemanticVersion {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "1.0.0-rc1" {
            Ok(Self)
        } else {
            Err(VersionError::InvalidVersion("1.0.0-rc1", s.to_string()))
        }
    }
}
