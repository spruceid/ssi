use serde_with::{DeserializeFromStr, SerializeDisplay};
use std::{
    fmt::{Display, Formatter, Result as FmtResult},
    str::FromStr,
};

#[derive(Clone, PartialEq, Debug, SerializeDisplay, DeserializeFromStr, Default)]
pub struct SemanticVersion;

impl Display for SemanticVersion {
    fn fmt(&self, f: &mut Formatter<'_>) -> FmtResult {
        write!(f, "0.2.0")
    }
}

#[derive(thiserror::Error, Debug)]
pub enum VersionError {
    #[error("Invalid version: expected 0.2.0, found {0}")]
    InvalidVersion(String),
}

impl FromStr for SemanticVersion {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "0.2.0" {
            Ok(Self)
        } else {
            Err(VersionError::InvalidVersion(s.to_string()))
        }
    }
}
