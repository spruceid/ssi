use core::fmt;
use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
#[error("invalid prefix `{0}`")]
pub struct InvalidPrefix(String);

#[derive(Debug, thiserror::Error)]
pub enum PrefixError {
    #[error(transparent)]
    Invalid(InvalidPrefix),

    #[error("missing prefix")]
    Missing,
}

#[derive(Clone, Copy, Debug)]
pub enum Prefix {
    TZ1,
    TZ2,
    TZ3,
    KT1,
}

impl Prefix {
    pub fn from_address(address: &str) -> Result<Self, PrefixError> {
        match address.get(..3) {
            Some(prefix) => Self::from_str(prefix).map_err(PrefixError::Invalid),
            None => Err(PrefixError::Missing),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::TZ1 => "tz1",
            Self::TZ2 => "tz2",
            Self::TZ3 => "tz3",
            Self::KT1 => "KT1",
        }
    }
}

impl FromStr for Prefix {
    type Err = InvalidPrefix;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s {
            "tz1" => Prefix::TZ1,
            "tz2" => Prefix::TZ2,
            "tz3" => Prefix::TZ3,
            "KT1" => Prefix::KT1,
            s => return Err(InvalidPrefix(s.to_owned())),
        })
    }
}

impl fmt::Display for Prefix {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}
