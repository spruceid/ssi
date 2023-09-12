use serde::{Deserialize, Serialize};
use std::str::FromStr;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(try_from = "String")]
#[serde(untagged)]
pub enum URI {
    String(String),
}

#[derive(thiserror::Error, Debug)]
pub enum URIParseErr {
    #[error("Invalid URI: {0}")]
    InvalidFormat(String),
}

impl From<URI> for String {
    fn from(uri: URI) -> String {
        let URI::String(string) = uri;
        string
    }
}

impl std::convert::TryFrom<String> for URI {
    type Error = URIParseErr;
    fn try_from(uri: String) -> Result<Self, Self::Error> {
        if uri.contains(':') {
            Ok(URI::String(uri))
        } else {
            Err(URIParseErr::InvalidFormat(uri))
        }
    }
}

impl URI {
    /// Return the URI as a string slice
    pub fn as_str(&self) -> &str {
        match self {
            URI::String(string) => string.as_str(),
        }
    }
}

impl FromStr for URI {
    type Err = URIParseErr;
    fn from_str(uri: &str) -> Result<Self, Self::Err> {
        URI::try_from(String::from(uri))
    }
}

impl std::fmt::Display for URI {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match self {
            Self::String(ref string) => write!(f, "{string}"),
        }
    }
}
