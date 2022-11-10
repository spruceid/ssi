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
    #[error("Invalid URI")]
    InvalidFormat,
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
            Err(URIParseErr::InvalidFormat)
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
            Self::String(ref string) => write!(f, "{}", string),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
#[serde(untagged)]
pub enum URIOrString {
    URI(URI),
    String(String),
}

impl From<URIOrString> for String {
    fn from(id: URIOrString) -> Self {
        match id {
            URIOrString::String(s) => s,
            URIOrString::URI(u) => u.into(),
        }
    }
}

impl From<String> for URIOrString {
    fn from(id: String) -> Self {
        if let Ok(uri) = URI::try_from(id.clone()) {
            Self::URI(uri)
        } else {
            URIOrString::String(id)
        }
    }
}

impl From<&str> for URIOrString {
    fn from(id: &str) -> Self {
        id.to_string().into()
    }
}

impl FromStr for URIOrString {
    type Err = ();

    fn from_str(id: &str) -> Result<Self, Self::Err> {
        Ok(Self::from(id.to_string()))
    }
}
