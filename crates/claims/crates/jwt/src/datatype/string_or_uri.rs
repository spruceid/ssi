use std::str::FromStr;

use iref::UriBuf;
use serde::{Deserialize, Serialize};

/// `StringOrURI` datatype defined in [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519#section-2)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(untagged)]
#[serde(try_from = "String")]
pub enum StringOrURI {
    String(String),
    URI(UriBuf),
}

impl StringOrURI {
    pub fn into_string(self) -> String {
        match self {
            Self::String(s) => s,
            Self::URI(s) => s.into_string(),
        }
    }
}

impl From<StringOrURI> for String {
    fn from(id: StringOrURI) -> Self {
        id.into_string()
    }
}

impl StringOrURI {
    pub fn as_str(&self) -> &str {
        match self {
            StringOrURI::URI(uri) => uri.as_str(),
            StringOrURI::String(string) => string.as_str(),
        }
    }
}

impl TryFrom<String> for StringOrURI {
    type Error = iref::InvalidUri<String>;

    fn try_from(string: String) -> Result<Self, Self::Error> {
        if string.contains(':') {
            UriBuf::try_from(string).map(Self::URI)
        } else {
            Ok(Self::String(string))
        }
    }
}

impl TryFrom<&str> for StringOrURI {
    type Error = iref::InvalidUri<String>;

    fn try_from(string: &str) -> Result<Self, Self::Error> {
        string.to_string().try_into()
    }
}

impl From<UriBuf> for StringOrURI {
    fn from(uri: UriBuf) -> Self {
        StringOrURI::URI(uri)
    }
}

impl FromStr for StringOrURI {
    type Err = iref::InvalidUri<String>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}
