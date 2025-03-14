use std::str::FromStr;

use iref::{Iri, UriBuf};
use serde::{Deserialize, Serialize};

/// `StringOrURI` datatype defined in [RFC7519].
///
/// A JSON string value, with the additional requirement that while arbitrary
/// string values MAY be used, any value containing a ":" character MUST be a
/// URI [RFC3986]. StringOrURI values are compared as case-sensitive strings
/// with no transformations or canonicalizations applied.
///
/// [RFC7519]: <https://datatracker.ietf.org/doc/html/rfc7519#section-2>
/// [RFC3986]: <https://datatracker.ietf.org/doc/html/rfc3986>
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct StringOrUri(String);

impl StringOrUri {
    fn validate(input: &str) -> bool {
        !input.contains(':') || Iri::validate(input.chars())
    }

    pub fn new(value: String) -> Result<Self, iref::InvalidUri<String>> {
        if Self::validate(&value) {
            Ok(Self(value))
        } else {
            Err(iref::InvalidUri(value))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl From<StringOrUri> for String {
    fn from(id: StringOrUri) -> Self {
        id.into_string()
    }
}

impl TryFrom<String> for StringOrUri {
    type Error = iref::InvalidUri<String>;

    fn try_from(string: String) -> Result<Self, Self::Error> {
        Self::new(string)
    }
}

impl TryFrom<&str> for StringOrUri {
    type Error = iref::InvalidUri<String>;

    fn try_from(string: &str) -> Result<Self, Self::Error> {
        string.to_string().try_into()
    }
}

impl From<UriBuf> for StringOrUri {
    fn from(uri: UriBuf) -> Self {
        Self(uri.into_string())
    }
}

impl FromStr for StringOrUri {
    type Err = iref::InvalidUri<String>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.try_into()
    }
}
