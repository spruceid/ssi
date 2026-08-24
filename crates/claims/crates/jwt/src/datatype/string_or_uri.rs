use std::str::FromStr;

use iref::{InvalidUri, Uri, UriBuf};
use serde::{Deserialize, Serialize};

/// `StringOrURI` datatype defined in [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519#section-2)
///
/// Any string is a valid value, except that a string containing a `:`
/// character MUST be a valid URI.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[serde(try_from = "String")]
pub struct StringOrURI(String);

impl Serialize for StringOrURI {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.0.serialize(serializer)
    }
}

impl StringOrURI {
    /// Creates a new `StringOrURI` value, failing if `string` contains a `:`
    /// character but is not a valid URI.
    pub fn new(string: impl Into<String>) -> Result<Self, InvalidUri<String>> {
        let string = string.into();

        if string.contains(':') {
            UriBuf::try_from(string).map(|uri| Self(uri.into_string()))
        } else {
            Ok(Self(string))
        }
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Checks if this value is a URI.
    pub fn is_uri(&self) -> bool {
        self.0.contains(':')
    }

    /// Returns this value as a URI, if it is one.
    pub fn as_uri(&self) -> Option<&Uri> {
        Uri::new(self.0.as_bytes()).ok()
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// Turns this value into a URI, if it is one.
    pub fn into_uri(self) -> Option<UriBuf> {
        UriBuf::try_from(self.0).ok()
    }
}

impl From<StringOrURI> for String {
    fn from(id: StringOrURI) -> Self {
        id.into_string()
    }
}

impl From<UriBuf> for StringOrURI {
    fn from(uri: UriBuf) -> Self {
        Self(uri.into_string())
    }
}

impl TryFrom<String> for StringOrURI {
    type Error = InvalidUri<String>;

    fn try_from(string: String) -> Result<Self, Self::Error> {
        Self::new(string)
    }
}

impl TryFrom<&str> for StringOrURI {
    type Error = InvalidUri<String>;

    fn try_from(string: &str) -> Result<Self, Self::Error> {
        Self::new(string)
    }
}

impl FromStr for StringOrURI {
    type Err = InvalidUri<String>;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s)
    }
}

#[cfg(test)]
mod tests {
    use super::{StringOrURI, UriBuf};

    #[test]
    fn accept_string() {
        let value = StringOrURI::new("foo").unwrap();
        assert_eq!(value.as_str(), "foo");
        assert!(!value.is_uri());
        assert!(value.as_uri().is_none());
        assert!(value.into_uri().is_none());
    }

    #[test]
    fn accept_uri() {
        let value = StringOrURI::new("http://example.org/#foo").unwrap();
        assert_eq!(value.as_str(), "http://example.org/#foo");
        assert!(value.is_uri());
        assert_eq!(value.as_uri().unwrap().as_str(), "http://example.org/#foo");
        assert_eq!(
            value.into_uri().unwrap().as_str(),
            "http://example.org/#foo"
        );
    }

    #[test]
    fn from_uri() {
        let uri = UriBuf::try_from("http://example.org/#foo".to_string()).unwrap();
        let value = StringOrURI::from(uri);
        assert_eq!(value.as_str(), "http://example.org/#foo");
        assert!(value.is_uri());
    }

    #[test]
    fn reject_invalid_uri() {
        assert!(StringOrURI::new(":bar").is_err());
    }

    #[test]
    fn deserialize_reject_invalid_uri() {
        assert!(serde_json::from_str::<StringOrURI>("\":bar\"").is_err());
    }

    #[test]
    fn serialize() {
        let value = StringOrURI::new("http://example.org/#foo").unwrap();
        assert_eq!(
            serde_json::to_string(&value).unwrap(),
            "\"http://example.org/#foo\""
        );
    }
}
