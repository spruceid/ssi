use serde::{Deserialize, Serialize};
use ssi_core::uri::{URIParseErr, URI};

/// `StringOrURI` datatype defined in [RFC7519](https://datatracker.ietf.org/doc/html/rfc7519#section-2)
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq)]
#[serde(untagged)]
#[serde(try_from = "String")]
pub enum StringOrURI {
    String(String),
    URI(URI),
}

impl From<StringOrURI> for String {
    fn from(id: StringOrURI) -> Self {
        match id {
            StringOrURI::URI(uri) => uri.into(),
            StringOrURI::String(s) => s,
        }
    }
}

impl StringOrURI {
    pub fn as_str(&self) -> &str {
        match self {
            StringOrURI::URI(URI::String(string)) => string.as_str(),
            StringOrURI::String(string) => string.as_str(),
        }
    }
}

impl TryFrom<String> for StringOrURI {
    type Error = URIParseErr;

    fn try_from(string: String) -> Result<Self, Self::Error> {
        if string.contains(':') {
            let uri = URI::try_from(string)?;
            Ok(Self::URI(uri))
        } else {
            Ok(Self::String(string))
        }
    }
}
impl TryFrom<&str> for StringOrURI {
    type Error = URIParseErr;

    fn try_from(string: &str) -> Result<Self, Self::Error> {
        string.to_string().try_into()
    }
}

impl From<URI> for StringOrURI {
    fn from(uri: URI) -> Self {
        StringOrURI::URI(uri)
    }
}
