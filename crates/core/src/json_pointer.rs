use core::{fmt, ops::Deref, str::FromStr};
use std::borrow::{Borrow, Cow};

use serde::{Deserialize, Serialize};

use crate::BytesBuf;

#[macro_export]
macro_rules! json_pointer {
    ($value:literal) => {
        const {
            match $crate::JsonPointer::from_str_const($value) {
                Ok(p) => p,
                Err(_) => panic!("invalid JSON pointer"),
            }
        }
    };
}

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid JSON pointer `{0}`")]
pub struct InvalidJsonPointer<T = String>(pub T);

/// JSON Pointer.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6901>
#[derive(Debug, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct JsonPointer(str);

impl<'a> Default for &'a JsonPointer {
    fn default() -> Self {
        JsonPointer::ROOT
    }
}

impl JsonPointer {
    pub const ROOT: &'static Self = json_pointer!("");

    /// Converts the given string into a JSON pointer.
    pub fn new<S>(s: &S) -> Result<&Self, InvalidJsonPointer<&S>>
    where
        S: AsRef<[u8]> + ?Sized,
    {
        core::str::from_utf8(s.as_ref())
            .ok()
            .and_then(|s| Self::from_str_const(s).ok())
            .ok_or(InvalidJsonPointer(s))
    }

    pub const fn from_str_const(s: &str) -> Result<&Self, InvalidJsonPointer<&str>> {
        if Self::validate_str(s) {
            Ok(unsafe { Self::new_unchecked_str(s) })
        } else {
            Err(InvalidJsonPointer(s))
        }
    }

    /// Converts the given string into a JSON pointer without validation.
    ///
    /// # Safety
    ///
    /// The input string *must* be a valid JSON pointer.
    pub const unsafe fn new_unchecked_str(s: &str) -> &Self {
        std::mem::transmute(s)
    }

    /// Converts the given string into a JSON pointer without validation.
    ///
    /// # Safety
    ///
    /// The input string *must* be a valid JSON pointer.
    pub const unsafe fn new_unchecked(s: &[u8]) -> &Self {
        Self::new_unchecked_str(core::str::from_utf8_unchecked(s))
    }

    /// Confirms the validity of a string such that it may be safely used for
    /// [`Self::new_unchecked`].
    pub const fn validate_bytes(s: &[u8]) -> bool {
        match core::str::from_utf8(s) {
            Ok(s) => Self::validate_str(s),
            Err(_) => false,
        }
    }

    /// Confirms the validity of a string such that it may be safely used for
    /// [`Self::new_unchecked_str`].
    pub const fn validate_str(s: &str) -> bool {
        let bytes = s.as_bytes();

        if !matches!(bytes, [] | [b'/', ..]) {
            return false;
        }

        let mut i = 0;
        while i < bytes.len() {
            // Escape char.
            if bytes[i] == b'~' {
                i += 1;
                if i >= bytes.len() || !matches!(bytes[i], b'0' | b'1') {
                    return false;
                }
            }

            i += 1
        }

        true
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn split_first(&self) -> Option<(&ReferenceToken, &Self)> {
        self.0.strip_prefix("/").map(|s| {
            let (left, right) = s.find("/").map(|idx| s.split_at(idx)).unwrap_or((s, ""));
            // Safety: the token is guaranteed not to include a '/', and remaining shall be either
            // empty or a valid pointer starting with '/'.
            let token = unsafe { ReferenceToken::new_unchecked(left) };
            let remaining = unsafe { Self::new_unchecked_str(right) };
            (token, remaining)
        })
    }

    pub fn iter(&self) -> JsonPointerIter {
        let mut tokens = self.0.split('/');
        tokens.next();
        JsonPointerIter(tokens)
    }
}

impl ToOwned for JsonPointer {
    type Owned = JsonPointerBuf;

    fn to_owned(&self) -> Self::Owned {
        JsonPointerBuf(self.0.to_owned())
    }
}

impl AsRef<JsonPointer> for JsonPointer {
    fn as_ref(&self) -> &JsonPointer {
        self
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl<'a> IntoIterator for &'a JsonPointer {
    type Item = &'a ReferenceToken;
    type IntoIter = JsonPointerIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct JsonPointerIter<'a>(std::str::Split<'a, char>);

impl<'a> Iterator for JsonPointerIter<'a> {
    type Item = &'a ReferenceToken;

    fn next(&mut self) -> Option<Self::Item> {
        self.0.next().map(|s| unsafe { std::mem::transmute(s) })
    }
}

impl<'de> Deserialize<'de> for &'de JsonPointer {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let s: &str = <&str as Deserialize>::deserialize(deserializer)?;
        JsonPointer::new(s).map_err(serde::de::Error::custom)
    }
}

/// JSON Pointer buffer.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6901>
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonPointerBuf(String);

impl Default for JsonPointerBuf {
    fn default() -> Self {
        JsonPointer::ROOT.to_owned()
    }
}

impl JsonPointerBuf {
    /// Converts the given byte string into an owned JSON pointer.
    pub fn new<B: BytesBuf>(value: B) -> Result<Self, InvalidJsonPointer<B>> {
        if JsonPointer::validate_bytes(value.as_ref()) {
            let v: Vec<u8> = value.into();
            // SAFETY: we've just ensured the contents of the BytesBuf is a valid UTF-8 string and
            // JsonPointer.
            Ok(Self(unsafe { String::from_utf8_unchecked(v) }))
        } else {
            Err(InvalidJsonPointer(value))
        }
    }

    pub fn push(&mut self, token: &str) {
        self.0.reserve(1 + token.len());
        self.0.push('/');
        for c in token.chars() {
            match c {
                '~' => self.0.push_str("~0"),
                '/' => self.0.push_str("~1"),
                _ => self.0.push(c),
            }
        }
    }

    pub fn push_index(&mut self, i: usize) {
        use core::fmt::Write;
        write!(self.0, "/{i}").unwrap()
    }

    pub fn as_json_pointer(&self) -> &JsonPointer {
        unsafe {
            // SAFETY: the inner bytes are representing a JSON pointer by
            // construction.
            JsonPointer::new_unchecked_str(&self.0)
        }
    }
}

impl Deref for JsonPointerBuf {
    type Target = JsonPointer;

    fn deref(&self) -> &Self::Target {
        self.as_json_pointer()
    }
}

impl Borrow<JsonPointer> for JsonPointerBuf {
    fn borrow(&self) -> &JsonPointer {
        self.as_json_pointer()
    }
}

impl AsRef<JsonPointer> for JsonPointerBuf {
    fn as_ref(&self) -> &JsonPointer {
        self.as_json_pointer()
    }
}

impl FromStr for JsonPointerBuf {
    type Err = InvalidJsonPointer;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        s.to_owned().try_into()
    }
}

impl TryFrom<String> for JsonPointerBuf {
    type Error = InvalidJsonPointer;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        if JsonPointer::validate_str(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidJsonPointer(value))
        }
    }
}

impl fmt::Display for JsonPointerBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl<'de> Deserialize<'de> for JsonPointerBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .try_into()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct ReferenceToken(str);

impl ReferenceToken {
    /// Converts the given string into a JSON pointer reference token without
    /// validation.
    ///
    /// # Safety
    ///
    /// The input string *must* be a valid JSON pointer reference token.
    pub const unsafe fn new_unchecked(s: &str) -> &Self {
        std::mem::transmute(s)
    }

    pub fn is_escaped(&self) -> bool {
        self.0.contains("~")
    }

    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_bytes()
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn to_decoded(&self) -> Cow<str> {
        if self.is_escaped() {
            Cow::Owned(self.decode())
        } else {
            Cow::Borrowed(self.as_str())
        }
    }

    pub fn decode(&self) -> String {
        let mut buf = String::with_capacity(self.0.len());
        let mut chars = self.0.chars();
        buf.extend(core::iter::from_fn(|| {
            Some(match chars.next()? {
                '~' => match chars.next() {
                    Some('0') => '~',
                    Some('1') => '/',
                    _ => unreachable!(),
                },
                c => c,
            })
        }));
        buf
    }

    pub fn as_array_index(&self) -> Option<usize> {
        // Like usize::from_str, but don't allow leading '+' or '0'.
        match self.0.as_bytes() {
            [c @ b'0'..=b'9'] => Some((c - b'0') as usize),
            [b'1'..=b'9', ..] => self.0.parse().ok(),
            _ => None,
        }
    }
}

impl fmt::Display for ReferenceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_serde_borrow() {
        let s = String::from("\"/foo/b~1ar\"");
        let p: JsonPointerBuf = serde_json::from_str(&s).unwrap();
        let jp: &JsonPointer = serde_json::from_str(&s).unwrap();
        assert_eq!(p.0, jp.0);

        serde_json::from_str::<&JsonPointer>("\"invalid\"").unwrap_err();
    }
}
