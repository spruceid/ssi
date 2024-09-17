use core::fmt;
use std::{
    borrow::{Borrow, Cow},
    ops::Deref,
    str::FromStr,
};

use serde::{Deserialize, Serialize};

use crate::BytesBuf;

#[macro_export]
macro_rules! json_pointer {
    ($value:literal) => {
        match $crate::JsonPointer::from_str_const($value) {
            Ok(p) => p,
            Err(_) => panic!("invalid JSON pointer"),
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
pub struct JsonPointer([u8]);

impl<'a> Default for &'a JsonPointer {
    fn default() -> Self {
        JsonPointer::ROOT
    }
}

impl JsonPointer {
    pub const ROOT: &'static Self = unsafe {
        // SAFETY: the empty string is a valid JSON pointer.
        JsonPointer::new_unchecked(&[])
    };

    /// Converts the given string into a JSON pointer.
    pub fn new<S: AsRef<[u8]>>(s: &S) -> Result<&Self, InvalidJsonPointer<&S>> {
        let bytes = s.as_ref();
        if Self::validate(bytes) {
            Ok(unsafe { Self::new_unchecked(bytes) })
        } else {
            Err(InvalidJsonPointer(s))
        }
    }

    pub const fn from_str_const(s: &str) -> Result<&Self, InvalidJsonPointer<&str>> {
        let bytes = s.as_bytes();
        if Self::validate(bytes) {
            Ok(unsafe { Self::new_unchecked(bytes) })
        } else {
            Err(InvalidJsonPointer(s))
        }
    }

    /// Converts the given string into a JSON pointer without validation.
    ///
    /// # Safety
    ///
    /// The input string *must* be a valid JSON pointer.
    pub const unsafe fn new_unchecked(s: &[u8]) -> &Self {
        std::mem::transmute(s)
    }

    pub const fn validate(bytes: &[u8]) -> bool {
        if std::str::from_utf8(bytes).is_err() {
            return false;
        };

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
        &self.0
    }

    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: a JSON pointer is an UTF-8 encoded string by definition.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn token_end(&self) -> Option<usize> {
        if self.is_empty() {
            None
        } else {
            let mut i = 1;

            while i < self.0.len() {
                if self.0[i] == b'/' {
                    break;
                }

                i += 1
            }

            Some(i)
        }
    }

    pub fn split_first(&self) -> Option<(&ReferenceToken, &Self)> {
        self.token_end().map(|i| unsafe {
            (
                ReferenceToken::new_unchecked(&self.0[1..i]),
                Self::new_unchecked(&self.0[i..]),
            )
        })
    }

    pub fn iter(&self) -> JsonPointerIter {
        let mut tokens = self.as_str().split('/');
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

/// JSON Pointer buffer.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6901>
#[derive(Debug, Clone, Serialize, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct JsonPointerBuf(Vec<u8>);

impl Default for JsonPointerBuf {
    fn default() -> Self {
        JsonPointer::ROOT.to_owned()
    }
}

impl JsonPointerBuf {
    /// Converts the given byte string into an owned JSON pointer.
    pub fn new<B: BytesBuf>(value: B) -> Result<Self, InvalidJsonPointer<B>> {
        if JsonPointer::validate(value.as_ref()) {
            Ok(Self(value.into()))
        } else {
            Err(InvalidJsonPointer(value))
        }
    }

    pub fn push(&mut self, token: &str) {
        self.0.push(b'/');
        for c in token.chars() {
            match c {
                '~' => {
                    self.0.push(b'~');
                    self.0.push(b'0');
                }
                '/' => {
                    self.0.push(b'~');
                    self.0.push(b'1');
                }
                _ => {
                    let i = self.0.len();
                    let len = c.len_utf8();
                    self.0.resize(i + len, 0);
                    c.encode_utf8(&mut self.0[i..]);
                }
            }
        }
    }

    pub fn push_index(&mut self, i: usize) {
        self.push(&i.to_string())
    }

    pub fn as_json_pointer(&self) -> &JsonPointer {
        unsafe {
            // SAFETY: the inner bytes are representing a JSON pointer by
            // construction.
            JsonPointer::new_unchecked(&self.0)
        }
    }
}

impl Deref for JsonPointerBuf {
    type Target = JsonPointer;

    fn deref(&self) -> &Self::Target {
        unsafe { JsonPointer::new_unchecked(&self.0) }
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
        Self::new(s.to_owned())
    }
}

impl TryFrom<String> for JsonPointerBuf {
    type Error = InvalidJsonPointer;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
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
            .parse()
            .map_err(serde::de::Error::custom)
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct ReferenceToken([u8]);

impl ReferenceToken {
    /// Converts the given string into a JSON pointer reference token without
    /// validation.
    ///
    /// # Safety
    ///
    /// The input string *must* be a valid JSON pointer reference token.
    pub const unsafe fn new_unchecked(s: &[u8]) -> &Self {
        std::mem::transmute(s)
    }

    pub fn is_escaped(&self) -> bool {
        self.0.contains(&b'~')
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: a reference token is an UTF-8 encoded string by
            // definition.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    pub fn to_decoded(&self) -> Cow<str> {
        if self.is_escaped() {
            Cow::Owned(self.decode())
        } else {
            Cow::Borrowed(self.as_str())
        }
    }

    pub fn decode(&self) -> String {
        let mut result = String::new();
        let mut chars = self.as_str().chars();
        while let Some(c) = chars.next() {
            let decoded_c = match c {
                '~' => match chars.next() {
                    Some('0') => '~',
                    Some('1') => '/',
                    _ => unreachable!(),
                },
                c => c,
            };

            result.push(decoded_c);
        }

        result
    }

    pub fn as_array_index(&self) -> Option<usize> {
        let mut chars = self.as_str().chars();
        let mut i = chars.next()?.to_digit(10)? as usize;
        if i == 0 {
            match chars.next() {
                Some(_) => None,
                None => Some(0),
            }
        } else {
            for c in chars {
                let d = c.to_digit(10)? as usize;
                i = i * 10 + d;
            }

            Some(i)
        }
    }
}

impl fmt::Display for ReferenceToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}
