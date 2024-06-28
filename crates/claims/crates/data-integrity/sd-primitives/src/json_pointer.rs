use core::fmt;
use std::{borrow::Cow, ops::Deref, str::FromStr};

use serde::Serialize;

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid JSON pointer `{0}`")]
pub struct InvalidJsonPointer<T = String>(pub T);

/// JSON Pointer.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6901>
#[derive(Debug, Serialize)]
pub struct JsonPointer(str);

impl JsonPointer {
    /// Converts the given string into a JSON pointer.
    pub fn new(s: &str) -> Result<&Self, InvalidJsonPointer<&str>> {
        if Self::validate(s) {
            Ok(unsafe { Self::new_unchecked(s) })
        } else {
            Err(InvalidJsonPointer(s))
        }
    }

    /// Converts the given string into a JSON pointer without validation.
    ///
    /// # Safety
    ///
    /// The input string *must* be a valid JSON pointer.
    pub unsafe fn new_unchecked(s: &str) -> &Self {
        std::mem::transmute(s)
    }

    pub fn validate(str: &str) -> bool {
        let mut chars = str.chars();
        while let Some(c) = chars.next() {
            if c == '~' && !matches!(chars.next(), Some('0' | '1')) {
                return false;
            }
        }

        true
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    fn token_end(&self) -> Option<usize> {
        if self.is_empty() {
            None
        } else {
            let mut i = 1;

            let bytes = self.0.as_bytes();
            while i < bytes.len() {
                if bytes[i] == b'/' {
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
        let mut tokens = self.0.split('/');
        tokens.next();
        JsonPointerIter(tokens)
    }
}

impl fmt::Display for JsonPointer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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
#[derive(Debug, Clone, Serialize)]
pub struct JsonPointerBuf(String);

impl JsonPointerBuf {
    /// Converts the given string into an owned JSON pointer.
    pub fn new(value: String) -> Result<Self, InvalidJsonPointer> {
        if JsonPointer::validate(&value) {
            Ok(Self(value))
        } else {
            Err(InvalidJsonPointer(value))
        }
    }

    /// Converts the given byte string into an owned JSON pointer.
    pub fn from_bytes(value: Vec<u8>) -> Result<Self, InvalidJsonPointer<Vec<u8>>> {
        match String::from_utf8(value) {
            Ok(value) => {
                if JsonPointer::validate(&value) {
                    Ok(Self(value))
                } else {
                    Err(InvalidJsonPointer(value.into_bytes()))
                }
            }
            Err(err) => Err(InvalidJsonPointer(err.into_bytes())),
        }
    }
}

impl Deref for JsonPointerBuf {
    type Target = JsonPointer;

    fn deref(&self) -> &Self::Target {
        unsafe { JsonPointer::new_unchecked(&self.0) }
    }
}

impl FromStr for JsonPointerBuf {
    type Err = InvalidJsonPointer;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl fmt::Display for JsonPointerBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
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
    pub unsafe fn new_unchecked(s: &str) -> &Self {
        std::mem::transmute(s)
    }

    pub fn is_escaped(&self) -> bool {
        self.0.contains('~')
    }

    pub fn to_str(&self) -> Cow<str> {
        if self.is_escaped() {
            Cow::Owned(self.decode())
        } else {
            Cow::Borrowed(&self.0)
        }
    }

    pub fn decode(&self) -> String {
        let mut result = String::new();
        let mut chars = self.0.chars();
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
        let mut chars = self.0.chars();
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
        self.0.fmt(f)
    }
}
