use std::{borrow::Cow, ops::Deref};

use serde::Serialize;

#[derive(Debug, Clone, Copy, thiserror::Error)]
#[error("invalid JSON pointer `{0}`")]
pub struct InvalidJsonPointer<T>(pub T);

/// JSON Pointer.
///
/// See: <https://datatracker.ietf.org/doc/html/rfc6901>
#[derive(Debug, Serialize)]
pub struct JsonPointer(str);

impl JsonPointer {
    pub fn new(s: &str) -> Result<&Self, InvalidJsonPointer<&str>> {
        if Self::validate(s) {
            Ok(unsafe { Self::new_unchecked(s) })
        } else {
            Err(InvalidJsonPointer(s))
        }
    }

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

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn split_first(&self) -> Option<(&ReferenceToken, &Self)> {
        if self.is_empty() {
            None
        } else {
            let after_sep = &self.0[1..];
            let (token, rest) = after_sep.split_once('/').unwrap_or((after_sep, ""));
            Some(unsafe {
                (
                    ReferenceToken::new_unchecked(token),
                    Self::new_unchecked(rest),
                )
            })
        }
    }

    pub fn iter(&self) -> JsonPointerIter {
        let mut tokens = self.0.split('/');
        tokens.next();
        JsonPointerIter(tokens)
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

impl Deref for JsonPointerBuf {
    type Target = JsonPointer;

    fn deref(&self) -> &Self::Target {
        unsafe { JsonPointer::new_unchecked(&self.0) }
    }
}

#[derive(Debug)]
#[repr(transparent)]
pub struct ReferenceToken(str);

impl ReferenceToken {
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
