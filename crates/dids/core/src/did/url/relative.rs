use core::fmt;
use std::ops::Deref;

use serde::{Deserialize, Serialize};

use crate::{DIDURLBuf, DID};

use super::{Fragment, Query, Unexpected};

/// Error raised when a conversion to a relative DID URL fails.
#[derive(Debug, thiserror::Error)]
#[error("invalid relative DID URL `{0}`: {1}")]
pub struct InvalidRelativeDIDURL<T>(pub T, pub Unexpected);

impl<T> InvalidRelativeDIDURL<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> InvalidRelativeDIDURL<U> {
        InvalidRelativeDIDURL(f(self.0), self.1)
    }
}

/// Relative DID URL.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RelativeDIDURL([u8]);

impl RelativeDIDURL {
    /// Converts the input `data` to a relative DID URL.
    ///
    /// Fails if the data is not a relative DID URL according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-url-syntax).
    pub fn new(data: &[u8]) -> Result<&Self, InvalidRelativeDIDURL<&[u8]>> {
        match Self::validate(data) {
            Ok(()) => Ok(unsafe {
                // SAFETY: DID is a transparent wrapper over `[u8]`,
                //         and we just checked that `data` is a relative DID
                //         URL.
                std::mem::transmute::<&[u8], &Self>(data)
            }),
            Err(e) => Err(InvalidRelativeDIDURL(data, e)),
        }
    }

    /// Converts the input `data` to a relative DID URL without validation.
    ///
    /// # Safety
    ///
    /// The input `data` must be a relative DID URL according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-url-syntax).
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        // SAFETY: DID URL is a transparent wrapper over `[u8]`,
        //         but we didn't check if it is actually a relative DID URL.
        std::mem::transmute::<&[u8], &Self>(data)
    }

    /// Returns the relative DID URL as a string.
    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: a relative DID URL is a valid ASCII string.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    /// Returns the relative DID URL as a byte string.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn query_delimiter_offset(&self) -> usize {
        self.0
            .iter()
            .position(|&b| matches!(b, b'?' | b'#'))
            .unwrap_or(self.0.len())
    }

    fn fragment_delimiter_offset(&self) -> usize {
        self.0
            .iter()
            .position(|&b| matches!(b, b'#'))
            .unwrap_or(self.0.len())
    }

    fn fragment_delimiter_offset_from(&self, offset: usize) -> usize {
        self.0[offset..]
            .iter()
            .position(|&b| matches!(b, b'#'))
            .map(|o| o + offset)
            .unwrap_or(self.0.len())
    }

    pub fn path(&self) -> &RelativePath {
        let end = self.query_delimiter_offset();
        unsafe { RelativePath::new_unchecked(&self.0[..end]) }
    }

    pub fn query(&self) -> Option<&Query> {
        let start = self.query_delimiter_offset();
        let end = self.fragment_delimiter_offset_from(start);
        if start == end {
            None
        } else {
            Some(unsafe { Query::new_unchecked(&self.0[(start + 1)..end]) })
        }
    }

    pub fn fragment(&self) -> Option<&Fragment> {
        let start = self.fragment_delimiter_offset();
        let end = self.fragment_delimiter_offset_from(start);
        if start == end {
            None
        } else {
            Some(unsafe { Fragment::new_unchecked(&self.0[(start + 1)..end]) })
        }
    }

    // /// Convert a DID URL to a absolute DID URL, given a DID as base URI,
    // /// according to [DID Core - Relative DID URLs](https://w3c.github.io/did-core/#relative-did-urls).
    // pub fn to_absolute(&self, base_did: &DID) -> DIDURLBuf {
    //     // // TODO: support [Reference Resolution](https://tools.ietf.org/html/rfc3986#section-5) more
    //     // // generally, e.g. when base is not a DID
    //     // DIDURL {
    //     //     did: base_did.to_string(),
    //     //     path_abempty: self.path.to_string(),
    //     //     query: self.query.as_ref().cloned(),
    //     //     fragment: self.fragment.as_ref().cloned(),
    //     // }
    // 	todo!()
    // }

    pub fn resolve(&self, base_id: &DID) -> DIDURLBuf {
        let mut bytes = base_id.as_bytes().to_vec();
        bytes.extend_from_slice(&self.0);
        unsafe { DIDURLBuf::new_unchecked(bytes) }
    }
}

/// DID URL path.
#[repr(transparent)]
pub struct RelativePath([u8]);

impl RelativePath {
    /// Creates a relative DID URL path from the given data without validation.
    ///
    /// # Safety
    ///
    /// The input data must be a valid relative DID URL path.
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        std::mem::transmute(data)
    }

    /// Returns the relative DID URL path as a string.
    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: a relative DID URL path is a valid ASCII string.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    /// Returns the relative DID URL path as a byte string.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RelativeDIDURLBuf(Vec<u8>);

impl RelativeDIDURLBuf {
    pub fn new(data: Vec<u8>) -> Result<Self, InvalidRelativeDIDURL<Vec<u8>>> {
        match RelativeDIDURL::validate(&data) {
            Ok(()) => Ok(Self(data)),
            Err(e) => Err(InvalidRelativeDIDURL(data, e)),
        }
    }

    pub fn as_relative_did_url(&self) -> &RelativeDIDURL {
        unsafe { RelativeDIDURL::new_unchecked(&self.0) }
    }
}

impl TryFrom<String> for RelativeDIDURLBuf {
    type Error = InvalidRelativeDIDURL<String>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        RelativeDIDURLBuf::new(value.into_bytes()).map_err(|e| {
            e.map(|bytes| unsafe {
                // SAFETY: `bytes` comes from the `value` string, which is UTF-8
                //         encoded by definition.
                String::from_utf8_unchecked(bytes)
            })
        })
    }
}

impl Deref for RelativeDIDURLBuf {
    type Target = RelativeDIDURL;

    fn deref(&self) -> &Self::Target {
        self.as_relative_did_url()
    }
}

impl fmt::Display for RelativeDIDURLBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for RelativeDIDURLBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl Serialize for RelativeDIDURLBuf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for RelativeDIDURLBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = RelativeDIDURLBuf;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a DID URL")
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.try_into().map_err(|e| E::custom(e))
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(v.to_string())
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

impl RelativeDIDURL {
    /// Validates a DID URL string.
    fn validate(data: &[u8]) -> Result<(), Unexpected> {
        let mut bytes = data.iter().copied();
        match Self::validate_from(0, &mut bytes)? {
            (_, None) => Ok(()),
            (i, Some(c)) => Err(Unexpected(i, Some(c))),
        }
    }

    /// Validates a DID URL string.
    fn validate_from(
        mut i: usize,
        bytes: &mut impl Iterator<Item = u8>,
    ) -> Result<(usize, Option<u8>), Unexpected> {
        enum State {
            Path,
            PathSegment,
            PathSegmentNc,
            PathSegmentNzNc,
            Query,
            Fragment,
            Pct1(Part),
            Pct2(Part),
        }

        enum Part {
            PathSegment,
            PathSegmentNc,
            Query,
            Fragment,
        }

        impl Part {
            pub fn state(&self) -> State {
                match self {
                    Self::PathSegment => State::PathSegment,
                    Self::PathSegmentNc => State::PathSegmentNc,
                    Self::Query => State::Query,
                    Self::Fragment => State::Fragment,
                }
            }
        }

        fn is_unreserved(b: u8) -> bool {
            b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~')
        }

        fn is_sub_delims(b: u8) -> bool {
            matches!(
                b,
                b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'='
            )
        }

        fn is_pchar(b: u8) -> bool {
            is_unreserved(b) || is_sub_delims(b) || matches!(b, b':' | b'@')
        }

        let mut state = State::Path;

        loop {
            match state {
                State::Path => match bytes.next() {
                    Some(b'/') => state = State::PathSegmentNzNc, // absolute path
                    Some(b'?') => state = State::Query,           // path-empty
                    Some(b'#') => state = State::Fragment,        // path-empty
                    Some(b'%') => state = State::Pct1(Part::PathSegmentNc), // path-noscheme
                    Some(b':') => break Ok((i, Some(b':'))),
                    Some(c) if is_pchar(c) => (), // path-noscheme
                    c => break Ok((i, c)),        // path-empty
                },
                State::PathSegment => match bytes.next() {
                    Some(b'/') => (), // next segment.
                    Some(b'?') => state = State::Query,
                    Some(b'#') => state = State::Fragment,
                    Some(b'%') => state = State::Pct1(Part::PathSegment),
                    Some(c) if is_pchar(c) => (),
                    c => break Ok((i, c)),
                },
                State::PathSegmentNc => match bytes.next() {
                    Some(b'/') => state = State::PathSegment,
                    Some(b'?') => state = State::Query,
                    Some(b'#') => state = State::Fragment,
                    Some(b'%') => state = State::Pct1(Part::PathSegmentNc),
                    Some(b':') => break Ok((i, Some(b':'))),
                    Some(c) if is_pchar(c) => (),
                    c => break Ok((i, c)),
                },
                State::PathSegmentNzNc => match bytes.next() {
                    Some(b'?') => state = State::Query,
                    Some(b'#') => state = State::Fragment,
                    Some(b'%') => state = State::Pct1(Part::PathSegmentNc),
                    Some(b':') => break Ok((i, Some(b':'))),
                    Some(c) if is_pchar(c) => state = State::PathSegmentNc,
                    c => break Ok((i, c)),
                },
                State::Query => match bytes.next() {
                    Some(b'#') => state = State::Fragment,
                    Some(b'%') => state = State::Pct1(Part::Query),
                    Some(c) if is_pchar(c) || matches!(c, b'/' | b'?') => (),
                    c => break Ok((i, c)),
                },
                State::Fragment => match bytes.next() {
                    Some(b'%') => state = State::Pct1(Part::Fragment),
                    Some(c) if is_pchar(c) || matches!(c, b'/' | b'?' | b'#') => (),
                    c => break Ok((i, c)),
                },
                State::Pct1(q) => match bytes.next() {
                    Some(c) if c.is_ascii_hexdigit() => state = State::Pct2(q),
                    c => break Err(Unexpected(i, c)),
                },
                State::Pct2(q) => match bytes.next() {
                    Some(c) if c.is_ascii_hexdigit() => state = q.state(),
                    c => break Err(Unexpected(i, c)),
                },
            }

            i += 1
        }
    }
}
