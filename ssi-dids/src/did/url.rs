use core::fmt;
use std::{borrow::Borrow, ops::Deref, usize};

use crate::DIDBuf;

use super::{Unexpected, DID};

mod primary;
mod reference;
mod relative;

pub use primary::*;
pub use reference::*;
pub use relative::*;
use serde::{Deserialize, Serialize};

/// Error raised when a conversion to a DID URL fails.
#[derive(Debug, thiserror::Error)]
#[error("invalid DID URL `{0}`: {1}")]
pub struct InvalidDIDURL<T>(pub T, pub Unexpected);

impl<T> InvalidDIDURL<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> InvalidDIDURL<U> {
        InvalidDIDURL(f(self.0), self.1)
    }
}

/// DID URL.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DIDURL([u8]);

impl DIDURL {
    /// Converts the input `data` to a DID URL.
    ///
    /// Fails if the data is not a DID URL according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-url-syntax).
    pub fn new(data: &[u8]) -> Result<&Self, InvalidDIDURL<&[u8]>> {
        match Self::validate(data) {
            Ok(()) => Ok(unsafe {
                // SAFETY: DID is a transparent wrapper over `[u8]`,
                //         and we just checked that `data` is a DID URL.
                std::mem::transmute(data)
            }),
            Err(e) => Err(InvalidDIDURL(data, e)),
        }
    }

    /// Converts the input `data` to a DID URL without validation.
    ///
    /// # Safety
    ///
    /// The input `data` must be a DID URL according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-url-syntax).
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        // SAFETY: DID URL is a transparent wrapper over `[u8]`,
        //         but we didn't check if it is actually a DID URL.
        std::mem::transmute(data)
    }

    /// Returns the DID URL as a string.
    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: a DID URL is a valid ASCII string.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    /// Returns the DID URL as a byte string.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    fn path_offset(&self) -> usize {
        self.0
            .iter()
            .position(|&b| matches!(b, b'/' | b'?' | b'#'))
            .unwrap_or(self.0.len())
    }

    fn query_delimiter_offset(&self) -> usize {
        self.0
            .iter()
            .position(|&b| matches!(b, b'?' | b'#'))
            .unwrap_or(self.0.len())
    }

    fn query_delimiter_offset_from(&self, offset: usize) -> usize {
        self.0[offset..]
            .iter()
            .position(|&b| matches!(b, b'?' | b'#'))
            .map(|o| o + offset)
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

    pub fn did(&self) -> &DID {
        unsafe { DID::new_unchecked(&self.0[..self.path_offset()]) }
    }

    pub fn path(&self) -> &Path {
        let start = self.path_offset();
        let end = self.query_delimiter_offset_from(start);
        unsafe { Path::new_unchecked(&self.0[start..end]) }
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
        let end = self.0.len();
        if start == end {
            None
        } else {
            Some(unsafe { Fragment::new_unchecked(&self.0[(start + 1)..end]) })
        }
    }

    /// Convert a DID URL to a relative DID URL, given a base DID.
    pub fn to_relative(&self, base_did: &DID) -> Option<&RelativeDIDURL> {
        if self.did() != base_did {
            None
        } else {
            let offset = self.path_offset();
            Some(unsafe { RelativeDIDURL::new_unchecked(&self.0[offset..]) })
        }
    }

    /// Convert to a fragment-less DID URL and return the removed fragment.
    ///
    /// The DID URL can be reconstructed using [PrimaryDIDURL::with_fragment].
    pub fn without_fragment(&self) -> (&PrimaryDIDURL, Option<&Fragment>) {
        let fragment_start = self.fragment_delimiter_offset();
        let fragment_end = self.0.len();

        let fragment = if fragment_start == fragment_end {
            None
        } else {
            Some(unsafe { Fragment::new_unchecked(&self.0[(fragment_start + 1)..fragment_end]) })
        };

        unsafe {
            (
                PrimaryDIDURL::new_unchecked(&self.0[..fragment_start]),
                fragment,
            )
        }
    }
}

impl PartialEq<DIDURLBuf> for DIDURL {
    fn eq(&self, other: &DIDURLBuf) -> bool {
        self == other.as_did_url()
    }
}

impl PartialEq<DID> for DIDURL {
    fn eq(&self, other: &DID) -> bool {
        self.path().is_empty()
            && self.query().is_none()
            && self.fragment().is_none()
            && self.did() == other
    }
}

impl PartialEq<DIDBuf> for DIDURL {
    fn eq(&self, other: &DIDBuf) -> bool {
        self == other.as_did()
    }
}

impl ToOwned for DIDURL {
    type Owned = DIDURLBuf;

    fn to_owned(&self) -> Self::Owned {
        unsafe { DIDURLBuf::new_unchecked(self.0.to_vec()) }
    }
}

impl Deref for DIDURL {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

/// DID URL path.
#[repr(transparent)]
pub struct Path([u8]);

impl Path {
    /// Creates a new DID URL path from the given data without validation.
    ///
    /// # Safety
    ///
    /// The input data must be a valid DID URL path.
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        std::mem::transmute(data)
    }

    /// Returns the DID URL as a string.
    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: a DID URL is a valid ASCII string.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    /// Returns the DID URL as a byte string.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Path {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

/// DID URL query.
#[repr(transparent)]
pub struct Query([u8]);

impl Query {
    /// Creates a new DID URL query from the given data without validation.
    ///
    /// # Safety
    ///
    /// The input data must be a valid DID URL query.
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        std::mem::transmute(data)
    }

    /// Returns the DID URL as a string.
    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: a DID URL is a valid ASCII string.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    /// Returns the DID URL as a byte string.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Query {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

#[repr(transparent)]
pub struct Fragment([u8]);

impl Fragment {
    /// Creates a new DID URL fragment from the given data without validation.
    ///
    /// # Safety
    ///
    /// The input data must be a valid DID URL fragment.
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        std::mem::transmute(data)
    }

    /// Returns the DID URL as a string.
    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: a DID URL is a valid ASCII string.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    /// Returns the DID URL as a byte string.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl Deref for Fragment {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl ToOwned for Fragment {
    type Owned = FragmentBuf;

    fn to_owned(&self) -> Self::Owned {
        unsafe { FragmentBuf::new_unchecked(self.0.to_vec()) }
    }
}

pub struct FragmentBuf(Vec<u8>);

impl FragmentBuf {
    /// Creates a new DID URL fragment from the given data without validation.
    ///
    /// # Safety
    ///
    /// The input data must be a valid DID URL fragment.
    pub unsafe fn new_unchecked(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_fragment(&self) -> &Fragment {
        unsafe { Fragment::new_unchecked(&self.0) }
    }
}

impl Deref for FragmentBuf {
    type Target = Fragment;

    fn deref(&self) -> &Self::Target {
        self.as_fragment()
    }
}

impl Borrow<Fragment> for FragmentBuf {
    fn borrow(&self) -> &Fragment {
        self.as_fragment()
    }
}

#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DIDURLBuf(Vec<u8>);

impl DIDURLBuf {
    pub fn new(data: Vec<u8>) -> Result<Self, InvalidDIDURL<Vec<u8>>> {
        match DIDURL::validate(&data) {
            Ok(()) => Ok(Self(data)),
            Err(e) => Err(InvalidDIDURL(data, e)),
        }
    }

    /// Creates a new DID URL from the given data without validation.
    ///
    /// # Safety
    ///
    /// The input data must be a valid DID URL.
    pub unsafe fn new_unchecked(data: Vec<u8>) -> Self {
        Self(data)
    }

    pub fn as_did_url(&self) -> &DIDURL {
        unsafe { DIDURL::new_unchecked(&self.0) }
    }

    /// Convert to a fragment-less DID URL and return the removed fragment.
    ///
    /// The DID URL can be reconstructed using [PrimaryDIDURL::with_fragment].
    pub fn remove_fragment(self) -> (PrimaryDIDURLBuf, Option<String>) {
        // (
        //     PrimaryDIDURL {
        //         did: self.did,
        //         path: if !self.path_abempty.is_empty() {
        //             Some(self.path_abempty)
        //         } else {
        //             None
        //         },
        //         query: self.query,
        //     },
        //     self.fragment,
        // )
        todo!()
    }
}

impl TryFrom<String> for DIDURLBuf {
    type Error = InvalidDIDURL<String>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        DIDURLBuf::new(value.into_bytes()).map_err(|e| {
            e.map(|bytes| unsafe {
                // SAFETY: `bytes` comes from the `value` string, which is UTF-8
                //         encoded by definition.
                String::from_utf8_unchecked(bytes)
            })
        })
    }
}

impl Deref for DIDURLBuf {
    type Target = DIDURL;

    fn deref(&self) -> &Self::Target {
        self.as_did_url()
    }
}

impl Borrow<DIDURL> for DIDURLBuf {
    fn borrow(&self) -> &DIDURL {
        self.as_did_url()
    }
}

impl fmt::Display for DIDURLBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for DIDURLBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl PartialEq<str> for DIDURLBuf {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<&'a str> for DIDURLBuf {
    fn eq(&self, other: &&'a str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<DIDURL> for DIDURLBuf {
    fn eq(&self, other: &DIDURL) -> bool {
        self.as_did_url() == other
    }
}

impl<'a> PartialEq<&'a DIDURL> for DIDURLBuf {
    fn eq(&self, other: &&'a DIDURL) -> bool {
        self.as_did_url() == *other
    }
}

impl PartialEq<DID> for DIDURLBuf {
    fn eq(&self, other: &DID) -> bool {
        self.as_did_url() == other
    }
}

impl<'a> PartialEq<&'a DID> for DIDURLBuf {
    fn eq(&self, other: &&'a DID) -> bool {
        self.as_did_url() == *other
    }
}

impl PartialEq<DIDBuf> for DIDURLBuf {
    fn eq(&self, other: &DIDBuf) -> bool {
        self.as_did_url() == other
    }
}

impl Serialize for DIDURLBuf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DIDURLBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = DIDURLBuf;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a relative DID URL")
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

impl DIDURL {
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
        i: usize,
        bytes: &mut impl Iterator<Item = u8>,
    ) -> Result<(usize, Option<u8>), Unexpected> {
        match DID::validate_from(i, bytes)? {
            (i, None) => Ok((i, None)),
            (mut i, Some(c)) => {
                enum State {
                    PathSegment,
                    Query,
                    Fragment,
                    Pct1(Part),
                    Pct2(Part),
                }

                enum Part {
                    PathSegment,
                    Query,
                    Fragment,
                }

                impl Part {
                    pub fn state(&self) -> State {
                        match self {
                            Self::PathSegment => State::PathSegment,
                            Self::Query => State::Query,
                            Self::Fragment => State::Fragment,
                        }
                    }
                }

                let mut state = match c {
                    b'/' => State::PathSegment,
                    b'?' => State::Query,
                    b'#' => State::Fragment,
                    c => return Err(Unexpected(i, Some(c))),
                };

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

                loop {
                    match state {
                        State::PathSegment => match bytes.next() {
                            Some(b'/') => (), // next segment.
                            Some(b'?') => state = State::Query,
                            Some(b'#') => state = State::Fragment,
                            Some(b'%') => state = State::Pct1(Part::PathSegment),
                            Some(c) if is_pchar(c) => (),
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
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_did_url_accept() {
        let vectors: [&[u8]; 4] = [
            b"did:method:foo",
            b"did:a:b",
            b"did:a:b#fragment",
            b"did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9#key"
        ];

        for input in vectors {
            DIDURL::new(input).unwrap();
        }
    }

    #[test]
    fn parse_did_url_reject() {
        let vectors: [&[u8]; 3] = [b"http:a:b", b"did::b", b"did:a:"];

        for input in vectors {
            assert!(DIDURL::new(input).is_err())
        }
    }
}