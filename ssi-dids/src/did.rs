use core::fmt;
use std::ops::Deref;

mod url;

use serde::{Deserialize, Serialize};
pub use url::*;

/// Error raised when a conversion to a DID fails.
#[derive(Debug, thiserror::Error)]
#[error("invalid DID `{0}`: {1}")]
pub struct InvalidDID<T>(pub T, pub Unexpected);

impl<T> InvalidDID<T> {
    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> InvalidDID<U> {
        InvalidDID(f(self.0), self.1)
    }
}

/// DID.
///
/// This type is unsized and used to represent borrowed DIDs. Use `DIDBuf` for
/// owned DIDs.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct DID([u8]);

impl DID {
    /// Converts the input `data` to a DID.
    ///
    /// Fails if the data is not a DID according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-syntax).
    pub fn new(data: &[u8]) -> Result<&Self, InvalidDID<&[u8]>> {
        match Self::validate(data) {
            Ok(()) => Ok(unsafe {
                // SAFETY: DID is a transparent wrapper over `[u8]`,
                //         and we just checked that `data` is a DID.
                std::mem::transmute(data)
            }),
            Err(e) => Err(InvalidDID(data, e)),
        }
    }

    /// Converts the input `data` to a DID without validation.
    ///
    /// # Safety
    ///
    /// The input `data` must be a DID according to the
    /// [DID Syntax](https://w3c.github.io/did-core/#did-syntax).
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
        // SAFETY: DID is a transparent wrapper over `[u8]`,
        //         but we didn't check if it is actually a DID.
        std::mem::transmute(data)
    }

    /// Returns the DID as a string.
    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: a DID is a valid ASCII string.
            std::str::from_utf8_unchecked(&self.0)
        }
    }

    /// Returns the DID as a byte string.
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the offset of the `:` byte just after the method name.
    fn method_name_separator_offset(&self) -> usize {
        self.0[5..].iter().position(|b| *b == b':').unwrap() + 5 // +5 and not +4 because the method name cannot be empty.
    }

    /// Returns the bytes of the DID method name.
    pub fn method_name_bytes(&self) -> &[u8] {
        &self.0[4..self.method_name_separator_offset()]
    }

    /// Returns the DID method name.
    pub fn method_name(&self) -> &str {
        unsafe {
            // SAFETY: the method name is a valid ASCII string.
            std::str::from_utf8_unchecked(self.method_name_bytes())
        }
    }

    /// Returns the bytes of the DID method specific identifier.
    pub fn method_specific_id_bytes(&self) -> &[u8] {
        &self.0[self.method_name_separator_offset() + 1..]
    }

    /// Returns the DID method specific identifier.
    pub fn method_specific_id(&self) -> &str {
        unsafe {
            // SAFETY: the method specific id is a valid ASCII string.
            std::str::from_utf8_unchecked(self.method_specific_id_bytes())
        }
    }
}

impl Deref for DID {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

impl PartialEq<DIDBuf> for DID {
    fn eq(&self, other: &DIDBuf) -> bool {
        self == other.as_did()
    }
}

impl PartialEq<DIDURL> for DID {
    fn eq(&self, other: &DIDURL) -> bool {
        other == self
    }
}

impl PartialEq<DIDURLBuf> for DID {
    fn eq(&self, other: &DIDURLBuf) -> bool {
        other == self
    }
}

/// Owned DID.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct DIDBuf(Vec<u8>);

impl DIDBuf {
    pub fn new(data: Vec<u8>) -> Result<Self, InvalidDID<Vec<u8>>> {
        match DID::validate(&data) {
            Ok(()) => Ok(Self(data)),
            Err(e) => Err(InvalidDID(data, e)),
        }
    }

    pub fn as_did(&self) -> &DID {
        unsafe {
            // SAFETY: we validated the data in `Self::new`.
            DID::new_unchecked(&self.0)
        }
    }
}

impl TryFrom<String> for DIDBuf {
    type Error = InvalidDID<String>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        DIDBuf::new(value.into_bytes()).map_err(|e| {
            e.map(|bytes| unsafe {
                // SAFETY: `bytes` comes from the `value` string, which is UTF-8
                //         encoded by definition.
                String::from_utf8_unchecked(bytes)
            })
        })
    }
}

impl Deref for DIDBuf {
    type Target = DID;

    fn deref(&self) -> &Self::Target {
        self.as_did()
    }
}

impl fmt::Display for DIDBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for DIDBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl PartialEq<str> for DIDBuf {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<&'a str> for DIDBuf {
    fn eq(&self, other: &&'a str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<DID> for DIDBuf {
    fn eq(&self, other: &DID) -> bool {
        self.as_did() == other
    }
}

impl<'a> PartialEq<&'a DID> for DIDBuf {
    fn eq(&self, other: &&'a DID) -> bool {
        self.as_did() == *other
    }
}

impl PartialEq<DIDURL> for DIDBuf {
    fn eq(&self, other: &DIDURL) -> bool {
        self.as_did() == other
    }
}

impl<'a> PartialEq<&'a DIDURL> for DIDBuf {
    fn eq(&self, other: &&'a DIDURL) -> bool {
        self.as_did() == *other
    }
}

impl PartialEq<DIDURLBuf> for DIDBuf {
    fn eq(&self, other: &DIDURLBuf) -> bool {
        self.as_did() == other
    }
}

impl Serialize for DIDBuf {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for DIDBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = DIDBuf;

            fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                write!(f, "a DID")
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

#[derive(Debug, thiserror::Error)]
pub struct Unexpected(pub usize, pub Option<u8>);

impl fmt::Display for Unexpected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.1 {
            Some(b) => write!(f, "unexpected byte {b} at offset {0:#04x}", self.0),
            None => write!(f, "unexpected end at offset {0:#04x}", self.0),
        }
    }
}

impl DID {
    /// Validates a DID string.
    fn validate(data: &[u8]) -> Result<(), Unexpected> {
        let mut bytes = data.iter().copied();
        match Self::validate_from(0, &mut bytes)? {
            (_, None) => Ok(()),
            (i, Some(c)) => Err(Unexpected(i, Some(c))),
        }
    }

    /// Validates a DID string.
    fn validate_from(
        mut i: usize,
        bytes: &mut impl Iterator<Item = u8>,
    ) -> Result<(usize, Option<u8>), Unexpected> {
        enum State {
            Scheme1,         // d
            Scheme2,         // i
            Scheme3,         // d
            SchemeSeparator, // :
            MethodNameStart,
            MethodName,
            MethodSpecificIdStartOrSeparator,
            MethodSpecificIdPct1,
            MethodSpecificIdPct2,
            MethodSpecificId,
        }

        let mut state = State::Scheme1;
        fn is_method_char(b: u8) -> bool {
            matches!(b, 0x61..=0x7a) || b.is_ascii_digit()
        }

        fn is_id_char(b: u8) -> bool {
            b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_')
        }

        loop {
            match state {
                State::Scheme1 => match bytes.next() {
                    Some(b'd') => state = State::Scheme2,
                    c => break Err(Unexpected(i, c)),
                },
                State::Scheme2 => match bytes.next() {
                    Some(b'i') => state = State::Scheme3,
                    c => break Err(Unexpected(i, c)),
                },
                State::Scheme3 => match bytes.next() {
                    Some(b'd') => state = State::SchemeSeparator,
                    c => break Err(Unexpected(i, c)),
                },
                State::SchemeSeparator => match bytes.next() {
                    Some(b':') => state = State::MethodNameStart,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodNameStart => match bytes.next() {
                    Some(c) if is_method_char(c) => state = State::MethodName,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodName => match bytes.next() {
                    Some(b':') => state = State::MethodSpecificIdStartOrSeparator,
                    Some(c) if is_method_char(c) => (),
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodSpecificIdStartOrSeparator => match bytes.next() {
                    Some(b':') => (),
                    Some(b'%') => state = State::MethodSpecificIdPct1,
                    Some(c) if is_id_char(c) => state = State::MethodSpecificId,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodSpecificIdPct1 => match bytes.next() {
                    Some(c) if c.is_ascii_hexdigit() => state = State::MethodSpecificIdPct2,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodSpecificIdPct2 => match bytes.next() {
                    Some(c) if c.is_ascii_hexdigit() => state = State::MethodSpecificId,
                    c => break Err(Unexpected(i, c)),
                },
                State::MethodSpecificId => match bytes.next() {
                    Some(b':') => state = State::MethodSpecificIdStartOrSeparator,
                    Some(c) if is_id_char(c) => (),
                    c => break Ok((i, c)),
                },
            }

            i += 1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_did_accept() {
        let vectors: [&[u8]; 3] = [
            b"did:method:foo",
            b"did:a:b",
            b"did:jwk:eyJjcnYiOiJQLTI1NiIsImt0eSI6IkVDIiwieCI6ImFjYklRaXVNczNpOF91c3pFakoydHBUdFJNNEVVM3l6OTFQSDZDZEgyVjAiLCJ5IjoiX0tjeUxqOXZXTXB0bm1LdG00NkdxRHo4d2Y3NEk1TEtncmwyR3pIM25TRSJ9"
        ];

        for input in vectors {
            DID::new(input).unwrap();
        }
    }

    #[test]
    fn parse_did_reject() {
        let vectors: [&[u8]; 3] = [b"http:a:b", b"did::b", b"did:a:"];

        for input in vectors {
            assert!(DID::new(input).is_err())
        }
    }
}
