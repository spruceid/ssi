use base64::Engine;
use core::fmt;
use ssi_core::BytesBuf;
use std::{ops::Deref, str::FromStr};

use crate::{
    utils::is_url_safe_base64_char, CompactJWS, CompactJWSStr, DecodeError, DecodedJWS, Header,
    InvalidCompactJWS,
};

/// Creates a new static URL-safe JWS reference from a string literal.
#[macro_export]
macro_rules! url_safe_jws {
    ($value:literal) => {
        match $crate::UrlSafeJws::from_str_const($value) {
            Ok(value) => value,
            Err(_) => panic!("invalid URL-safe JWS"),
        }
    };
}

/// URL-safe JWS.
///
/// Contrarily to [`CompactJWS`] or [`CompactJWSStr`], this type guarantees that
/// the payload uses URL-safe characters (even if it is not URL-safe encoded).
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct UrlSafeJws(CompactJWSStr);

impl UrlSafeJws {
    pub fn new<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<&Self, InvalidCompactJWS<&T>> {
        let bytes = data.as_ref();
        match std::str::from_utf8(bytes) {
            Ok(_) => {
                let _ = CompactJWS::new(bytes).map_err(|_| InvalidCompactJWS(data))?;
                Ok(unsafe { Self::new_unchecked(bytes) })
            }
            Err(_) => Err(InvalidCompactJWS(data)),
        }
    }

    /// Parses the given `input` string as an URL-safe JWS.
    ///
    /// Returns an error if it is not a valid URL-safe JWS.
    pub const fn from_str_const(input: &str) -> Result<&Self, InvalidCompactJWS<&str>> {
        let bytes = input.as_bytes();
        if Self::validate(bytes) {
            Ok(unsafe { Self::new_unchecked(bytes) })
        } else {
            Err(InvalidCompactJWS(input))
        }
    }

    pub const fn validate(bytes: &[u8]) -> bool {
        Self::validate_range(bytes, 0, bytes.len())
    }

    pub const fn validate_range(bytes: &[u8], mut i: usize, end: usize) -> bool {
        // Header.
        loop {
            if i >= end {
                // Missing `.`
                return false;
            }

            if bytes[i] == b'.' {
                break;
            }

            if !is_url_safe_base64_char(bytes[i]) {
                return false;
            }

            i += 1
        }

        i += 1;

        // Payload.
        loop {
            if i >= end {
                // Missing `.`
                return false;
            }

            if bytes[i] == b'.' {
                break;
            }

            if !is_url_safe_base64_char(bytes[i]) {
                return false;
            }

            i += 1
        }

        i += 1;

        // Signature.
        while i < end {
            if !is_url_safe_base64_char(bytes[i]) {
                return false;
            }

            i += 1
        }

        true
    }

    /// Creates a new compact JWS without checking the data.
    ///
    /// # Safety
    ///
    /// The input `data` must represent a valid compact JWS where the payload
    /// is an UTF-8 string.
    pub const unsafe fn new_unchecked(data: &[u8]) -> &Self {
        std::mem::transmute(data)
    }

    pub fn as_str(&self) -> &str {
        unsafe {
            // Safety: we already checked that the bytes are a valid UTF-8
            // string.
            std::str::from_utf8_unchecked(self.0.as_bytes())
        }
    }
}

impl Deref for UrlSafeJws {
    type Target = CompactJWS;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for UrlSafeJws {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for UrlSafeJws {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl serde::Serialize for UrlSafeJws {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl PartialEq<str> for UrlSafeJws {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<String> for UrlSafeJws {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<String> for &'a UrlSafeJws {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<UrlSafeJws> for str {
    fn eq(&self, other: &UrlSafeJws) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<UrlSafeJws> for String {
    fn eq(&self, other: &UrlSafeJws) -> bool {
        self == other.as_str()
    }
}

impl<'a> PartialEq<&'a UrlSafeJws> for String {
    fn eq(&self, other: &&'a UrlSafeJws) -> bool {
        self == other.as_str()
    }
}

/// Owned URL-safe JWS.
///
/// Contrarily to [`CompactJWSBuf`] or [`CompactJWSString`], this type
/// guarantees that the payload uses URL-safe characters (even if it is not
/// URL-safe encoded).
#[derive(Clone, serde::Serialize)]
#[serde(transparent)]
pub struct UrlSafeJwsBuf(String);

impl UrlSafeJwsBuf {
    pub fn new<B: BytesBuf>(bytes: B) -> Result<Self, InvalidCompactJWS<B>> {
        if UrlSafeJws::validate(bytes.as_ref()) {
            Ok(unsafe {
                // SAFETY: we just validated the bytes.
                Self::new_unchecked(bytes.into())
            })
        } else {
            Err(InvalidCompactJWS(bytes))
        }
    }

    /// # Safety
    ///
    /// The input `bytes` must represent a valid compact JWS where the payload
    /// is UTF-8 encoded.
    pub unsafe fn new_unchecked(bytes: Vec<u8>) -> Self {
        Self(String::from_utf8_unchecked(bytes))
    }

    /// Creates a new detached JWS from a header and base64-encoded signature.
    ///
    /// Detached means the payload will not appear in the JWS.
    pub fn new_detached(
        header: Header,
        b64_signature: &[u8],
    ) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        let mut bytes = header.encode().into_bytes();
        bytes.extend(b"..");
        bytes.extend(b64_signature.iter().copied());
        Self::new(bytes)
    }

    /// Creates a new detached JWS from a header and unencoded signature.
    ///
    /// Detached means the payload will not appear in the JWS.
    pub fn encode_detached(header: Header, signature: &[u8]) -> Self {
        let b64_signature = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(signature);
        Self::new_detached(header, b64_signature.as_bytes()).unwrap()
    }

    /// Encodes the given signature in base64 and returns a compact JWS.
    pub fn encode_from_signing_bytes_and_signature(
        signing_bytes: Vec<u8>,
        signature: &[u8],
    ) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        let b64_signature = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(signature);
        let mut bytes = signing_bytes;
        bytes.push(b'.');
        bytes.extend_from_slice(b64_signature.as_bytes());
        Self::new(bytes)
    }

    pub fn from_signing_bytes_and_signature(
        signing_bytes: Vec<u8>,
        signature: impl IntoIterator<Item = u8>,
    ) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        let mut bytes = signing_bytes;
        bytes.push(b'.');
        bytes.extend(signature);
        Self::new(bytes)
    }

    /// # Safety
    ///
    /// The input `signing_bytes` and `signature` must form a valid compact JWS
    /// once concatenated with a `.`.
    pub unsafe fn from_signing_bytes_and_signature_unchecked(
        signing_bytes: Vec<u8>,
        signature: Vec<u8>,
    ) -> Self {
        let mut bytes = signing_bytes;
        bytes.push(b'.');
        bytes.extend(signature);
        Self::new_unchecked(bytes)
    }

    pub fn as_compact_jws_str(&self) -> &UrlSafeJws {
        unsafe { UrlSafeJws::new_unchecked(self.0.as_bytes()) }
    }

    pub fn into_signing_bytes(mut self) -> String {
        self.0.truncate(self.payload_end()); // remove the signature.
        self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// Decodes the entire JWS while preserving the signing bytes so they can
    /// be verified.
    pub fn into_decoded(self) -> Result<DecodedJWS<'static>, DecodeError> {
        Ok(self.decode()?.into_owned())
    }
}

impl Deref for UrlSafeJwsBuf {
    type Target = UrlSafeJws;

    fn deref(&self) -> &Self::Target {
        self.as_compact_jws_str()
    }
}

impl fmt::Display for UrlSafeJwsBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for UrlSafeJwsBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl FromStr for UrlSafeJwsBuf {
    type Err = InvalidCompactJWS;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::new(s.to_owned())
    }
}

impl TryFrom<String> for UrlSafeJwsBuf {
    type Error = InvalidCompactJWS<String>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<'de> serde::Deserialize<'de> for UrlSafeJwsBuf {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = UrlSafeJwsBuf;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("compact JWS")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                self.visit_string(v.to_owned())
            }

            fn visit_string<E>(self, v: String) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                UrlSafeJwsBuf::new(v).map_err(|e| E::custom(e))
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

impl PartialEq<str> for UrlSafeJwsBuf {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<&'a str> for UrlSafeJwsBuf {
    fn eq(&self, other: &&'a str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for UrlSafeJwsBuf {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<UrlSafeJwsBuf> for str {
    fn eq(&self, other: &UrlSafeJwsBuf) -> bool {
        self == other.as_str()
    }
}

impl<'a> PartialEq<UrlSafeJwsBuf> for &'a str {
    fn eq(&self, other: &UrlSafeJwsBuf) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<UrlSafeJwsBuf> for String {
    fn eq(&self, other: &UrlSafeJwsBuf) -> bool {
        self == other.as_str()
    }
}
