use core::fmt;
use std::{ops::Deref, str::FromStr};

use crate::{CompactJWS, DecodeError, DecodedJWS, Header, InvalidCompactJWS};

/// JWS in UTF-8 compact serialized form.
///
/// Contrarily to [`CompactJWS`], this type guarantees that the payload is
/// a valid UTF-8 string, meaning the whole compact JWS is an UTF-8 string.
/// This does not necessarily mean the payload is base64 encoded.
#[repr(transparent)]
pub struct CompactJWSStr(CompactJWS);

impl CompactJWSStr {
    pub fn new(data: &[u8]) -> Result<&Self, InvalidCompactJWS<&[u8]>> {
        match std::str::from_utf8(data) {
            Ok(s) => Self::from_string(s).map_err(|_| InvalidCompactJWS(data)),
            Err(_) => Err(InvalidCompactJWS(data)),
        }
    }

    pub fn from_string(data: &str) -> Result<&Self, InvalidCompactJWS<&str>> {
        let inner = CompactJWS::new(data.as_bytes()).map_err(|_| InvalidCompactJWS(data))?;
        Ok(unsafe { std::mem::transmute::<&CompactJWS, &Self>(inner) })
    }

    /// Creates a new compact JWS without checking the data.
    ///
    /// # Safety
    ///
    /// The input `data` must represent a valid compact JWS where the payload
    /// is an UTF-8 string.
    pub unsafe fn new_unchecked(data: &[u8]) -> &Self {
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

impl Deref for CompactJWSStr {
    type Target = CompactJWS;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for CompactJWSStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for CompactJWSStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl serde::Serialize for CompactJWSStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl PartialEq<str> for CompactJWSStr {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<String> for CompactJWSStr {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<String> for &'a CompactJWSStr {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<CompactJWSStr> for str {
    fn eq(&self, other: &CompactJWSStr) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<CompactJWSStr> for String {
    fn eq(&self, other: &CompactJWSStr) -> bool {
        self == other.as_str()
    }
}

impl<'a> PartialEq<&'a CompactJWSStr> for String {
    fn eq(&self, other: &&'a CompactJWSStr) -> bool {
        self == other.as_str()
    }
}

/// JWS in compact serialized form, with an UTF-8 encoded payload.
///
/// Contrarily to [`CompactJWS`], this type guarantees that the payload is
/// a valid UTF-8 string, meaning the whole compact JWS is an UTF-8 string.
/// This does not necessarily mean the payload is base64 encoded.
#[derive(Clone, serde::Serialize)]
#[serde(transparent)]
pub struct CompactJWSString(String);

impl CompactJWSString {
    pub fn new(bytes: Vec<u8>) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        match String::from_utf8(bytes) {
            Ok(string) => {
                if CompactJWS::check(string.as_bytes()) {
                    Ok(Self(string))
                } else {
                    Err(InvalidCompactJWS(string.into_bytes()))
                }
            }
            Err(e) => Err(InvalidCompactJWS(e.into_bytes())),
        }
    }

    pub fn from_string(string: String) -> Result<Self, InvalidCompactJWS<String>> {
        if CompactJWS::check(string.as_bytes()) {
            Ok(Self(string))
        } else {
            Err(InvalidCompactJWS(string))
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
        let b64_signature = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
        Self::new_detached(header, b64_signature.as_bytes()).unwrap()
    }

    /// Encodes the given signature in base64 and returns a compact JWS.
    pub fn encode_from_signing_bytes_and_signature(
        signing_bytes: Vec<u8>,
        signature: &[u8],
    ) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        let b64_signature = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
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

    pub fn as_compact_jws_str(&self) -> &CompactJWSStr {
        unsafe { CompactJWSStr::new_unchecked(self.0.as_bytes()) }
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
    pub fn into_decoded(self) -> Result<DecodedJWS<Vec<u8>>, DecodeError> {
        let decoded = self.decode()?.into_owned();
        Ok(DecodedJWS::new(
            self.into_signing_bytes().into_bytes(),
            decoded,
        ))
    }
}

impl Deref for CompactJWSString {
    type Target = CompactJWSStr;

    fn deref(&self) -> &Self::Target {
        self.as_compact_jws_str()
    }
}

impl fmt::Display for CompactJWSString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for CompactJWSString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl FromStr for CompactJWSString {
    type Err = InvalidCompactJWS;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_string(s.to_owned())
    }
}

impl TryFrom<String> for CompactJWSString {
    type Error = InvalidCompactJWS<String>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_string(value)
    }
}

impl<'de> serde::Deserialize<'de> for CompactJWSString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = CompactJWSString;

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
                CompactJWSString::from_string(v).map_err(|e| E::custom(e))
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

impl PartialEq<str> for CompactJWSString {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<&'a str> for CompactJWSString {
    fn eq(&self, other: &&'a str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for CompactJWSString {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<CompactJWSString> for str {
    fn eq(&self, other: &CompactJWSString) -> bool {
        self == other.as_str()
    }
}

impl<'a> PartialEq<CompactJWSString> for &'a str {
    fn eq(&self, other: &CompactJWSString) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<CompactJWSString> for String {
    fn eq(&self, other: &CompactJWSString) -> bool {
        self == other.as_str()
    }
}
