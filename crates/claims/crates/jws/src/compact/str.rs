use base64::Engine;
use core::fmt;
use std::{ops::Deref, str::FromStr};

use crate::{
    utils::is_url_safe_base64_char, DecodeError, DecodedJws, Header, InvalidJws, JwsSlice,
};

/// Borrowed UTF-8 encoded JWS.
///
/// This is an unsized type borrowing the JWS and meant to be referenced as
/// `&JwsStr`, just like `&str`.
/// Use [`JwsString`] if you need to own the JWS.
///
/// This type is similar to the [`Jws`](crate::Jws) type.
/// However contrarily to `Jws`, there is no guarantee that the JWS is URL-safe.
///
/// Use [`Jws`](crate::Jws) if you expect URL-safe JWSs.
#[derive(PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct JwsStr(JwsSlice);

impl JwsStr {
    pub fn new<T: ?Sized + AsRef<[u8]>>(data: &T) -> Result<&Self, InvalidJws<&T>> {
        let bytes = data.as_ref();
        match std::str::from_utf8(bytes) {
            Ok(_) => {
                let _ = JwsSlice::new(bytes).map_err(|_| InvalidJws(data))?;
                Ok(unsafe { Self::new_unchecked(bytes) })
            }
            Err(_) => Err(InvalidJws(data)),
        }
    }

    pub const fn validate(bytes: &[u8]) -> bool {
        Self::validate_range(bytes, 0, bytes.len())
    }

    pub const fn validate_range(bytes: &[u8], mut i: usize, end: usize) -> bool {
        let mut j = if end > bytes.len() { bytes.len() } else { end };

        // Header.
        loop {
            if i >= j {
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

        // Signature.
        if i >= j {
            return false;
        }
        j -= 1;
        loop {
            if i >= j {
                // Missing `.`
                return false;
            }

            if bytes[j] == b'.' {
                break;
            }

            if !is_url_safe_base64_char(bytes[j]) {
                return false;
            }

            j -= 1
        }

        // Payload.
        i += 1;
        let payload_bytes = unsafe { std::slice::from_raw_parts(bytes.as_ptr().add(i), j - i) };

        std::str::from_utf8(payload_bytes).is_ok()
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

impl Deref for JwsStr {
    type Target = JwsSlice;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl fmt::Display for JwsStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for JwsStr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl serde::Serialize for JwsStr {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.as_str().serialize(serializer)
    }
}

impl PartialEq<str> for JwsStr {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<String> for JwsStr {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<String> for &'a JwsStr {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<JwsStr> for str {
    fn eq(&self, other: &JwsStr) -> bool {
        self == other.as_str()
    }
}

impl PartialEq<JwsStr> for String {
    fn eq(&self, other: &JwsStr) -> bool {
        self == other.as_str()
    }
}

impl<'a> PartialEq<&'a JwsStr> for String {
    fn eq(&self, other: &&'a JwsStr) -> bool {
        self == other.as_str()
    }
}

/// Owned UTF-8 encoded JWS.
///
/// This type is similar to the [`JwsBuf`](crate::JwsBuf) type.
/// However contrarily to `JwsBuf`, there is no guarantee that the JWS is
/// URL-safe.
///
/// Use [`JwsBuf`](crate::JwsBuf) if you expect URL-safe JWSs.
#[derive(Clone, serde::Serialize)]
#[serde(transparent)]
pub struct JwsString(String);

impl JwsString {
    pub fn new(bytes: Vec<u8>) -> Result<Self, InvalidJws<Vec<u8>>> {
        match String::from_utf8(bytes) {
            Ok(string) => {
                if JwsSlice::validate(string.as_bytes()) {
                    Ok(Self(string))
                } else {
                    Err(InvalidJws(string.into_bytes()))
                }
            }
            Err(e) => Err(InvalidJws(e.into_bytes())),
        }
    }

    pub fn from_string(string: String) -> Result<Self, InvalidJws<String>> {
        if JwsSlice::validate(string.as_bytes()) {
            Ok(Self(string))
        } else {
            Err(InvalidJws(string))
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
    pub fn new_detached(header: Header, b64_signature: &[u8]) -> Result<Self, InvalidJws<Vec<u8>>> {
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
    ) -> Result<Self, InvalidJws<Vec<u8>>> {
        let b64_signature = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(signature);
        let mut bytes = signing_bytes;
        bytes.push(b'.');
        bytes.extend_from_slice(b64_signature.as_bytes());
        Self::new(bytes)
    }

    pub fn from_signing_bytes_and_signature(
        signing_bytes: Vec<u8>,
        signature: impl IntoIterator<Item = u8>,
    ) -> Result<Self, InvalidJws<Vec<u8>>> {
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

    pub fn as_compact_jws_str(&self) -> &JwsStr {
        unsafe { JwsStr::new_unchecked(self.0.as_bytes()) }
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
    pub fn into_decoded(self) -> Result<DecodedJws<'static>, DecodeError> {
        Ok(self.decode()?.into_owned())
    }
}

impl Deref for JwsString {
    type Target = JwsStr;

    fn deref(&self) -> &Self::Target {
        self.as_compact_jws_str()
    }
}

impl fmt::Display for JwsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl fmt::Debug for JwsString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.as_str().fmt(f)
    }
}

impl FromStr for JwsString {
    type Err = InvalidJws;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Self::from_string(s.to_owned())
    }
}

impl TryFrom<String> for JwsString {
    type Error = InvalidJws<String>;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        Self::from_string(value)
    }
}

impl<'de> serde::Deserialize<'de> for JwsString {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = JwsString;

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
                JwsString::from_string(v).map_err(|e| E::custom(e))
            }
        }

        deserializer.deserialize_string(Visitor)
    }
}

impl PartialEq<str> for JwsString {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == other
    }
}

impl<'a> PartialEq<&'a str> for JwsString {
    fn eq(&self, other: &&'a str) -> bool {
        self.as_str() == *other
    }
}

impl PartialEq<String> for JwsString {
    fn eq(&self, other: &String) -> bool {
        self.as_str() == other
    }
}

impl PartialEq<JwsString> for str {
    fn eq(&self, other: &JwsString) -> bool {
        self == other.as_str()
    }
}

impl<'a> PartialEq<JwsString> for &'a str {
    fn eq(&self, other: &JwsString) -> bool {
        *self == other.as_str()
    }
}

impl PartialEq<JwsString> for String {
    fn eq(&self, other: &JwsString) -> bool {
        self == other.as_str()
    }
}
