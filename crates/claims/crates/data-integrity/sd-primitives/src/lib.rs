use std::ops::Deref;

use getrandom::getrandom;
pub use hmac::Hmac;
use hmac::Mac;
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Sha384};

pub use ssi_core::{JsonPointer, JsonPointerBuf};

pub type HmacSha256 = Hmac<Sha256>;
pub type HmacSha384 = Hmac<Sha384>;

#[derive(Debug, Clone, Copy)]
pub enum ShaAny {
    Sha256,
    Sha384,
}

impl ShaAny {
    pub fn into_key(self, key: Option<HmacShaAnyKey>) -> Result<HmacShaAnyKey, IntoHmacError> {
        match (self, key) {
            (Self::Sha256, Some(HmacShaAnyKey::Sha256(key))) => Ok(HmacShaAnyKey::Sha256(key)),
            (Self::Sha384, Some(HmacShaAnyKey::Sha384(key))) => Ok(HmacShaAnyKey::Sha384(key)),
            (_, Some(_)) => Err(IntoHmacError::IncompatibleKey),
            (Self::Sha256, None) => {
                let mut key = HmacSha256Key::default();
                getrandom(&mut key).map_err(IntoHmacError::rng)?;
                Ok(HmacShaAnyKey::Sha256(key))
            }
            (Self::Sha384, None) => {
                let mut key = [0; 48];
                getrandom(&mut key).map_err(IntoHmacError::rng)?;
                Ok(HmacShaAnyKey::Sha384(key))
            }
        }
    }

    pub fn into_hmac(self, key: Option<HmacShaAnyKey>) -> Result<HmacShaAny, IntoHmacError> {
        match (self, key) {
            (Self::Sha256, Some(HmacShaAnyKey::Sha256(key))) => Ok(HmacShaAny::Sha256(
                HmacSha256::new_from_slice(&key).unwrap(),
            )),
            (Self::Sha384, Some(HmacShaAnyKey::Sha384(key))) => Ok(HmacShaAny::Sha384(
                HmacSha384::new_from_slice(&key).unwrap(),
            )),
            (_, Some(_)) => Err(IntoHmacError::IncompatibleKey),
            (Self::Sha256, None) => {
                let mut key = HmacSha256Key::default();
                getrandom(&mut key).map_err(IntoHmacError::rng)?;
                Ok(HmacShaAny::Sha256(
                    HmacSha256::new_from_slice(&key).unwrap(),
                ))
            }
            (Self::Sha384, None) => {
                let mut key = [0; 48];
                getrandom(&mut key).map_err(IntoHmacError::rng)?;
                Ok(HmacShaAny::Sha384(
                    HmacSha384::new_from_slice(&key).unwrap(),
                ))
            }
        }
    }

    pub fn hash_all<I: IntoIterator>(&self, iter: I) -> ShaAnyBytes
    where
        I::Item: AsRef<[u8]>,
    {
        use sha2::Digest;
        match self {
            Self::Sha256 => ShaAnyBytes::Sha256(
                iter.into_iter()
                    .fold(Sha256::new(), |h, line| h.chain_update(line.as_ref()))
                    .finalize()
                    .into(),
            ),
            Self::Sha384 => ShaAnyBytes::Sha384(
                iter.into_iter()
                    .fold(Sha384::new(), |h, line| h.chain_update(line.as_ref()))
                    .finalize()
                    .into(),
            ),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum IntoHmacError {
    #[error("incompatible key")]
    IncompatibleKey,

    #[error("random number generation failed: {0}")]
    RandomGenerationFailed(String),
}

impl IntoHmacError {
    fn rng(e: impl ToString) -> Self {
        Self::RandomGenerationFailed(e.to_string())
    }
}

pub enum HmacShaAny {
    Sha256(HmacSha256),
    Sha384(HmacSha384),
}

impl HmacShaAny {
    pub fn update(&mut self, data: &[u8]) {
        match self {
            Self::Sha256(hmac) => hmac.update(data),
            Self::Sha384(hmac) => hmac.update(data),
        }
    }

    pub fn finalize_reset(&mut self) -> ShaAnyBytes {
        match self {
            Self::Sha256(hmac) => ShaAnyBytes::Sha256(hmac.finalize_reset().into_bytes().into()),
            Self::Sha384(hmac) => ShaAnyBytes::Sha384(hmac.finalize_reset().into_bytes().into()),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum ShaAnyBytes {
    Sha256([u8; 32]),
    Sha384([u8; 48]),
}

impl ShaAnyBytes {
    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Sha256(bytes) => bytes,
            Self::Sha384(bytes) => bytes,
        }
    }
}

impl Deref for ShaAnyBytes {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl AsRef<[u8]> for ShaAnyBytes {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

#[derive(Debug, thiserror::Error)]
#[error("invalid HMAC key")]
pub struct InvalidHmacKey;

pub type HmacSha256Key = [u8; 32];
pub type HmacSha384Key = [u8; 48];

#[derive(Debug, Clone, Copy)]
pub enum HmacShaAnyKey {
    Sha256(HmacSha256Key),
    Sha384(HmacSha384Key),
}

impl HmacShaAnyKey {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, InvalidHmacKey> {
        match bytes.len() {
            32 => Ok(Self::Sha256(bytes.try_into().unwrap())),
            48 => Ok(Self::Sha384(bytes.try_into().unwrap())),
            _ => Err(InvalidHmacKey),
        }
    }

    pub fn as_slice(&self) -> &[u8] {
        match self {
            Self::Sha256(bytes) => bytes,
            Self::Sha384(bytes) => bytes,
        }
    }

    pub fn to_hmac(&self) -> HmacShaAny {
        match self {
            Self::Sha256(key) => HmacShaAny::Sha256(HmacSha256::new_from_slice(key).unwrap()),
            Self::Sha384(key) => HmacShaAny::Sha384(HmacSha384::new_from_slice(key).unwrap()),
        }
    }

    pub fn algorithm(&self) -> ShaAny {
        match self {
            Self::Sha256(_) => ShaAny::Sha256,
            Self::Sha384(_) => ShaAny::Sha384,
        }
    }

    pub fn into_sha256(self) -> Result<HmacSha256Key, Self> {
        match self {
            Self::Sha256(k) => Ok(k),
            other => Err(other),
        }
    }
}

impl Deref for HmacShaAnyKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        self.as_slice()
    }
}

impl Serialize for HmacShaAnyKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        hex::encode(self.as_slice()).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for HmacShaAnyKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let hex_string = String::deserialize(deserializer)?;
        let bytes = hex::decode(hex_string).map_err(serde::de::Error::custom)?;
        HmacShaAnyKey::from_bytes(&bytes).map_err(serde::de::Error::custom)
    }
}

pub mod canonicalize;
pub mod group;
pub mod select;
pub mod skolemize;
