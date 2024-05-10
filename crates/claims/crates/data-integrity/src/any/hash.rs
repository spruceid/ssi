use ssi_claims_core::{ProofValidationError, SignatureError};

#[derive(Debug, thiserror::Error)]
#[error("invalid hash")]
pub struct InvalidHash;

impl From<InvalidHash> for SignatureError {
    fn from(value: InvalidHash) -> Self {
        Self::Claims(value.to_string())
    }
}

impl From<InvalidHash> for ProofValidationError {
    fn from(value: InvalidHash) -> Self {
        Self::InvalidInputData(value.to_string())
    }
}

#[derive(Debug, Clone)]
pub enum AnyHash {
    Array32([u8; 32]),
    Array64([u8; 64]),
    Array66([u8; 66]),
    Vec(Vec<u8>),
    String(String),
}

impl AsRef<[u8]> for AnyHash {
    fn as_ref(&self) -> &[u8] {
        match self {
            Self::Array32(a) => a.as_ref(),
            Self::Array64(a) => a.as_ref(),
            Self::Array66(a) => a.as_ref(),
            Self::Vec(v) => v.as_ref(),
            Self::String(s) => s.as_bytes(),
        }
    }
}

impl From<[u8; 32]> for AnyHash {
    fn from(value: [u8; 32]) -> Self {
        Self::Array32(value)
    }
}

impl<'a> TryFrom<&'a AnyHash> for &'a [u8; 32] {
    type Error = InvalidHash;

    fn try_from(value: &'a AnyHash) -> Result<Self, Self::Error> {
        match value {
            AnyHash::Array32(h) => Ok(h),
            _ => Err(InvalidHash),
        }
    }
}

impl From<[u8; 64]> for AnyHash {
    fn from(value: [u8; 64]) -> Self {
        Self::Array64(value)
    }
}

impl<'a> TryFrom<&'a AnyHash> for &'a [u8; 64] {
    type Error = InvalidHash;

    fn try_from(value: &'a AnyHash) -> Result<Self, Self::Error> {
        match value {
            AnyHash::Array64(h) => Ok(h),
            _ => Err(InvalidHash),
        }
    }
}

impl From<[u8; 66]> for AnyHash {
    fn from(value: [u8; 66]) -> Self {
        Self::Array66(value)
    }
}

impl<'a> TryFrom<&'a AnyHash> for &'a [u8; 66] {
    type Error = InvalidHash;

    fn try_from(value: &'a AnyHash) -> Result<Self, Self::Error> {
        match value {
            AnyHash::Array66(h) => Ok(h),
            _ => Err(InvalidHash),
        }
    }
}

impl From<Vec<u8>> for AnyHash {
    fn from(value: Vec<u8>) -> Self {
        Self::Vec(value)
    }
}

impl<'a> TryFrom<&'a AnyHash> for &'a Vec<u8> {
    type Error = InvalidHash;

    fn try_from(value: &'a AnyHash) -> Result<Self, Self::Error> {
        match value {
            AnyHash::Vec(h) => Ok(h),
            _ => Err(InvalidHash),
        }
    }
}

impl From<String> for AnyHash {
    fn from(value: String) -> Self {
        Self::String(value)
    }
}

impl<'a> TryFrom<&'a AnyHash> for &'a String {
    type Error = InvalidHash;

    fn try_from(value: &'a AnyHash) -> Result<Self, Self::Error> {
        match value {
            AnyHash::String(h) => Ok(h),
            _ => Err(InvalidHash),
        }
    }
}
