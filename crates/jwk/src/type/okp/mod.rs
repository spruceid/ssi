use serde::{Deserialize, Serialize};
use ssi_crypto::{key::KeyConversionError, KeyType};
use zeroize::ZeroizeOnDrop;

use crate::Base64urlUInt;

pub mod curve;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, ZeroizeOnDrop)]
pub struct OkpParams {
    // Parameters for Octet Key Pair Public Keys
    #[serde(rename = "crv")]
    pub curve: String,
    #[serde(rename = "x")]
    pub public_key: Base64urlUInt,

    // Parameters for Octet Key Pair Private Keys
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub private_key: Option<Base64urlUInt>,
}

impl OkpParams {
    pub fn r#type(&self) -> Option<KeyType> {
        match self.curve.as_str() {
            curve::ED25519 => Some(KeyType::Ed25519),
            _ => None,
        }
    }

    pub fn is_public(&self) -> bool {
        self.private_key.is_none()
    }

    /// Strip private key material
    pub fn to_public(&self) -> Self {
        Self {
            curve: self.curve.clone(),
            public_key: self.public_key.clone(),
            private_key: None,
        }
    }
}

impl TryFrom<OkpParams> for ssi_crypto::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: OkpParams) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OkpParams> for ssi_crypto::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: &OkpParams) -> Result<Self, Self::Error> {
        match value.curve.as_str() {
            #[cfg(feature = "ed25519")]
            curve::ED25519 => value.try_into().map(ssi_crypto::PublicKey::Ed25519),
            _ => Err(KeyConversionError::Unsupported),
        }
    }
}

impl TryFrom<OkpParams> for ssi_crypto::SecretKey {
    type Error = KeyConversionError;

    fn try_from(value: OkpParams) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&OkpParams> for ssi_crypto::SecretKey {
    type Error = KeyConversionError;

    fn try_from(value: &OkpParams) -> Result<Self, Self::Error> {
        match value.curve.as_str() {
            #[cfg(feature = "ed25519")]
            curve::ED25519 => value.try_into().map(ssi_crypto::SecretKey::Ed25519),
            _ => Err(KeyConversionError::Unsupported),
        }
    }
}
