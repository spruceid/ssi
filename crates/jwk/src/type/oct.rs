use serde::{Deserialize, Serialize};
use ssi_crypto::key::{symmetric::SymmetricKey, KeyConversionError};
use zeroize::ZeroizeOnDrop;

use crate::Base64urlUInt;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, ZeroizeOnDrop)]
pub struct OctParams {
    // Parameters for Symmetric Keys
    #[serde(rename = "k")]
    pub key_value: Option<Base64urlUInt>,
}

impl OctParams {
    pub fn is_public(&self) -> bool {
        self.key_value.is_none()
    }

    /// Strip private key material
    pub fn to_public(&self) -> Self {
        Self { key_value: None }
    }

    pub fn to_symmetric_key(&self) -> Result<SymmetricKey, KeyConversionError> {
        Ok(SymmetricKey::new(
            self.key_value
                .as_ref()
                .ok_or(KeyConversionError::NotSecret)?
                .0
                .clone()
                .into_boxed_slice(),
        ))
    }
}

impl From<&OctParams> for ssi_crypto::PublicKey {
    fn from(_: &OctParams) -> Self {
        Self::Symmetric
    }
}

impl TryFrom<&OctParams> for ssi_crypto::SecretKey {
    type Error = KeyConversionError;

    fn try_from(value: &OctParams) -> Result<Self, Self::Error> {
        value
            .to_symmetric_key()
            .map(ssi_crypto::SecretKey::Symmetric)
    }
}
