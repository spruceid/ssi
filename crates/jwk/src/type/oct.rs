use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::Base64urlUInt;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct SymmetricParams {
    // Parameters for Symmetric Keys
    #[serde(rename = "k")]
    pub key_value: Option<Base64urlUInt>,
}

impl SymmetricParams {
    pub fn is_public(&self) -> bool {
        self.key_value.is_none()
    }

    /// Strip private key material
    pub fn to_public(&self) -> Self {
        Self { key_value: None }
    }
}

impl Drop for SymmetricParams {
    fn drop(&mut self) {
        // Zeroize private/symmetric key
        if let Some(ref mut k) = self.key_value {
            k.zeroize();
        }
    }
}
