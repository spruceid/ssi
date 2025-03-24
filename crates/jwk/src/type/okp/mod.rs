use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::Base64urlUInt;

mod curve;
pub use curve::*;

mod der;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct OctetParams {
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

impl OctetParams {
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

impl Drop for OctetParams {
    fn drop(&mut self) {
        // Zeroize private key
        if let Some(ref mut d) = self.private_key {
            d.zeroize();
        }
    }
}

#[cfg(feature = "ring")]
impl TryFrom<&OctetParams> for &ring::signature::EdDSAParameters {
    type Error = crate::Error;

    fn try_from(params: &OctetParams) -> Result<Self, Self::Error> {
        if params.curve != *"Ed25519" {
            return Err(crate::Error::CurveNotImplemented(params.curve.to_string()));
        }

        Ok(&ring::signature::ED25519)
    }
}
