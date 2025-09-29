use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::Base64urlUInt;

mod curve;
pub use curve::*;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
pub struct ECParams {
    // Parameters for Elliptic Curve Public Keys
    #[serde(rename = "crv")]
    pub curve: Option<String>,
    #[serde(rename = "x")]
    pub x_coordinate: Option<Base64urlUInt>,
    #[serde(rename = "y")]
    pub y_coordinate: Option<Base64urlUInt>,

    // Parameters for Elliptic Curve Private Keys
    #[serde(rename = "d")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecc_private_key: Option<Base64urlUInt>,
}

impl ECParams {
    pub fn is_public(&self) -> bool {
        self.ecc_private_key.is_none()
    }

    /// Strip private key material
    pub fn to_public(&self) -> Self {
        Self {
            curve: self.curve.clone(),
            x_coordinate: self.x_coordinate.clone(),
            y_coordinate: self.y_coordinate.clone(),
            ecc_private_key: None,
        }
    }
}

impl Drop for ECParams {
    fn drop(&mut self) {
        // Zeroize private key
        if let Some(ref mut d) = self.ecc_private_key {
            d.zeroize();
        }
    }
}
