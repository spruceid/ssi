use serde::{Deserialize, Serialize};
use ssi_crypto::KeyType;
use zeroize::ZeroizeOnDrop;

use crate::{Base64urlUInt, KeyConversionError};

pub mod curve;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, ZeroizeOnDrop)]
pub struct EcParams {
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

impl EcParams {
    pub fn r#type(&self) -> Option<KeyType> {
        match self.curve.as_deref()? {
            curve::P256 => Some(KeyType::P256),
            curve::P384 => Some(KeyType::P384),
            curve::SECP_256K1 => Some(KeyType::K256),
            _ => None,
        }
    }

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

impl TryFrom<EcParams> for ssi_crypto::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: EcParams) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EcParams> for ssi_crypto::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: &EcParams) -> Result<Self, Self::Error> {
        match value.curve.as_deref().ok_or(KeyConversionError::Invalid)? {
            #[cfg(feature = "secp256k1")]
            curve::SECP_256K1 => value.try_into().map(ssi_crypto::PublicKey::K256),
            curve::P256 => {
                todo!()
            }
            curve::P384 => {
                todo!()
            }
            _ => Err(KeyConversionError::Unsupported),
        }
    }
}

impl TryFrom<EcParams> for ssi_crypto::SecretKey {
    type Error = KeyConversionError;

    fn try_from(value: EcParams) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&EcParams> for ssi_crypto::SecretKey {
    type Error = KeyConversionError;

    fn try_from(value: &EcParams) -> Result<Self, Self::Error> {
        match value.curve.as_deref().ok_or(KeyConversionError::Invalid)? {
            curve::SECP_256K1 => {
                todo!()
            }
            curve::P256 => {
                todo!()
            }
            curve::P384 => {
                todo!()
            }
            _ => Err(KeyConversionError::Unsupported),
        }
    }
}
