use ssi_bbs::{BBSplusPublicKey, BBSplusSecretKey};
use ssi_crypto::key::KeyConversionError;

use crate::{Base64urlUInt, EcParams, Params, JWK};

impl JWK {
    pub fn generate_bls12381g2_with(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        ssi_bbs::generate_secret_key(rng).into()
    }

    pub fn generate_bls12381g2() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_bls12381g2_with(&mut rng)
    }

    pub fn from_public_bls12381g2_bytes(bytes: &[u8]) -> Result<JWK, KeyConversionError> {
        Ok(BBSplusPublicKey::from_bytes(bytes)
            .map_err(|_| KeyConversionError::Invalid)?
            .into())
    }
}

impl<'a> TryFrom<&'a JWK> for BBSplusPublicKey {
    type Error = KeyConversionError;

    fn try_from(value: &'a JWK) -> Result<Self, Self::Error> {
        (&value.params).try_into()
    }
}

impl TryFrom<JWK> for BBSplusPublicKey {
    type Error = KeyConversionError;

    fn try_from(value: JWK) -> Result<Self, Self::Error> {
        value.params.try_into()
    }
}

impl<'a> From<&'a BBSplusPublicKey> for EcParams {
    fn from(value: &'a BBSplusPublicKey) -> Self {
        let (x, y) = value.to_coordinates();
        Self {
            curve: Some("BLS12381G2".to_owned()),
            x_coordinate: Some(Base64urlUInt(x.to_vec())),
            y_coordinate: Some(Base64urlUInt(y.to_vec())),
            ecc_private_key: None,
        }
    }
}

impl From<BBSplusPublicKey> for EcParams {
    fn from(value: BBSplusPublicKey) -> Self {
        (&value).into()
    }
}

impl<'a> From<&'a BBSplusPublicKey> for Params {
    fn from(value: &'a BBSplusPublicKey) -> Self {
        Self::Ec(value.into())
    }
}

impl From<BBSplusPublicKey> for Params {
    fn from(value: BBSplusPublicKey) -> Self {
        Self::Ec(value.into())
    }
}

impl<'a> From<&'a BBSplusPublicKey> for JWK {
    fn from(value: &'a BBSplusPublicKey) -> Self {
        Params::from(value).into()
    }
}

impl From<BBSplusPublicKey> for JWK {
    fn from(value: BBSplusPublicKey) -> Self {
        Params::from(value).into()
    }
}

impl<'a> TryFrom<&'a Params> for BBSplusPublicKey {
    type Error = KeyConversionError;

    fn try_from(value: &'a Params) -> Result<Self, Self::Error> {
        match value {
            Params::Ec(params) => match params.curve.as_deref() {
                Some("BLS12381G2") => {
                    let x: &[u8; 96] = params
                        .x_coordinate
                        .as_ref()
                        .ok_or(KeyConversionError::Invalid)?
                        .0
                        .as_slice()
                        .try_into()
                        .map_err(|_| KeyConversionError::Invalid)?;
                    let y: &[u8; 96] = params
                        .y_coordinate
                        .as_ref()
                        .ok_or(KeyConversionError::Invalid)?
                        .0
                        .as_slice()
                        .try_into()
                        .map_err(|_| KeyConversionError::Invalid)?;

                    BBSplusPublicKey::from_coordinates(x, y)
                        .map_err(|_| KeyConversionError::Invalid)
                }
                Some(_) => Err(KeyConversionError::Unsupported),
                None => Err(KeyConversionError::Invalid),
            },
            _ => Err(KeyConversionError::Unsupported),
        }
    }
}

impl TryFrom<Params> for BBSplusPublicKey {
    type Error = KeyConversionError;

    fn try_from(value: Params) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl<'a> TryFrom<&'a JWK> for BBSplusSecretKey {
    type Error = KeyConversionError;

    fn try_from(value: &'a JWK) -> Result<Self, Self::Error> {
        (&value.params).try_into()
    }
}

impl TryFrom<JWK> for BBSplusSecretKey {
    type Error = KeyConversionError;

    fn try_from(value: JWK) -> Result<Self, Self::Error> {
        value.params.try_into()
    }
}

impl<'a> TryFrom<&'a Params> for BBSplusSecretKey {
    type Error = KeyConversionError;

    fn try_from(value: &'a Params) -> Result<Self, Self::Error> {
        match value {
            Params::Ec(params) => match params.curve.as_deref() {
                Some("BLS12381G2") => {
                    let p = params
                        .ecc_private_key
                        .as_ref()
                        .ok_or(KeyConversionError::Invalid)?
                        .0
                        .as_slice();

                    BBSplusSecretKey::from_bytes(p).map_err(|_| KeyConversionError::Invalid)
                }
                Some(_) => Err(KeyConversionError::Unsupported),
                None => Err(KeyConversionError::Invalid),
            },
            _ => Err(KeyConversionError::Unsupported),
        }
    }
}

impl TryFrom<Params> for BBSplusSecretKey {
    type Error = KeyConversionError;

    fn try_from(value: Params) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl<'a> From<&'a BBSplusSecretKey> for EcParams {
    fn from(value: &'a BBSplusSecretKey) -> Self {
        let pk = value.public_key();
        let mut params: EcParams = pk.into();
        params.ecc_private_key = Some(Base64urlUInt(value.to_bytes().to_vec()));
        params
    }
}

impl From<BBSplusSecretKey> for EcParams {
    fn from(value: BBSplusSecretKey) -> Self {
        (&value).into()
    }
}

impl<'a> From<&'a BBSplusSecretKey> for Params {
    fn from(value: &'a BBSplusSecretKey) -> Self {
        Self::Ec(value.into())
    }
}

impl From<BBSplusSecretKey> for Params {
    fn from(value: BBSplusSecretKey) -> Self {
        Self::Ec(value.into())
    }
}

impl<'a> From<&'a BBSplusSecretKey> for JWK {
    fn from(value: &'a BBSplusSecretKey) -> Self {
        Params::from(value).into()
    }
}

impl From<BBSplusSecretKey> for JWK {
    fn from(value: BBSplusSecretKey) -> Self {
        Params::from(value).into()
    }
}
