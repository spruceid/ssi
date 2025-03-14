use super::P384;
use crate::{Base64urlUInt, EcParams, KeyConversionError, JWK};

impl EcParams {
    pub fn generate_p384() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_p384_from(&mut rng)
    }

    pub fn generate_p384_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::from_secret_p384(&p384::SecretKey::random(rng))
    }

    pub fn from_public_p384(key: &p384::PublicKey) -> Self {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let encoded_point = key.to_encoded_point(false);
        Self {
            curve: Some(P384.to_string()),
            x_coordinate: encoded_point.x().map(|x| Base64urlUInt(x.to_vec())),
            y_coordinate: encoded_point.y().map(|y| Base64urlUInt(y.to_vec())),
            ecc_private_key: None,
        }
    }

    pub fn from_public_p384_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        let key =
            p384::PublicKey::from_sec1_bytes(bytes).map_err(|_| KeyConversionError::Invalid)?;
        Ok(Self::from_public_p384(&key))
    }

    pub fn from_secret_p384(key: &p384::SecretKey) -> Self {
        let pk = key.public_key();
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let encoded_point = pk.to_encoded_point(false);
        Self {
            curve: Some(P384.to_string()),
            x_coordinate: encoded_point.x().map(|x| Base64urlUInt(x.to_vec())),
            y_coordinate: encoded_point.y().map(|y| Base64urlUInt(y.to_vec())),
            ecc_private_key: Some(Base64urlUInt(key.to_bytes().to_vec())),
        }
    }

    pub fn from_secret_p384_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        let key =
            p384::SecretKey::from_bytes(bytes.into()).map_err(|_| KeyConversionError::Invalid)?;
        Ok(Self::from_secret_p384(&key))
    }

    pub fn to_public_p384(&self) -> Result<p384::PublicKey, KeyConversionError> {
        let curve = self.curve.as_deref().ok_or(KeyConversionError::Invalid)?;

        if curve != P384 {
            return Err(KeyConversionError::Unsupported);
        }

        const EC_UNCOMPRESSED_POINT_TAG: &[u8] = &[0x04];
        let x = &self
            .x_coordinate
            .as_ref()
            .ok_or(KeyConversionError::Invalid)?
            .0;
        let y = &self
            .y_coordinate
            .as_ref()
            .ok_or(KeyConversionError::Invalid)?
            .0;
        let pk_data = [EC_UNCOMPRESSED_POINT_TAG, x.as_slice(), y.as_slice()].concat();

        p384::PublicKey::from_sec1_bytes(&pk_data).map_err(|_| KeyConversionError::Invalid)
    }

    /// Serialize a P-256 public key as a 33-byte string with point compression.
    pub fn to_public_p384_bytes(&self) -> Result<Box<[u8]>, KeyConversionError> {
        Ok(self.to_public_p384()?.to_sec1_bytes())
    }

    pub fn to_secret_p384(&self) -> Result<p384::SecretKey, KeyConversionError> {
        let curve = self.curve.as_ref().ok_or(KeyConversionError::Invalid)?;

        if curve != P384 {
            return Err(KeyConversionError::Unsupported);
        }

        let private_key = self
            .ecc_private_key
            .as_ref()
            .ok_or(KeyConversionError::NotSecret)?;

        p384::SecretKey::from_bytes(private_key.0.as_slice().into())
            .map_err(|_| KeyConversionError::Invalid)
    }

    pub fn to_secret_p384_bytes(&self) -> Result<Box<[u8]>, KeyConversionError> {
        Ok(self.to_secret_p384()?.to_bytes().as_slice().into())
    }
}

impl From<p384::PublicKey> for EcParams {
    fn from(pk: p384::PublicKey) -> Self {
        Self::from_public_p384(&pk)
    }
}

impl From<&p384::PublicKey> for EcParams {
    fn from(pk: &p384::PublicKey) -> Self {
        Self::from_public_p384(pk)
    }
}

impl From<p384::SecretKey> for EcParams {
    fn from(k: p384::SecretKey) -> Self {
        Self::from_secret_p384(&k)
    }
}

impl From<&p384::SecretKey> for EcParams {
    fn from(k: &p384::SecretKey) -> Self {
        Self::from_secret_p384(k)
    }
}

impl TryFrom<EcParams> for p384::PublicKey {
    type Error = KeyConversionError;

    fn try_from(params: EcParams) -> Result<Self, Self::Error> {
        params.to_public_p384()
    }
}

impl TryFrom<&EcParams> for p384::PublicKey {
    type Error = KeyConversionError;

    fn try_from(params: &EcParams) -> Result<Self, Self::Error> {
        params.to_public_p384()
    }
}

impl TryFrom<EcParams> for p384::SecretKey {
    type Error = KeyConversionError;

    fn try_from(params: EcParams) -> Result<Self, Self::Error> {
        params.to_secret_p384()
    }
}

impl TryFrom<&EcParams> for p384::SecretKey {
    type Error = KeyConversionError;

    fn try_from(params: &EcParams) -> Result<Self, Self::Error> {
        params.to_secret_p384()
    }
}

impl JWK {
    pub fn generate_p384() -> JWK {
        EcParams::generate_p384().into()
    }

    pub fn generate_p384_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> JWK {
        EcParams::generate_p384_from(rng).into()
    }

    pub fn from_public_p384(key: p384::PublicKey) -> Self {
        EcParams::from_public_p384(&key).into()
    }

    pub fn from_public_p384_bytes(data: &[u8]) -> Result<Self, KeyConversionError> {
        EcParams::from_public_p384_bytes(data).map(Into::into)
    }

    pub fn from_secret_p384(key: p384::SecretKey) -> Self {
        EcParams::from_secret_p384(&key).into()
    }

    pub fn from_secret_p384_bytes(data: &[u8]) -> Result<Self, KeyConversionError> {
        EcParams::from_secret_p384_bytes(data).map(Into::into)
    }
}

impl From<p384::PublicKey> for JWK {
    fn from(value: p384::PublicKey) -> Self {
        EcParams::from(value).into()
    }
}

impl From<&p384::PublicKey> for JWK {
    fn from(value: &p384::PublicKey) -> Self {
        EcParams::from(value).into()
    }
}

impl From<p384::SecretKey> for JWK {
    fn from(value: p384::SecretKey) -> Self {
        EcParams::from(value).into()
    }
}

impl From<&p384::SecretKey> for JWK {
    fn from(value: &p384::SecretKey) -> Self {
        EcParams::from(value).into()
    }
}

impl TryFrom<JWK> for p384::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: JWK) -> Result<Self, Self::Error> {
        value
            .params
            .as_ec()
            .ok_or(KeyConversionError::Unsupported)?
            .to_public_p384()
    }
}

impl TryFrom<&JWK> for p384::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: &JWK) -> Result<Self, Self::Error> {
        value
            .params
            .as_ec()
            .ok_or(KeyConversionError::Unsupported)?
            .to_public_p384()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn p384_generate() {
        let _jwk = crate::JWK::generate_p384();
    }
}
