use super::SECP_256K1;
use crate::{Base64urlUInt, EcParams, KeyConversionError, JWK};

impl EcParams {
    pub fn generate_secp256k1() -> Self {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_secp256k1_from(&mut rng)
    }

    pub fn generate_secp256k1_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> Self {
        Self::from_secret_secp256k1(&k256::SecretKey::random(rng))
    }

    pub fn from_public_secp256k1(key: &k256::PublicKey) -> Self {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let ec_points = key.to_encoded_point(false);
        EcParams {
            curve: Some(SECP_256K1.to_owned()),
            x_coordinate: ec_points.x().map(|x| Base64urlUInt(x.to_vec())),
            y_coordinate: ec_points.y().map(|y| Base64urlUInt(y.to_vec())),
            ecc_private_key: None,
        }
    }

    pub fn from_public_secp256k1_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        let key =
            k256::PublicKey::from_sec1_bytes(bytes).map_err(|_| KeyConversionError::Invalid)?;
        Ok(Self::from_public_secp256k1(&key))
    }

    pub fn from_secret_secp256k1(key: &k256::SecretKey) -> Self {
        let pk = key.public_key();
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let ec_points = pk.to_encoded_point(false);
        EcParams {
            curve: Some(SECP_256K1.to_owned()),
            x_coordinate: ec_points.x().map(|x| Base64urlUInt(x.to_vec())),
            y_coordinate: ec_points.y().map(|y| Base64urlUInt(y.to_vec())),
            ecc_private_key: Some(Base64urlUInt(key.to_bytes().to_vec())),
        }
    }

    pub fn from_secret_secp256k1_bytes(bytes: &[u8]) -> Result<Self, KeyConversionError> {
        let key = k256::SecretKey::from_sec1_der(bytes).map_err(|_| KeyConversionError::Invalid)?;
        Ok(Self::from_secret_secp256k1(&key))
    }

    pub fn to_public_secp256k1(&self) -> Result<k256::PublicKey, KeyConversionError> {
        let curve = self.curve.as_deref().ok_or(KeyConversionError::Invalid)?;

        if curve != SECP_256K1 {
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

        k256::PublicKey::from_sec1_bytes(&pk_data).map_err(|_| KeyConversionError::Invalid)
    }

    /// Serialize a secp256k1 public key as a 33-byte string with point compression.
    pub fn to_public_secp256k1_bytes(&self) -> Result<Box<[u8]>, KeyConversionError> {
        use k256::elliptic_curve::sec1::ToEncodedPoint;

        let pk = self.to_public_secp256k1()?;
        let pk_compressed_bytes = pk.to_encoded_point(true);
        Ok(pk_compressed_bytes.as_bytes().into())
    }

    pub fn to_secret_secp256k1(&self) -> Result<k256::SecretKey, KeyConversionError> {
        let curve = self.curve.as_deref().ok_or(KeyConversionError::Invalid)?;

        if curve != SECP_256K1 {
            return Err(KeyConversionError::Unsupported);
        }

        let private_key = self
            .ecc_private_key
            .as_ref()
            .ok_or(KeyConversionError::NotSecret)?;

        k256::SecretKey::from_bytes(private_key.0.as_slice().into())
            .map_err(|_| KeyConversionError::Invalid)
    }
}

impl From<k256::PublicKey> for EcParams {
    fn from(pk: k256::PublicKey) -> Self {
        Self::from_public_secp256k1(&pk)
    }
}

impl From<&k256::PublicKey> for EcParams {
    fn from(pk: &k256::PublicKey) -> Self {
        Self::from_public_secp256k1(pk)
    }
}

impl From<k256::SecretKey> for EcParams {
    fn from(k: k256::SecretKey) -> Self {
        Self::from_secret_secp256k1(&k)
    }
}

impl From<&k256::SecretKey> for EcParams {
    fn from(k: &k256::SecretKey) -> Self {
        Self::from_secret_secp256k1(k)
    }
}

impl TryFrom<EcParams> for k256::PublicKey {
    type Error = KeyConversionError;

    fn try_from(params: EcParams) -> Result<Self, Self::Error> {
        params.to_public_secp256k1()
    }
}

impl TryFrom<&EcParams> for k256::PublicKey {
    type Error = KeyConversionError;

    fn try_from(params: &EcParams) -> Result<Self, Self::Error> {
        params.to_public_secp256k1()
    }
}

impl TryFrom<EcParams> for k256::SecretKey {
    type Error = KeyConversionError;

    fn try_from(params: EcParams) -> Result<Self, Self::Error> {
        params.to_secret_secp256k1()
    }
}

impl TryFrom<&EcParams> for k256::SecretKey {
    type Error = KeyConversionError;

    fn try_from(params: &EcParams) -> Result<Self, Self::Error> {
        params.to_secret_secp256k1()
    }
}

impl JWK {
    pub fn generate_secp256k1() -> JWK {
        EcParams::generate_secp256k1().into()
    }

    pub fn generate_secp256k1_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> JWK {
        EcParams::generate_secp256k1_from(rng).into()
    }

    pub fn from_public_secp256k1(key: k256::PublicKey) -> Self {
        EcParams::from_public_secp256k1(&key).into()
    }

    pub fn from_public_secp256k1_bytes(data: &[u8]) -> Result<Self, KeyConversionError> {
        EcParams::from_public_secp256k1_bytes(data).map(Into::into)
    }

    pub fn from_secret_secp256k1(key: k256::SecretKey) -> Self {
        EcParams::from_secret_secp256k1(&key).into()
    }

    pub fn from_secret_secp256k1_bytes(data: &[u8]) -> Result<Self, KeyConversionError> {
        EcParams::from_secret_secp256k1_bytes(data).map(Into::into)
    }
}

impl From<k256::PublicKey> for JWK {
    fn from(value: k256::PublicKey) -> Self {
        EcParams::from(value).into()
    }
}

impl From<&k256::PublicKey> for JWK {
    fn from(value: &k256::PublicKey) -> Self {
        EcParams::from(value).into()
    }
}

impl From<k256::SecretKey> for JWK {
    fn from(value: k256::SecretKey) -> Self {
        EcParams::from(value).into()
    }
}

impl From<&k256::SecretKey> for JWK {
    fn from(value: &k256::SecretKey) -> Self {
        EcParams::from(value).into()
    }
}

impl TryFrom<JWK> for k256::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: JWK) -> Result<Self, Self::Error> {
        value
            .params
            .as_ec()
            .ok_or(KeyConversionError::Unsupported)?
            .to_public_secp256k1()
    }
}

impl TryFrom<&JWK> for k256::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: &JWK) -> Result<Self, Self::Error> {
        value
            .params
            .as_ec()
            .ok_or(KeyConversionError::Unsupported)?
            .to_public_secp256k1()
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn secp256k1_generate() {
        let _jwk = crate::JWK::generate_secp256k1();
    }
}
