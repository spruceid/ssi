use crate::{Base64urlUInt, ECParams, Error, Params, JWK};

pub fn p384_parse(pk_bytes: &[u8]) -> Result<JWK, Error> {
    let pk = p384::PublicKey::from_sec1_bytes(pk_bytes)?;
    let jwk = JWK {
        params: Params::EC(ECParams::from(&pk)),
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
    };
    Ok(jwk)
}

pub fn p384_parse_private(data: &[u8]) -> Result<JWK, Error> {
    let k = p384::SecretKey::from_bytes(data.into())?;
    let jwk = JWK {
        params: Params::EC(ECParams::from(&k)),
        public_key_use: None,
        key_operations: None,
        algorithm: None,
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
    };
    Ok(jwk)
}

/// Serialize a P-384 public key as a 49-byte string with point compression.
pub fn serialize_p384(params: &ECParams) -> Result<Vec<u8>, Error> {
    // TODO: check that curve is P-384
    use p384::elliptic_curve::{sec1::EncodedPoint, FieldBytes};
    let x = FieldBytes::<p384::NistP384>::from_slice(
        &params.x_coordinate.as_ref().ok_or(Error::MissingPoint)?.0,
    );
    let y = FieldBytes::<p384::NistP384>::from_slice(
        &params.y_coordinate.as_ref().ok_or(Error::MissingPoint)?.0,
    );
    let encoded_point = EncodedPoint::<p384::NistP384>::from_affine_coordinates(x, y, true);
    let pk_compressed_bytes = encoded_point.to_bytes();
    Ok(pk_compressed_bytes.to_vec())
}

impl JWK {
    pub fn generate_p384() -> JWK {
        let mut rng = rand::rngs::OsRng {};
        let secret_key = p384::SecretKey::random(&mut rng);
        let sk_bytes = zeroize::Zeroizing::new(secret_key.to_bytes().to_vec());
        let public_key: p384::PublicKey = secret_key.public_key();
        let mut ec_params = ECParams::from(&public_key);
        ec_params.ecc_private_key = Some(Base64urlUInt(sk_bytes.to_vec()));
        JWK::from(Params::EC(ec_params))
    }
}

impl From<p384::PublicKey> for JWK {
    fn from(value: p384::PublicKey) -> Self {
        JWK {
            params: Params::EC(ECParams::from(&value)),
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        }
    }
}

impl TryFrom<&ECParams> for p384::SecretKey {
    type Error = Error;
    fn try_from(params: &ECParams) -> Result<Self, Self::Error> {
        let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
        if curve != "P-384" {
            return Err(Error::CurveNotImplemented(curve.to_string()));
        }
        let private_key = params
            .ecc_private_key
            .as_ref()
            .ok_or(Error::MissingPrivateKey)?;
        let secret_key = p384::SecretKey::from_bytes(private_key.0.as_slice().into())?;
        Ok(secret_key)
    }
}

impl TryFrom<&ECParams> for p384::PublicKey {
    type Error = Error;
    fn try_from(params: &ECParams) -> Result<Self, Self::Error> {
        let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
        if curve != "P-384" {
            return Err(Error::CurveNotImplemented(curve.to_string()));
        }
        const EC_UNCOMPRESSED_POINT_TAG: &[u8] = &[0x04];
        let x = &params.x_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
        let y = &params.y_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
        let pk_data = [EC_UNCOMPRESSED_POINT_TAG, x.as_slice(), y.as_slice()].concat();
        let public_key = p384::PublicKey::from_sec1_bytes(&pk_data)?;
        Ok(public_key)
    }
}

impl From<&p384::PublicKey> for ECParams {
    fn from(pk: &p384::PublicKey) -> Self {
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let encoded_point = pk.to_encoded_point(false);
        ECParams {
            curve: Some("P-384".to_string()),
            x_coordinate: encoded_point.x().map(|x| Base64urlUInt(x.to_vec())),
            y_coordinate: encoded_point.y().map(|y| Base64urlUInt(y.to_vec())),
            ecc_private_key: None,
        }
    }
}

impl From<&p384::SecretKey> for ECParams {
    fn from(k: &p384::SecretKey) -> Self {
        let pk = k.public_key();
        use p384::elliptic_curve::sec1::ToEncodedPoint;
        let encoded_point = pk.to_encoded_point(false);
        ECParams {
            curve: Some("P-384".to_string()),
            x_coordinate: encoded_point.x().map(|x| Base64urlUInt(x.to_vec())),
            y_coordinate: encoded_point.y().map(|y| Base64urlUInt(y.to_vec())),
            ecc_private_key: Some(Base64urlUInt(k.to_bytes().to_vec())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::JWK;

    #[test]
    fn p384_generate() {
        let _jwk = JWK::generate_p384();
    }
}
