use crate::{Base64urlUInt, ECParams, Error, Params, JWK};

pub fn secp256k1_parse(data: &[u8]) -> Result<JWK, Error> {
    let pk = k256::PublicKey::from_sec1_bytes(data)?;
    Ok(pk.into())
}

pub fn secp256k1_parse_private(data: &[u8]) -> Result<JWK, Error> {
    let k = k256::SecretKey::from_sec1_der(data)?;
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

/// Serialize a secp256k1 public key as a 33-byte string with point compression.
pub fn serialize_secp256k1(params: &ECParams) -> Result<Vec<u8>, Error> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    let pk = k256::PublicKey::try_from(params)?;
    let pk_compressed_bytes = pk.to_encoded_point(true);
    Ok(pk_compressed_bytes.as_bytes().to_vec())
}

impl JWK {
    pub fn generate_secp256k1() -> JWK {
        let mut rng = rand::rngs::OsRng {};
        Self::generate_secp256k1_from(&mut rng)
    }

    pub fn generate_secp256k1_from(rng: &mut (impl rand::CryptoRng + rand::RngCore)) -> JWK {
        let secret_key = k256::SecretKey::random(rng);
        let sk_bytes = zeroize::Zeroizing::new(secret_key.to_bytes().to_vec());
        let public_key = secret_key.public_key();
        let mut ec_params = ECParams::from(&public_key);
        ec_params.ecc_private_key = Some(Base64urlUInt(sk_bytes.to_vec()));
        JWK::from(Params::EC(ec_params))
    }
}

impl From<k256::PublicKey> for JWK {
    fn from(value: k256::PublicKey) -> Self {
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

impl TryFrom<&ECParams> for k256::SecretKey {
    type Error = Error;
    fn try_from(params: &ECParams) -> Result<Self, Self::Error> {
        let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
        if curve != "secp256k1" {
            return Err(Error::CurveNotImplemented(curve.to_string()));
        }
        let private_key = params
            .ecc_private_key
            .as_ref()
            .ok_or(Error::MissingPrivateKey)?;
        let secret_key = k256::SecretKey::from_bytes(private_key.0.as_slice().into())?;
        Ok(secret_key)
    }
}

impl TryFrom<&ECParams> for k256::PublicKey {
    type Error = Error;
    fn try_from(params: &ECParams) -> Result<Self, Self::Error> {
        let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
        if curve != "secp256k1" {
            return Err(Error::CurveNotImplemented(curve.to_string()));
        }
        const EC_UNCOMPRESSED_POINT_TAG: &[u8] = &[0x04];
        let x = &params.x_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
        let y = &params.y_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
        let pk_data = [EC_UNCOMPRESSED_POINT_TAG, x.as_slice(), y.as_slice()].concat();
        let public_key = k256::PublicKey::from_sec1_bytes(&pk_data)?;
        Ok(public_key)
    }
}

impl From<&k256::PublicKey> for ECParams {
    fn from(pk: &k256::PublicKey) -> Self {
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let ec_points = pk.to_encoded_point(false);
        ECParams {
            // TODO according to https://tools.ietf.org/id/draft-jones-webauthn-secp256k1-00.html#rfc.section.2 it should be P-256K?
            curve: Some("secp256k1".to_string()),
            x_coordinate: ec_points.x().map(|x| Base64urlUInt(x.to_vec())),
            y_coordinate: ec_points.y().map(|y| Base64urlUInt(y.to_vec())),
            ecc_private_key: None,
        }
    }
}

impl From<&k256::SecretKey> for ECParams {
    fn from(k: &k256::SecretKey) -> Self {
        let pk = k.public_key();
        use k256::elliptic_curve::sec1::ToEncodedPoint;
        let ec_points = pk.to_encoded_point(false);
        ECParams {
            // TODO according to https://tools.ietf.org/id/draft-jones-webauthn-secp256k1-00.html#rfc.section.2 it should be P-256K?
            curve: Some("secp256k1".to_string()),
            x_coordinate: ec_points.x().map(|x| Base64urlUInt(x.to_vec())),
            y_coordinate: ec_points.y().map(|y| Base64urlUInt(y.to_vec())),
            ecc_private_key: Some(Base64urlUInt(k.to_bytes().to_vec())),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::JWK;

    #[test]
    fn secp256k1_generate() {
        let _jwk = JWK::generate_secp256k1();
    }
}
