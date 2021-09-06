use crate::error::Error;

use crate::jwk::{Params, JWK};

const TZ1_HASH: [u8; 3] = [0x06, 0xa1, 0x9f];
#[cfg(feature = "secp256k1")]
const TZ2_HASH: [u8; 3] = [0x06, 0xa1, 0xa1];
#[cfg(feature = "p256")]
const TZ3_HASH: [u8; 3] = [0x06, 0xa1, 0xa4];

pub fn hash_public_key(jwk: &JWK) -> Result<String, Error> {
    #[allow(unused)]
    let bytes: Vec<u8>;
    let (outer_prefix, public_key_bytes) = match jwk.params {
        Params::OKP(ref params) => (&TZ1_HASH, &params.public_key.0),
        Params::EC(ref params) => {
            let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
            match &curve[..] {
                #[cfg(feature = "secp256k1")]
                "secp256k1" => {
                    bytes = serialize_secp256k1(params)?;
                    (&TZ2_HASH, &bytes)
                }
                #[cfg(feature = "p256")]
                "P-256" => {
                    bytes = serialize_p256(params)?;
                    (&TZ3_HASH, &bytes)
                }
                _ => return Err(Error::CurveNotImplemented(curve.to_string())),
            }
        }
        _ => return Err(Error::KeyTypeNotImplemented),
    };
    let mut hasher = blake2b_simd::Params::new();
    hasher.hash_length(20);
    let blake2b = hasher.hash(&public_key_bytes);
    let blake2b = blake2b.as_bytes();
    let mut outer = Vec::with_capacity(20);
    outer.extend_from_slice(outer_prefix);
    outer.extend_from_slice(&blake2b);
    let encoded = bs58::encode(&outer).with_check().into_string();
    Ok(encoded)
}

#[cfg(feature = "p256")]
pub fn serialize_p256(params: &crate::jwk::ECParams) -> Result<Vec<u8>, Error> {
    use p256::elliptic_curve::{sec1::EncodedPoint, FieldBytes};
    let x = FieldBytes::<p256::NistP256>::from_slice(
        &params.x_coordinate.as_ref().ok_or(Error::MissingPoint)?.0,
    );
    let y = FieldBytes::<p256::NistP256>::from_slice(
        &params.y_coordinate.as_ref().ok_or(Error::MissingPoint)?.0,
    );
    let encoded_point: EncodedPoint<p256::NistP256> =
        EncodedPoint::from_affine_coordinates(x, y, true);
    let pk_compressed_bytes = encoded_point.to_bytes();
    Ok(pk_compressed_bytes.to_vec())
}

#[cfg(feature = "k256")]
pub fn serialize_secp256k1(params: &crate::jwk::ECParams) -> Result<Vec<u8>, Error> {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use std::convert::TryFrom;
    let pk = k256::PublicKey::try_from(params)?;
    let pk_compressed_bytes = pk.to_encoded_point(true);
    Ok(pk_compressed_bytes.as_bytes().to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn hash() {
        // tz1
        let jwk: JWK = serde_json::from_str(
            r#"{
              "crv": "Ed25519",
              "kty": "OKP",
              "x": "G80iskrv_nE69qbGLSpeOHJgmV4MKIzsy5l5iT6pCww"
            }"#,
        )
        .unwrap();
        let hash = hash_public_key(&jwk).unwrap();
        assert_eq!(hash, "tz1NcJyMQzUw7h85baBA6vwRGmpwPnM1fz83");
    }

    #[cfg(feature = "secp256k1")]
    #[test]
    fn hash_tz2() {
        use serde_json::json;
        let jwk: JWK = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": "ieabWBGH26ns_K6-aHS0RTSewO8mN2DqezH1l6fZ2QM",
            "y": "YfCj40TxBad4Fx2ag8pkUxJV0xAdCUaF6QdHvYQoNbw"
        }))
        .unwrap();
        let hash = hash_public_key(&jwk).unwrap();
        // https://github.com/murbard/pytezos/blob/master/tests/test_crypto.py#L31
        assert_eq!(hash, "tz28YZoayJjVz2bRgGeVjxE8NonMiJ3r2Wdu");
    }

    #[cfg(feature = "p256")]
    #[test]
    fn hash_tz3() {
        // tz3
        let jwk: JWK = serde_json::from_value(serde_json::json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "UmzXjEZzlGmpaM_CmFEJtOO5JBntW8yl_fM1LEQlWQ4",
            "y": "OmoZmcbUadg7dEC8bg5kXryN968CJqv2UFMUKRERZ6s"
        }))
        .unwrap();
        let hash = hash_public_key(&jwk).unwrap();
        // https://github.com/murbard/pytezos/blob/a228a67fbc94b11dd7dbc7ff0df9e996d0ff5f01tests/test_crypto.py#L34
        assert_eq!(hash, "tz3agP9LGe2cXmKQyYn6T68BHKjjktDbbSWX");
    }
}
