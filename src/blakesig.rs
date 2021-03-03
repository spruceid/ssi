use crate::error::Error;

use crate::jwk::{Params, JWK};

const TZ1_EDPK: [u8; 4] = [0x65, 0x64, 0x70, 0x6b];
const TZ2_SPPK: [u8; 4] = [0x73, 0x70, 0x70, 0x6b];
const TZ3_P2PK: [u8; 4] = [0x70, 0x32, 0x70, 0x6b];

const TZ1_HASH: [u8; 3] = [0x06, 0xa1, 0x9f];
const TZ2_HASH: [u8; 3] = [0x06, 0xa1, 0xa1];
const TZ3_HASH: [u8; 3] = [0x06, 0xa1, 0xa4];

fn curve_to_prefixes(curve: &str) -> Result<(&'static [u8; 4], &'static [u8; 3]), Error> {
    let prefix = match curve {
        "Ed25519" => (&TZ1_EDPK, &TZ1_HASH),
        "secp256k1" => (&TZ2_SPPK, &TZ2_HASH),
        "P-256" => (&TZ3_P2PK, &TZ3_HASH),
        _ => return Err(Error::KeyTypeNotImplemented),
    };
    Ok(prefix)
}

pub fn hash_public_key(jwk: &JWK) -> Result<String, Error> {
    let bytes;
    let (curve, public_key_bytes) = match jwk.params {
        Params::OKP(ref params) => (&params.curve, &params.public_key.0),
        Params::EC(ref params) => {
            let curve = params.curve.as_ref().ok_or(Error::MissingCurve)?;
            let x = &params.x_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
            let y = &params.y_coordinate.as_ref().ok_or(Error::MissingPoint)?.0;
            bytes = [x.as_slice(), y.as_slice()].concat();
            (curve, &bytes)
        }
        _ => return Err(Error::KeyTypeNotImplemented),
    };
    let (_, outer_prefix) = curve_to_prefixes(curve)?;
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

        // tz2
        use serde_json::json;
        let jwk: JWK = serde_json::from_value(json!({
            "kty": "EC",
            "crv": "secp256k1",
            "x": "yclqMZ0MtyVkKm1eBh2AyaUtsqT0l5RJM3g4SzRT96A",
            "y": "yQzUwKnftWCJPGs-faGaHiYi1sxA6fGJVw2Px_LCNe8",
            "d": "meTmccmR_6ZsOa2YuTTkKkJ4ZPYsKdAH1Wx_RRf2j_E"
        }))
        .unwrap();
        let hash = hash_public_key(&jwk).unwrap();
        assert_eq!(hash, "tz2A2DY3xyHHL7ZmyXKzVZJGPSbrqpLvCEYd");
    }
}
