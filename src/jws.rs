use crate::error::Error;
use crate::jwk::{Algorithm, Base64urlUInt, Params as JWKParams, JWK};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::convert::TryFrom;

// RFC 7515 - JSON Web Signature (JWS)
// RFC 7797 - JSON Web Signature (JWS) Unencoded Payload Option

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Default)]
pub struct Header {
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "jku")]
    pub jwk_set_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<JWK>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "kid")]
    pub key_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5u")]
    pub x509_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5c")]
    pub x509_certificate_chain: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t")]
    pub x509_thumbprint_sha1: Option<Base64urlUInt>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t#S256")]
    pub x509_thumbprint_sha256: Option<Base64urlUInt>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "typ")]
    pub type_: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cty")]
    pub content_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "crit")]
    pub critical: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "b64")]
    pub base64urlencode_payload: Option<bool>,

    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(flatten)]
    pub additional_parameters: BTreeMap<String, serde_json::Value>,
}

fn base64_encode_json<T: Serialize>(object: &T) -> Result<String, Error> {
    let json = serde_json::to_string(&object)?;
    Ok(base64::encode_config(json, base64::URL_SAFE_NO_PAD))
}

pub fn sign_bytes(algorithm: Algorithm, data: &[u8], key: &JWK) -> Result<Vec<u8>, Error> {
    let signature = match &key.params {
        #[cfg(feature = "ring")]
        JWKParams::RSA(rsa_params) => {
            let key_pair = ring::signature::RsaKeyPair::try_from(rsa_params)?;
            let padding_alg = match algorithm {
                Algorithm::RS256 => &ring::signature::RSA_PKCS1_SHA256,
                _ => return Err(Error::AlgorithmNotImplemented),
            };
            let mut sig = vec![0u8; key_pair.public_modulus_len()];
            let rng = ring::rand::SystemRandom::new();
            key_pair.sign(padding_alg, &rng, data, &mut sig)?;
            sig
        }
        #[cfg(feature = "rsa")]
        JWKParams::RSA(rsa_params) => {
            let private_key = rsa::RSAPrivateKey::try_from(rsa_params)?;
            let padding;
            let hashed;
            match algorithm {
                Algorithm::RS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    padding = rsa::padding::PaddingScheme::new_pkcs1v15_sign(Some(hash));
                    hashed = crate::hash::sha256(data)?;
                }
                _ => return Err(Error::AlgorithmNotImplemented),
            }
            private_key.sign(padding, &hashed)?
        }
        #[cfg(feature = "ring")]
        JWKParams::OKP(okp) => {
            if algorithm != Algorithm::EdDSA {
                return Err(Error::UnsupportedAlgorithm);
            }
            if okp.curve != *"Ed25519" {
                return Err(Error::CurveNotImplemented(okp.curve.to_string()));
            }
            let key_pair = ring::signature::Ed25519KeyPair::try_from(okp)?;
            key_pair.sign(data).as_ref().to_vec()
        }
        // TODO: SymmetricParams
        #[cfg(feature = "ed25519-dalek")]
        JWKParams::OKP(okp) => {
            if algorithm != Algorithm::EdDSA {
                return Err(Error::UnsupportedAlgorithm);
            }
            if okp.curve != *"Ed25519" {
                return Err(Error::CurveNotImplemented(okp.curve.to_string()));
            }
            let keypair = ed25519_dalek::Keypair::try_from(okp)?;
            use ed25519_dalek::Signer;
            keypair.sign(data).to_bytes().to_vec()
        }
        #[allow(unused)]
        JWKParams::EC(ec) => match algorithm {
            #[cfg(feature = "p256")]
            Algorithm::ES256 => {
                use p256::ecdsa::signature::{Signature, Signer};
                let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                if curve != "P-256" {
                    return Err(Error::CurveNotImplemented(curve.to_string()));
                }
                let secret_key = p256::SecretKey::try_from(ec)?;
                let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                let hashed = crate::hash::sha256(data)?;
                let sig = signing_key.try_sign(&hashed)?;
                sig.as_bytes().to_vec()
            }
            #[cfg(feature = "libsecp256k1")]
            Algorithm::ES256K | Algorithm::ES256KR => {
                let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                if curve != "secp256k1" {
                    return Err(Error::CurveNotImplemented(curve.to_string()));
                }
                let secret_key = secp256k1::SecretKey::try_from(ec)?;
                let hashed = crate::hash::sha256(data)?;
                let msg = secp256k1::Message::parse_slice(&hashed)?;
                let (sig, rec_id) = secp256k1::sign(&msg, &secret_key);
                let mut sig = sig.serialize().to_vec();
                if algorithm == Algorithm::ES256KR {
                    sig.push(rec_id.serialize());
                }
                sig
            }
            _ => {
                return Err(Error::UnsupportedAlgorithm);
            }
        },
        _ => return Err(Error::KeyTypeNotImplemented),
    };
    Ok(signature)
}

pub fn sign_bytes_b64(algorithm: Algorithm, data: &[u8], key: &JWK) -> Result<String, Error> {
    let signature = sign_bytes(algorithm, data, key)?;
    let sig_b64 = base64::encode_config(signature, base64::URL_SAFE_NO_PAD);
    Ok(sig_b64)
}

pub fn verify_bytes(
    algorithm: Algorithm,
    data: &[u8],
    key: &JWK,
    signature: &[u8],
) -> Result<(), Error> {
    if let Some(key_algorithm) = key.algorithm {
        if key_algorithm != algorithm {
            return Err(Error::AlgorithmMismatch);
        }
    }
    match &key.params {
        #[cfg(feature = "ring")]
        JWKParams::RSA(rsa_params) => {
            use ring::signature::RsaPublicKeyComponents;
            let public_key = RsaPublicKeyComponents::try_from(rsa_params)?;
            let parameters = match algorithm {
                Algorithm::RS256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                _ => return Err(Error::AlgorithmNotImplemented),
            };
            public_key.verify(parameters, data, signature)?
        }
        #[cfg(feature = "rsa")]
        JWKParams::RSA(rsa_params) => {
            use rsa::PublicKey;
            let public_key = rsa::RSAPublicKey::try_from(rsa_params)?;
            let padding;
            let hashed;
            match algorithm {
                Algorithm::RS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    padding = rsa::padding::PaddingScheme::new_pkcs1v15_sign(Some(hash));
                    hashed = crate::hash::sha256(data)?;
                }
                _ => return Err(Error::AlgorithmNotImplemented),
            }
            public_key.verify(padding, &hashed, signature)?;
        }
        // TODO: SymmetricParams
        #[cfg(feature = "ring")]
        JWKParams::OKP(okp) => {
            use ring::signature::UnparsedPublicKey;
            if okp.curve != *"Ed25519" {
                return Err(Error::CurveNotImplemented(okp.curve.to_string()));
            }
            let verification_algorithm = &ring::signature::ED25519;
            let public_key = UnparsedPublicKey::new(verification_algorithm, &okp.public_key.0);
            public_key.verify(data, signature)?;
        }
        #[cfg(feature = "ed25519-dalek")]
        JWKParams::OKP(okp) => {
            use ed25519_dalek::ed25519::signature::Signature;
            if okp.curve != *"Ed25519" {
                return Err(Error::CurveNotImplemented(okp.curve.to_string()));
            }
            let public_key = ed25519_dalek::PublicKey::try_from(okp)?;
            let signature = ed25519_dalek::Signature::from_bytes(signature)?;
            use ed25519_dalek::Verifier;
            public_key.verify(data, &signature)?;
        }
        #[allow(unused)]
        JWKParams::EC(ec) => match algorithm {
            #[cfg(feature = "p256")]
            Algorithm::ES256 => {
                use p256::ecdsa::signature::{Signature, Verifier};
                let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                if curve != "P-256" {
                    return Err(Error::CurveNotImplemented(curve.to_string()));
                }
                let public_key = p256::PublicKey::try_from(ec)?;
                let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
                let sig = Signature::from_bytes(signature)?;
                let hashed = crate::hash::sha256(data)?;
                verifying_key.verify(&hashed, &sig)?;
            }
            #[cfg(feature = "libsecp256k1")]
            Algorithm::ES256K | Algorithm::ES256KR => {
                let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                if curve != "secp256k1" {
                    return Err(Error::CurveNotImplemented(curve.to_string()));
                }
                let hashed = crate::hash::sha256(data)?;
                let msg = secp256k1::Message::parse_slice(&hashed)?;
                let signature = if algorithm == Algorithm::ES256KR && signature.len() == 65 {
                    // Drop recovery byte
                    &signature[0..64]
                } else {
                    signature
                };
                let sig = secp256k1::Signature::parse_slice(&signature)?;
                let public_key = secp256k1::PublicKey::try_from(ec)?;
                let ok = secp256k1::verify(&msg, &sig, &public_key);
                if !ok {
                    Err(secp256k1::Error::InvalidSignature)?;
                }
            }
            _ => {
                return Err(Error::UnsupportedAlgorithm);
            }
        },
        _ => return Err(Error::KeyTypeNotImplemented),
    }
    Ok(())
}

/// Recover a key from a signature and message, if the algorithm supports this.  (e.g.
/// [ES256K-R](https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r))
pub fn recover(algorithm: Algorithm, data: &[u8], signature: &[u8]) -> Result<JWK, Error> {
    match algorithm {
        #[cfg(feature = "libsecp256k1")]
        Algorithm::ES256KR => {
            let hashed = crate::hash::sha256(data)?;
            let msg = secp256k1::Message::parse_slice(&hashed)?;
            let (rec_byte, sig_bytes) = signature.split_last().ok_or(Error::InvalidSignature)?;
            let rec_id = secp256k1::RecoveryId::parse(*rec_byte)?;
            let sig = secp256k1::Signature::parse_slice(sig_bytes)?;
            let public_key = secp256k1::recover(&msg, &sig, &rec_id)?;
            // Is it redundant to verify after recover?
            let ok = secp256k1::verify(&msg, &sig, &public_key);
            if !ok {
                Err(secp256k1::Error::InvalidSignature)?;
            }
            use crate::jwk::ECParams;
            let jwk = JWK {
                params: JWKParams::EC(ECParams::try_from(&public_key)?),
                public_key_use: None,
                key_operations: None,
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_certificate_chain: None,
                x509_thumbprint_sha1: None,
                x509_thumbprint_sha256: None,
            };
            return Ok(jwk);
        }
        _ => {
            let _ = data;
            let _ = signature;
            return Err(Error::UnsupportedAlgorithm);
        }
    }
}

pub fn detached_sign_unencoded_payload(
    algorithm: Algorithm,
    payload: &[u8],
    key: &JWK,
) -> Result<String, Error> {
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        critical: Some(vec!["b64".to_string()]),
        base64urlencode_payload: Some(false),
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let signing_input = [header_b64.as_bytes(), b".", payload].concat();
    let sig_b64 = sign_bytes_b64(header.algorithm, &signing_input, key)?;
    let jws = header_b64 + ".." + &sig_b64;
    Ok(jws)
}

pub fn prepare_detached_unencoded_payload(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<(Header, Vec<u8>), Error> {
    let header = Header {
        algorithm,
        critical: Some(vec!["b64".to_string()]),
        base64urlencode_payload: Some(false),
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let signing_input = [header_b64.as_bytes(), b".", payload].concat().to_vec();
    Ok((header, signing_input))
}

pub fn complete_sign_unencoded_payload(header: Header, sig_b64: &str) -> Result<String, Error> {
    let header_b64 = base64_encode_json(&header)?;
    let jws = header_b64 + ".." + sig_b64;
    Ok(jws)
}

pub fn encode_sign(algorithm: Algorithm, payload: &str, key: &JWK) -> Result<String, Error> {
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
    let signing_input = header_b64 + "." + &payload_b64;
    let sig_b64 = sign_bytes_b64(algorithm, signing_input.as_bytes(), key)?;
    let jws = [signing_input, sig_b64].join(".");
    Ok(jws)
}

pub fn encode_unsigned(payload: &str) -> Result<String, Error> {
    let header = Header {
        algorithm: Algorithm::None,
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let payload_b64 = base64::encode_config(payload, base64::URL_SAFE_NO_PAD);
    Ok(header_b64 + "." + &payload_b64 + ".")
}

fn split_jws(jws: &str) -> Result<(&str, &str, &str), Error> {
    let mut parts = jws.splitn(3, '.');
    Ok(
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), Some(c), None) => (a, b, c),
            _ => return Err(Error::InvalidJWS),
        },
    )
}

struct DecodedJWS {
    header: Header,
    signing_input: Vec<u8>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

fn decode_jws_parts(
    header_b64: &str,
    payload_enc: &[u8],
    signature_b64: &str,
) -> Result<DecodedJWS, Error> {
    let signature = base64::decode_config(signature_b64, base64::URL_SAFE_NO_PAD)?;
    let header_json = base64::decode_config(header_b64, base64::URL_SAFE_NO_PAD)?;
    let header: Header = serde_json::from_slice(&header_json)?;
    let payload_vec;
    let payload = if header.base64urlencode_payload.unwrap_or(true) {
        payload_vec = base64::decode_config(payload_enc, base64::URL_SAFE_NO_PAD)?;
        payload_vec.as_slice()
    } else {
        payload_enc
    };
    for name in header.critical.iter().flatten() {
        match name.as_str() {
            "alg" | "jku" | "jwk" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "typ" | "cty"
            | "crit" => return Err(Error::InvalidCriticalHeader),
            "b64" => {}
            _ => return Err(Error::UnknownCriticalHeader),
        }
    }
    let signing_input = [header_b64.as_bytes(), b".", payload_enc].concat();
    Ok(DecodedJWS {
        header,
        signing_input,
        payload: payload.to_vec(),
        signature,
    })
}

/// Verify a JWS with detached payload. Returns the JWS header on success.
pub fn detached_verify(jws: &str, payload_enc: &[u8], key: &JWK) -> Result<Header, Error> {
    let (header_b64, omitted_payload, signature_b64) = split_jws(jws)?;
    if !omitted_payload.is_empty() {
        return Err(Error::InvalidJWS);
    }
    let DecodedJWS {
        header,
        signing_input,
        payload: _,
        signature,
    } = decode_jws_parts(header_b64, payload_enc, signature_b64)?;
    verify_bytes(header.algorithm, &signing_input, key, &signature)?;
    Ok(header)
}

/// Recover a JWK from a JWS and payload, if the algorithm supports that (such as [ES256K-R](https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r)).
pub fn detached_recover(jws: &str, payload_enc: &[u8]) -> Result<(Header, JWK), Error> {
    let (header_b64, omitted_payload, signature_b64) = split_jws(jws)?;
    if !omitted_payload.is_empty() {
        return Err(Error::InvalidJWS);
    }
    let DecodedJWS {
        header,
        signing_input,
        payload: _,
        signature,
    } = decode_jws_parts(header_b64, payload_enc, signature_b64)?;
    let key = recover(header.algorithm, &signing_input, &signature)?;
    Ok((header, key))
}

pub fn decode_verify(jws: &str, key: &JWK) -> Result<(Header, Vec<u8>), Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;
    let DecodedJWS {
        header,
        signing_input,
        payload,
        signature,
    } = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?;
    verify_bytes(header.algorithm, &signing_input, key, &signature)?;
    Ok((header, payload))
}

pub fn decode_unverified(jws: &str) -> Result<(Header, Vec<u8>), Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;
    let DecodedJWS {
        header,
        signing_input: _,
        payload,
        signature: _,
    } = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?;
    Ok((header, payload))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn jws_encode() {
        // https://tools.ietf.org/html/rfc7515#appendix-A.2
        let payload =
            "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

        use serde_json::json;
        // https://tools.ietf.org/html/rfc7515#page-41
        let key: JWK = serde_json::from_value(json!({"kty":"RSA",
         "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
         "e":"AQAB",
         "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
         "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc", "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
         "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
         "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
         "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
        }))
        .unwrap();

        // https://tools.ietf.org/html/rfc7515#page-43
        let jws = encode_sign(Algorithm::RS256, payload, &key).unwrap();
        assert_eq!(jws, "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw");

        decode_verify(&jws, &key).unwrap();
    }

    #[test]
    #[cfg(feature = "libsecp256k1")]
    fn secp256k1_sign_verify() {
        let key = JWK::generate_secp256k1().unwrap();
        let data = b"asdf";
        let sig = sign_bytes(Algorithm::ES256K, data, &key).unwrap();
        verify_bytes(Algorithm::ES256K, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256K, b"no", &key, &sig).unwrap_err();

        // ES256K-R
        let key = JWK {
            algorithm: Some(Algorithm::ES256KR),
            ..key
        };
        verify_bytes(Algorithm::ES256KR, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256KR, b"no", &key, &sig).unwrap_err();

        // Test recovery
        let sig = sign_bytes(Algorithm::ES256KR, data, &key).unwrap();
        verify_bytes(Algorithm::ES256KR, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256KR, b"nope", &key, &sig).unwrap_err();
        let recovered_key = recover(Algorithm::ES256KR, data, &sig).unwrap();
        verify_bytes(Algorithm::ES256KR, data, &recovered_key, &sig).unwrap();
        let other_key = JWK::generate_secp256k1().unwrap();
        verify_bytes(Algorithm::ES256KR, data, &other_key, &sig).unwrap_err();
    }

    #[test]
    #[cfg(feature = "p256")]
    fn p256_sign_verify() {
        let key = JWK::generate_p256().unwrap();
        let data = b"asdf";
        let sig = sign_bytes(Algorithm::ES256, data, &key).unwrap();
        verify_bytes(Algorithm::ES256, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256, b"no", &key, &sig).unwrap_err();
    }
}
