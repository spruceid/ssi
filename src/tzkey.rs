use crate::error::Error;
use crate::jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK};
use core::convert::TryFrom;

/// Parse a Tezos key string into a JWK.
pub fn jwk_from_tezos_key(tz_pk: &str) -> Result<JWK, Error> {
    if tz_pk.len() < 4 {
        return Err(Error::KeyPrefix);
    }
    let (alg, params) = match &tz_pk[..4] {
        "edpk" => (
            Algorithm::EdDSA,
            Params::OKP(OctetParams {
                curve: "Ed25519".into(),
                public_key: Base64urlUInt(
                    bs58::decode(&tz_pk).with_check(None).into_vec()?[4..].to_owned(),
                ),
                private_key: None,
            }),
        ),
        #[cfg(feature = "secp256k1")]
        "sppk" => {
            let pk_bytes = bs58::decode(&tz_pk).with_check(None).into_vec()?[4..].to_owned();
            let jwk =
                crate::jwk::secp256k1_parse(&pk_bytes).map_err(|e| Error::Secp256k1Parse(e))?;
            (Algorithm::ES256K, jwk.params)
        }
        #[cfg(feature = "p256")]
        "p2pk" => {
            let pk_bytes = bs58::decode(&tz_pk).with_check(None).into_vec()?[4..].to_owned();
            let jwk = crate::jwk::p256_parse(&pk_bytes)?;
            (Algorithm::PS256, jwk.params)
        }
        // TODO: secret keys?
        _ => return Err(Error::KeyPrefix),
    };
    Ok(JWK {
        public_key_use: None,
        key_operations: None,
        algorithm: Some(alg),
        key_id: None,
        x509_url: None,
        x509_certificate_chain: None,
        x509_thumbprint_sha1: None,
        x509_thumbprint_sha256: None,
        params,
    })
}

#[derive(thiserror::Error, Debug)]
pub enum SignTezosError {
    #[error("Unsupported algorithm for Tezos signing: {0:?}")]
    UnsupportedAlgorithm(Algorithm),
    #[error("Signing: {0}")]
    Sign(String),
}

pub fn sign_tezos(data: &[u8], algorithm: Algorithm, key: &JWK) -> Result<String, SignTezosError> {
    let hash = blake2b_simd::Params::new()
        .hash_length(32)
        .hash(&data)
        .as_bytes()
        .to_vec();
    let sig = crate::jws::sign_bytes(algorithm, &hash, key)
        .map_err(|e| SignTezosError::Sign(e.to_string()))?;
    let mut sig_prefixed = Vec::new();
    const EDSIG_PREFIX: [u8; 5] = [9, 245, 205, 134, 18];
    const SPSIG_PREFIX: [u8; 5] = [13, 115, 101, 19, 63];
    const P2SIG_PREFIX: [u8; 4] = [54, 240, 44, 52];
    let prefix: &[u8] = match algorithm {
        Algorithm::EdDSA => &EDSIG_PREFIX,
        Algorithm::ES256K => &SPSIG_PREFIX,
        Algorithm::ES256 => &P2SIG_PREFIX,
        alg => return Err(SignTezosError::UnsupportedAlgorithm(alg)),
    };
    sig_prefixed.extend_from_slice(&prefix);
    sig_prefixed.extend_from_slice(&sig);
    let sig_bs58 = bs58::encode(sig_prefixed).with_check().into_string();
    Ok(sig_bs58)
}

#[derive(thiserror::Error, Debug)]
pub enum EncodeTezosSignedMessageError {
    #[error("Message length conversion error: {0}")]
    Length(#[from] core::num::TryFromIntError),
}

pub fn encode_tezos_signed_message(msg: &str) -> Result<Vec<u8>, EncodeTezosSignedMessageError> {
    const BYTES_PREFIX: [u8; 2] = [05, 01];
    let msg_bytes = msg.as_bytes();
    let mut bytes = Vec::with_capacity(msg_bytes.len());
    let prefix = b"Tezos Signed Message: ";
    let msg_len = prefix.len() + msg_bytes.len();

    let len_u32 = u32::try_from(msg_len).map_err(|e| EncodeTezosSignedMessageError::Length(e))?;
    bytes.extend_from_slice(&BYTES_PREFIX);
    bytes.extend_from_slice(&len_u32.to_be_bytes());
    bytes.extend_from_slice(prefix);
    bytes.extend_from_slice(msg_bytes);
    Ok(bytes)
}

#[derive(thiserror::Error, Debug)]
pub enum DecodeTezosSignatureError {
    #[error("Expected signature length {0} but found {1}")]
    SignatureLength(usize, usize),
    #[error("Unknown signature prefix: {0}")]
    SignaturePrefix(String),
    #[error("Base58 decoding: {0}")]
    Base58(#[from] bs58::decode::Error),
}

pub fn decode_tzsig(sig_bs58: &str) -> Result<(Algorithm, Vec<u8>), DecodeTezosSignatureError> {
    let tzsig = bs58::decode(&sig_bs58).with_check(None).into_vec()?;
    if tzsig.len() < 5 {
        return Err(DecodeTezosSignatureError::SignaturePrefix(
            sig_bs58.to_string(),
        ));
    }
    let (algorithm, sig) = match &sig_bs58[0..5] {
        "edsig" => (Algorithm::EdDSA, tzsig[5..].to_vec()),
        "spsig" => (Algorithm::ES256K, tzsig[5..].to_vec()),
        "p2sig" => (Algorithm::ES256, tzsig[4..].to_vec()),
        prefix => {
            return Err(DecodeTezosSignatureError::SignaturePrefix(
                prefix.to_string(),
            ))
        }
    };
    if sig.len() != 64 {
        return Err(DecodeTezosSignatureError::SignatureLength(64, sig.len()));
    }
    Ok((algorithm, sig))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::blakesig::hash_public_key;
    use serde_json::json;

    #[test]
    fn edpk_jwk_tz_edsig() {
        let jwk =
            jwk_from_tezos_key("edpkuxZ5AQVCeEJ9inUG3w6VFhio5KBwC22ekPLBzcvub3QY2DvJ7n").unwrap();
        let jwk_expected: JWK = serde_json::from_value(json!(
            {"alg":"EdDSA","kty":"OKP","crv":"Ed25519","x":"rVEB0Icbomw1Ir-ck52iCZl1SICc5lCg2pxI8AmydDw"}
        )).unwrap();
        assert_eq!(jwk, jwk_expected);
        let hash = hash_public_key(&jwk).unwrap();
        assert_eq!(hash, "tz1TwZZZSShtM73oEr74aDtDcns3UmFqaca6");
        let tsm =
            encode_tezos_signed_message("example.org 2021-05-25T18:54:42Z Signed with Temple tz1")
                .unwrap();
        let tsm_expected_hex = "05010000004d54657a6f73205369676e6564204d6573736167653a206578616d706c652e6f726720323032312d30352d32355431383a35343a34325a205369676e656420776974682054656d706c6520747a31";
        assert_eq!(hex::encode(&tsm), tsm_expected_hex);

        let sig_bs58 = "edsigtpfAeN8PqB9dpYdzDTpbCFPFuNe6Vfo4pokAQWYzFczZCjkWtfmWH3zxsse1KbxSc2NksTfoAMJzpqCAee4PQL6gydVWyy";
        let (algorithm, sig) = decode_tzsig(sig_bs58).unwrap();
        let mut data = blake2b_simd::Params::new()
            .hash_length(32)
            .hash(&tsm)
            .as_bytes()
            .to_vec();
        crate::jws::verify_bytes(Algorithm::EdDSA, &data, &jwk, &sig).unwrap();

        // Negative test: alter signing input
        data[1] ^= 1;
        crate::jws::verify_bytes(Algorithm::EdDSA, &data, &jwk, &sig).unwrap_err();
    }

    #[ignore]
    // Signature produced by Kukai wallet but unable to verify here
    #[test]
    fn sppk_jwk_tz_spsig() {
        let jwk =
            jwk_from_tezos_key("sppk7bYNanLcEPRpvLc231GBC8i6YfLBbQjiQMbz8kriz9qxASf5wHw").unwrap();
        let jwk_expected: JWK = serde_json::from_value(json!(
            {"alg":"ES256K","kty":"EC","crv":"secp256k1","x":"JpVAlV0nDVVmPnSNdZTqes8YXoQqzyBq9R1VHWhBdgY","y":"G2jCkm3F3uu-TqtgrqCji13-MR-tlND2Tqt8rh7ZPN8"}
        )).unwrap();
        assert_eq!(jwk, jwk_expected);
        let hash = hash_public_key(&jwk).unwrap();
        assert_eq!(hash, "tz2EzZh8dhciPgTh4azWhgKCNz3HRh2ZvUhA");
        let tsm =
            encode_tezos_signed_message("example.org 2021-05-25T20:10:03Z Signed with Kukai tz2")
                .unwrap();
        let tsm_expected_hex = "05010000004c54657a6f73205369676e6564204d6573736167653a206578616d706c652e6f726720323032312d30352d32355432303a31303a30335a205369676e65642077697468204b756b616920747a32";
        assert_eq!(hex::encode(&tsm), tsm_expected_hex);

        let sig_bs58 = "spsig1TJjahaMVSCyvSBPvHJFXQ1WxASgHsygTvxgJxAWbYsv5R9nH1yzj5BEeHoqmHCogVYioVCbeKDNDwP17hMaM9foFdF8SS";
        let (algorithm, sig) = decode_tzsig(sig_bs58).unwrap();
        let mut data = blake2b_simd::Params::new()
            .hash_length(32)
            .hash(&tsm)
            .as_bytes()
            .to_vec();
        crate::jws::verify_bytes(Algorithm::ES256K, &data, &jwk, &sig).unwrap();
        data[1] ^= 1;
        crate::jws::verify_bytes(Algorithm::ES256K, &data, &jwk, &sig).unwrap_err();
    }

    #[test]
    fn edsk_sign() {
        let key: JWK =
            serde_json::from_str(include_str!("../tests/ed25519-2020-10-18.json")).unwrap();
        eprintln!("key: {:?}", key);
        let hash = hash_public_key(&key).unwrap();
        assert_eq!(hash, "tz1NcJyMQzUw7h85baBA6vwRGmpwPnM1fz83");
        let tsm = encode_tezos_signed_message("example.org 2021-05-26T18:28:26Z Signed with ssi")
            .unwrap();
        eprintln!("msg: {:?}", tsm);
        let sig = sign_tezos(&tsm, Algorithm::EdDSA, &key).unwrap();
        let sig_expected = "edsigtvvyq6uFWyeoSNZq4Jq2AvsNGZ9hHYDgt4Hzdou4FVkaBLX34tWRyL9MsapFBg3RFXReJ4bNCaAg2F1XWAMgetCLU9AACo";
        assert_eq!(sig, sig_expected);
    }

    #[test]
    #[ignore]
    // tz2/spsig not currently working
    fn spsk_sign() {
        let key: JWK = serde_json::from_value(json!({
            "alg": "ES256K",
            "kty": "EC",
            "crv": "secp256k1",
            "x": "yclqMZ0MtyVkKm1eBh2AyaUtsqT0l5RJM3g4SzRT96A",
            "y": "yQzUwKnftWCJPGs-faGaHiYi1sxA6fGJVw2Px_LCNe8",
            "d": "meTmccmR_6ZsOa2YuTTkKkJ4ZPYsKdAH1Wx_RRf2j_E"
        }))
        .unwrap();
        eprintln!("key {:?}", key);
        let hash = hash_public_key(&key).unwrap();
        assert_eq!(hash, "tz2CA2f3SWWcqbWsjHsMZPZxCY5iafSN3nDz");
        let tsm = encode_tezos_signed_message("example.org 2021-05-26T17:01:41Z Signed with ssi")
            .unwrap();
        eprintln!("msg: {:?}", tsm);
        let sig = sign_tezos(&tsm, Algorithm::ES256K, &key).unwrap();
        eprintln!("sig: {}", sig);
        todo!();
    }
}
