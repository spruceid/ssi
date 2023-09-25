use core::convert::TryFrom;
use ssi_jwk::{Algorithm, Base64urlUInt, OctetParams, Params, JWK};
use ssi_jws::Error as JwsError;

const EDPK_PREFIX: [u8; 4] = [13, 15, 37, 217];
const SPPK_PREFIX: [u8; 4] = [3, 254, 226, 86];
const P2PK_PREFIX: [u8; 4] = [3, 178, 139, 127];

pub fn jwk_to_tezos_key(jwk: &JWK) -> Result<String, JwsError> {
    let mut tzkey_prefixed = Vec::new();
    let bytes;
    let (prefix, bytes) = match &jwk.params {
        Params::OKP(okp_params) if okp_params.curve == "Ed25519" => {
            if let Some(ref _sk) = okp_params.private_key {
                // TODO: edsk
                return Err(JwsError::UnsupportedAlgorithm);
            }
            (EDPK_PREFIX, &okp_params.public_key.0)
        }
        Params::EC(ec_params) if ec_params.curve == Some("secp256k1".to_string()) => {
            if let Some(ref _sk) = ec_params.ecc_private_key {
                // TODO: spsk
                return Err(JwsError::UnsupportedAlgorithm);
            }
            {
                // TODO: p2sk
                bytes = ssi_jwk::serialize_secp256k1(ec_params)?;
                (SPPK_PREFIX, &bytes)
            }
        }
        Params::EC(ec_params) if ec_params.curve == Some("P-256".to_string()) => {
            if let Some(ref _sk) = ec_params.ecc_private_key {
                return Err(JwsError::UnsupportedAlgorithm);
            }
            {
                bytes = ssi_jwk::serialize_p256(ec_params)?;
                (P2PK_PREFIX, &bytes)
            }
        }
        _ => {
            return Err(JwsError::UnsupportedAlgorithm);
        }
    };
    tzkey_prefixed.extend_from_slice(&prefix);
    tzkey_prefixed.extend_from_slice(bytes);
    let tzkey = bs58::encode(tzkey_prefixed).with_check().into_string();
    Ok(tzkey)
}

#[derive(thiserror::Error, Debug)]
pub enum DecodeTezosPkError {
    #[error("Key Prefix")]
    KeyPrefix,
    #[error(transparent)]
    B58(#[from] bs58::decode::Error),
    #[error(transparent)]
    JWK(#[from] ssi_jwk::Error),
}

/// Parse a Tezos key string into a JWK.
pub fn jwk_from_tezos_key(tz_pk: &str) -> Result<JWK, DecodeTezosPkError> {
    if tz_pk.len() < 4 {
        return Err(DecodeTezosPkError::KeyPrefix);
    }
    let (alg, params) = match tz_pk.get(..4) {
        Some("edpk") => (
            Algorithm::EdBlake2b,
            Params::OKP(OctetParams {
                curve: "Ed25519".into(),
                public_key: Base64urlUInt(
                    bs58::decode(&tz_pk).with_check(None).into_vec()?[4..].to_owned(),
                ),
                private_key: None,
            }),
        ),
        Some("edsk") => {
            let sk_bytes = bs58::decode(&tz_pk).with_check(None).into_vec()?[4..].to_owned();
            let pk_bytes;
            {
                let sk = ed25519_dalek::SigningKey::try_from(sk_bytes.as_slice())
                    .map_err(ssi_jwk::Error::from)?;
                pk_bytes = ed25519_dalek::VerifyingKey::from(&sk).as_bytes().to_vec()
            }
            (
                Algorithm::EdBlake2b,
                Params::OKP(OctetParams {
                    curve: "Ed25519".into(),
                    public_key: Base64urlUInt(pk_bytes),
                    private_key: Some(Base64urlUInt(sk_bytes)),
                }),
            )
        }
        Some("sppk") => {
            let pk_bytes = bs58::decode(&tz_pk).with_check(None).into_vec()?[4..].to_owned();
            let jwk = ssi_jwk::secp256k1_parse(&pk_bytes)?;
            (Algorithm::ESBlake2bK, jwk.params)
        }
        Some("p2pk") => {
            let pk_bytes = bs58::decode(&tz_pk).with_check(None).into_vec()?[4..].to_owned();
            let jwk = ssi_jwk::p256_parse(&pk_bytes)?;
            (Algorithm::ESBlake2b, jwk.params)
        }
        // TODO: more secret keys
        _ => return Err(DecodeTezosPkError::KeyPrefix),
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
    let sig = ssi_jws::sign_bytes(algorithm, data, key)
        .map_err(|e| SignTezosError::Sign(e.to_string()))?;
    let mut sig_prefixed = Vec::new();
    const EDSIG_PREFIX: [u8; 5] = [9, 245, 205, 134, 18];
    const SPSIG_PREFIX: [u8; 5] = [13, 115, 101, 19, 63];
    const P2SIG_PREFIX: [u8; 4] = [54, 240, 44, 52];
    let prefix: &[u8] = match algorithm {
        Algorithm::EdBlake2b => &EDSIG_PREFIX,
        Algorithm::ESBlake2bK => &SPSIG_PREFIX,
        Algorithm::ESBlake2b => &P2SIG_PREFIX,
        alg => return Err(SignTezosError::UnsupportedAlgorithm(alg)),
    };
    sig_prefixed.extend_from_slice(prefix);
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
    const BYTES_PREFIX: [u8; 2] = [0x05, 0x01];
    let msg_bytes = msg.as_bytes();
    let mut bytes = Vec::with_capacity(msg_bytes.len());
    let prefix = b"Tezos Signed Message: ";
    let msg_len = prefix.len() + msg_bytes.len();

    let len_u32 = u32::try_from(msg_len).map_err(EncodeTezosSignedMessageError::Length)?;
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
    // sig_bs58 has been checked as base58. But use the non-panicking get function anyway, for good
    // measure.
    let (algorithm, sig) = match sig_bs58.get(0..5) {
        Some("edsig") => (Algorithm::EdBlake2b, tzsig[5..].to_vec()),
        Some("spsig") => (Algorithm::ESBlake2bK, tzsig[5..].to_vec()),
        Some("p2sig") => (Algorithm::ESBlake2b, tzsig[4..].to_vec()),
        _ => {
            return Err(DecodeTezosSignatureError::SignaturePrefix(
                sig_bs58.to_string(),
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
    use serde_json::json;
    use ssi_jwk::blakesig::hash_public_key;

    #[test]
    fn test_jwk_from_tezos_key_glyph_split() {
        // Attempt to decode tzsig that would involve subslicing
        // through a char boundary.
        let bad_tzk = "xx💣️";
        jwk_from_tezos_key(bad_tzk).unwrap_err();
    }

    #[test]
    fn edpk_jwk_tz_edsig() {
        let tzpk = "edpkuxZ5AQVCeEJ9inUG3w6VFhio5KBwC22ekPLBzcvub3QY2DvJ7n";
        let jwk = jwk_from_tezos_key(tzpk).unwrap();
        assert_eq!(jwk_to_tezos_key(&jwk).unwrap(), tzpk);
        let jwk_expected: JWK = serde_json::from_value(json!(
            {"alg":"EdBlake2b","kty":"OKP","crv":"Ed25519","x":"rVEB0Icbomw1Ir-ck52iCZl1SICc5lCg2pxI8AmydDw"}
        )).unwrap();
        assert_eq!(jwk, jwk_expected);
        let hash = hash_public_key(&jwk).unwrap();
        assert_eq!(hash, "tz1TwZZZSShtM73oEr74aDtDcns3UmFqaca6");
        let mut tsm =
            encode_tezos_signed_message("example.org 2021-05-25T18:54:42Z Signed with Temple tz1")
                .unwrap();
        let tsm_expected_hex = "05010000004d54657a6f73205369676e6564204d6573736167653a206578616d706c652e6f726720323032312d30352d32355431383a35343a34325a205369676e656420776974682054656d706c6520747a31";
        assert_eq!(hex::encode(&tsm), tsm_expected_hex);

        let sig_bs58 = "edsigtpfAeN8PqB9dpYdzDTpbCFPFuNe6Vfo4pokAQWYzFczZCjkWtfmWH3zxsse1KbxSc2NksTfoAMJzpqCAee4PQL6gydVWyy";
        let (_, sig) = decode_tzsig(sig_bs58).unwrap();
        ssi_jws::verify_bytes(Algorithm::EdBlake2b, &tsm, &jwk, &sig).unwrap();

        // Negative test: alter signing input
        tsm[1] ^= 1;
        ssi_jws::verify_bytes(Algorithm::EdBlake2b, &tsm, &jwk, &sig).unwrap_err();
    }

    // Signature produced by Kukai wallet
    #[test]
    fn sppk_jwk_tz_spsig() {
        let tzpk = "sppk7bYNanLcEPRpvLc231GBC8i6YfLBbQjiQMbz8kriz9qxASf5wHw";
        let jwk = jwk_from_tezos_key(tzpk).unwrap();
        assert_eq!(jwk_to_tezos_key(&jwk).unwrap(), tzpk);
        let jwk_expected: JWK = serde_json::from_value(json!(
            {"alg":"ESBlake2bK","kty":"EC","crv":"secp256k1","x":"JpVAlV0nDVVmPnSNdZTqes8YXoQqzyBq9R1VHWhBdgY","y":"G2jCkm3F3uu-TqtgrqCji13-MR-tlND2Tqt8rh7ZPN8"}
        )).unwrap();
        assert_eq!(jwk, jwk_expected);
        let hash = hash_public_key(&jwk).unwrap();
        assert_eq!(hash, "tz2EzZh8dhciPgTh4azWhgKCNz3HRh2ZvUhA");
        let mut tsm =
            encode_tezos_signed_message("example.org 2021-05-25T20:10:03Z Signed with Kukai tz2")
                .unwrap();
        let tsm_expected_hex = "05010000004c54657a6f73205369676e6564204d6573736167653a206578616d706c652e6f726720323032312d30352d32355432303a31303a30335a205369676e65642077697468204b756b616920747a32";
        assert_eq!(hex::encode(&tsm), tsm_expected_hex);

        let sig_bs58 = "spsig1TJjahaMVSCyvSBPvHJFXQ1WxASgHsygTvxgJxAWbYsv5R9nH1yzj5BEeHoqmHCogVYioVCbeKDNDwP17hMaM9foFdF8SS";
        let (_, sig) = decode_tzsig(sig_bs58).unwrap();
        ssi_jws::verify_bytes(Algorithm::ESBlake2bK, &tsm, &jwk, &sig).unwrap();
        tsm[1] ^= 1;
        ssi_jws::verify_bytes(Algorithm::ESBlake2bK, &tsm, &jwk, &sig).unwrap_err();
    }

    #[test]
    fn p2pk_jwk() {
        let tzpk = "p2pk679D18uQNkdjpRxuBXL5CqcDKTKzsiXVtc9oCUT6xb82zQmgUks";
        let jwk = jwk_from_tezos_key(tzpk).unwrap();
        let jwk_expected: JWK = serde_json::from_value(json!(
            {"alg":"ESBlake2b","kty":"EC","crv":"P-256","x":"UmzXjEZzlGmpaM_CmFEJtOO5JBntW8yl_fM1LEQlWQ4","y":"OmoZmcbUadg7dEC8bg5kXryN968CJqv2UFMUKRERZ6s"}
        )).unwrap();
        assert_eq!(jwk, jwk_expected);
        assert_eq!(jwk_to_tezos_key(&jwk).unwrap(), tzpk);
        // TODO: verify signature made by another implementation
    }

    #[test]
    fn edsk_sign() {
        let mut key: JWK =
            serde_json::from_str(include_str!("../../tests/ed25519-2020-10-18.json")).unwrap();
        key.algorithm = Some(Algorithm::EdBlake2b);
        eprintln!("key: {:?}", key);
        let hash = hash_public_key(&key).unwrap();
        assert_eq!(hash, "tz1NcJyMQzUw7h85baBA6vwRGmpwPnM1fz83");
        let tsm = encode_tezos_signed_message("example.org 2021-05-26T18:28:26Z Signed with ssi")
            .unwrap();
        eprintln!("msg: {:?}", tsm);
        let sig = sign_tezos(&tsm, Algorithm::EdBlake2b, &key).unwrap();
        let sig_expected = "edsigtvvyq6uFWyeoSNZq4Jq2AvsNGZ9hHYDgt4Hzdou4FVkaBLX34tWRyL9MsapFBg3RFXReJ4bNCaAg2F1XWAMgetCLU9AACo";
        assert_eq!(sig, sig_expected);
    }

    #[test]
    fn spsk_sign() {
        let key: JWK = serde_json::from_value(json!({
            "alg": "ESBlake2bK",
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
        eprintln!("msg: {:x?}", tsm);
        let sig = sign_tezos(&tsm, Algorithm::ESBlake2bK, &key).unwrap();
        let sig_expected = "spsig1NRgjYaq8jeaWTMPUSsxkawWUzW1C3RoMfczWY2JAZSkNQQGM9QvCkxtRMcauJRaSUNcKgkj6WfpzLh1upXwjcfLh4wqqX";
        assert_eq!(sig, sig_expected);
    }
}
