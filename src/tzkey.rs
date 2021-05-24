use crate::error::Error;
use crate::jwk::{Algorithm, Base64urlUInt, ECParams, OctetParams, Params, JWK};

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
        #[cfg(feature = "k256")]
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn edpk_to_jwk() {
        let jwk =
            jwk_from_tezos_key("edpkuxZ5AQVCeEJ9inUG3w6VFhio5KBwC22ekPLBzcvub3QY2DvJ7n").unwrap();
        let jwk_expected: JWK = serde_json::from_value(json!(
            {"alg":"EdDSA","kty":"OKP","crv":"Ed25519","x":"rVEB0Icbomw1Ir-ck52iCZl1SICc5lCg2pxI8AmydDw"}
        )).unwrap();
        assert_eq!(jwk, jwk_expected);
    }
}
