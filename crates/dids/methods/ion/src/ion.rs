use ssi_jwk::{Algorithm, JWK};

use crate::sidetree::Sidetree;

#[derive(Default, Clone)]
pub struct ION;

impl Sidetree for ION {
    fn generate_key() -> JWK {
        JWK::generate_secp256k1()
    }

    fn validate_key(key: &JWK) -> bool {
        is_secp256k1(key)
    }

    const SIGNATURE_ALGORITHM: Algorithm = Algorithm::ES256K;
    const METHOD: &'static str = "ion";
    const NETWORK: Option<&'static str> = None;
}

/// Check that a JWK is Secp256k1
pub fn is_secp256k1(jwk: &JWK) -> bool {
    matches!(jwk, JWK {params: ssi_jwk::Params::EC(ssi_jwk::ECParams { curve: Some(curve), ..}), ..} if curve == "secp256k1")
}
