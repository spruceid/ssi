use anyhow::{ensure, Context, Error, Result};
use ssi::jwk::{Algorithm, JWK};

pub mod sidetree;

use sidetree::{is_secp256k1, Sidetree, SidetreeClient};

pub struct ION;

/// did:ion Method
pub type DIDION = SidetreeClient<ION>;

impl Sidetree for ION {
    fn generate_key() -> Result<JWK, Error> {
        JWK::generate_secp256k1().context("Generate secp256k1 key")
    }

    fn validate_key(key: &JWK) -> Result<(), Error> {
        ensure!(is_secp256k1(&key), "Key must be Secp256k1 for ION");
        Ok(())
    }

    const SIGNATURE_ALGORITHM: Algorithm = Algorithm::ES256K;
    const METHOD: &'static str = "ion";
    const NETWORK: Option<&'static str> = Some("test");
}
