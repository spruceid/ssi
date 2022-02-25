use anyhow::{anyhow, Context, Result};
use ssi::jwk::{Algorithm, JWK};

pub mod sidetree;

use sidetree::{is_secp256k1, Sidetree, SidetreeClient, SidetreeError};

pub struct ION;

/// did:ion Method
pub type DIDION = SidetreeClient<ION>;

impl Sidetree for ION {
    fn generate_key() -> Result<JWK, SidetreeError> {
        let key = JWK::generate_secp256k1().context("Generate secp256k1 key")?;
        Ok(key)
    }

    fn validate_key(key: &JWK) -> Result<(), SidetreeError> {
        if !is_secp256k1(&key) {
            return Err(anyhow!("Key must be Secp256k1").into());
        }
        Ok(())
    }

    const SIGNATURE_ALGORITHM: Algorithm = Algorithm::ES256K;
    const METHOD: &'static str = "ion";
    const NETWORK: Option<&'static str> = Some("test");
}
