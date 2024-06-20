use ssi_jwk::{Params, JWK};

use super::BlockchainAccountIdType;

// convert a JWK to a Aleo account address string if it looks like an Aleo key
pub(crate) fn encode_aleo_address(jwk: &JWK, network_id: &str) -> Result<String, &'static str> {
    if network_id != "1" {
        return Err("Unexpected Aleo network id");
    }
    let params = match jwk.params {
        Params::OKP(ref params) if params.curve == ssi_jwk::aleo::OKP_CURVE => params,
        _ => return Err("Invalid public key type for Aleo"),
    };

    use bech32::ToBase32;
    let address = bech32::encode(
        "aleo",
        params.public_key.0.to_base32(),
        bech32::Variant::Bech32m,
    )
    .map_err(|_| "Unable to encode Aleo account address")?;

    Ok(address)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Aleo;

impl BlockchainAccountIdType for Aleo {
    const NAMESPACE: &'static str = "aleo";

    const REFERENCE: &'static str = "1";
}

pub type AleoBlockchainAccountId = super::TypedBlockchainAccountId<Aleo>;
