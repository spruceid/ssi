use crate::blakesig;
use crate::jwk::{Params, JWK};
use std::fmt;
use std::str::FromStr;

use thiserror::Error;

/// https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md
#[derive(Clone, PartialEq, Hash, Debug)]
pub struct BlockchainAccountId {
    pub account_address: String,
    pub chain_id: String,
}

#[derive(Error, Debug)]
pub enum BlockchainAccountIdVerifyError {
    #[error("Unknown chain id: {0}")]
    UnknownChainId(String),
    #[error("Error hashing public key: {0}")]
    HashError(String),
    #[error("Key does not match account id: got {0}, expected {1}")]
    KeyMismatch(String, String),
}

const ACCOUNT_ADDRESS_MIN_LENGTH: usize = 1;
const ACCOUNT_ADDRESS_MAX_LENGTH: usize = 64;
const CHAIN_ID_MIN_LENGTH: usize = 5;
const CHAIN_ID_MAX_LENGTH: usize = 41;

// convert a JWK to a base58 byte string if it is Ed25519
fn encode_ed25519(jwk: &JWK) -> Result<String, &'static str> {
    let string = match jwk.params {
        Params::OKP(ref params) if params.curve == "Ed25519" => {
            bs58::encode(&params.public_key.0).into_string()
        }
        _ => return Err("Expected Ed25519 key"),
    };
    Ok(string)
}

impl BlockchainAccountId {
    /// Check that a given JWK corresponds to this account id
    pub fn verify(&self, jwk: &JWK) -> Result<(), BlockchainAccountIdVerifyError> {
        let hash = match self.chain_id.split(':').collect::<Vec<&str>>().as_slice() {
            ["tezos", _net] => blakesig::hash_public_key(&jwk)
                .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string())),
            #[cfg(feature = "keccak-hash")]
            ["eip155", _net] => crate::keccak_hash::hash_public_key(&jwk)
                .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string())),
            ["solana"] => encode_ed25519(&jwk)
                .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string())),
            // Bitcoin
            #[cfg(feature = "ripemd160")]
            ["bip122", "000000000019d6689c085ae165831e93"] => {
                crate::ripemd::hash_public_key(&jwk, 0x00)
                    .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string()))
            }
            // Dogecoin
            #[cfg(feature = "ripemd160")]
            ["bip122", "1a91e3dace36e2be3bf030a65679fe82"] => {
                crate::ripemd::hash_public_key(&jwk, 0x1e)
                    .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string()))
            }
            _ => Err(BlockchainAccountIdVerifyError::UnknownChainId(
                self.chain_id.clone(),
            )),
        }?;
        if hash != self.account_address {
            return Err(BlockchainAccountIdVerifyError::KeyMismatch(
                hash,
                self.account_address.clone(),
            ));
        }
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum BlockchainAccountIdParseError {
    #[error("Unexpected character in account address: {0}")]
    AddressChar(char),
    #[error("Account address bad length: {0}")]
    AddressLength(usize),
    #[error("Unexpected character in chain id: {0}")]
    ChainChar(char),
    #[error("Chain id bad length: {0}")]
    ChainLength(usize),
    #[error("Missing separator between chain id and account address")]
    MissingSeparator,
}

impl FromStr for BlockchainAccountId {
    type Err = BlockchainAccountIdParseError;
    fn from_str(account_id: &str) -> Result<Self, Self::Err> {
        let is_legacy = account_id.contains('@');
        let (chain_id, account_address) = match if is_legacy {
            // https://github.com/ChainAgnostic/CAIPs/blob/0697e26/CAIPs/caip-10.md#backwards-compatibility
            account_id
                .rsplitn(2, '@')
                .map(String::from)
                .collect::<Vec<String>>()
        } else {
            account_id
                .rsplitn(2, ':')
                .map(String::from)
                .collect::<Vec<String>>()
                .into_iter()
                .rev()
                .collect::<Vec<String>>()
        }
        .as_slice()
        {
            [account_address, chain_id] => (account_address.to_owned(), chain_id.to_owned()),
            _ => return Err(BlockchainAccountIdParseError::MissingSeparator),
        };
        let chain_len = chain_id.len();
        if chain_len < CHAIN_ID_MIN_LENGTH || chain_len > CHAIN_ID_MAX_LENGTH {
            return Err(BlockchainAccountIdParseError::ChainLength(chain_len));
        }
        let address_len = account_address.len();
        if address_len < ACCOUNT_ADDRESS_MIN_LENGTH || address_len > ACCOUNT_ADDRESS_MAX_LENGTH {
            return Err(BlockchainAccountIdParseError::AddressLength(address_len));
        }
        for c in account_address.chars() {
            match c {
                'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm'
                | 'n' | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z'
                | 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'G' | 'H' | 'I' | 'J' | 'K' | 'L' | 'M'
                | 'N' | 'O' | 'P' | 'Q' | 'R' | 'S' | 'T' | 'U' | 'V' | 'W' | 'X' | 'Y' | 'Z'
                | '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' => {}
                c => {
                    return Err(BlockchainAccountIdParseError::AddressChar(c));
                }
            }
        }
        for c in chain_id.chars() {
            match c {
                'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm'
                | 'n' | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z'
                | 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'G' | 'H' | 'I' | 'J' | 'K' | 'L' | 'M'
                | 'N' | 'O' | 'P' | 'Q' | 'R' | 'S' | 'T' | 'U' | 'V' | 'W' | 'X' | 'Y' | 'Z'
                | '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | ':' | '-' => {}
                c => {
                    return Err(BlockchainAccountIdParseError::ChainChar(c));
                }
            }
        }
        Ok(Self {
            account_address,
            chain_id,
        })
    }
}

impl fmt::Display for BlockchainAccountId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.chain_id, self.account_address)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn account_id() {
        // https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md#test-cases
        let dummy_max_length = "chainstd:8c3444cf8970a9e41a706fab93e7a6c4:6d9b0b4b9994e8a6afbd3dc3ed983cd51c755afb27cd1dc7825ef59c134a39f7";
        let account_id = BlockchainAccountId::from_str(&dummy_max_length).unwrap();
        assert_eq!(account_id.to_string(), dummy_max_length);

        // Support old format, for backwards compatibility
        let old = "6d9b0b4b9994e8a6afbd3dc3ed983cd51c755afb27cd1dc7825ef59c134a39f7@chainstd:8c3444cf8970a9e41a706fab93e7a6c4";
        let account_id_old = BlockchainAccountId::from_str(&dummy_max_length).unwrap();
        assert_eq!(account_id_old.to_string(), dummy_max_length);
    }

    #[test]
    fn verify() {
        use serde_json::json;
        let jwk: JWK = serde_json::from_value(json!({
          "crv": "Ed25519",
          "kty": "OKP",
          "x": "G80iskrv_nE69qbGLSpeOHJgmV4MKIzsy5l5iT6pCww"
        }))
        .unwrap();
        let account_id =
            BlockchainAccountId::from_str("tezos:mainnet:tz1NcJyMQzUw7h85baBA6vwRGmpwPnM1fz83")
                .unwrap();
        account_id.verify(&jwk).unwrap();
    }
}
