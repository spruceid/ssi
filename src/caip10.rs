use crate::blakesig;
use crate::jwk::JWK;
use std::str::FromStr;

use thiserror::Error;

/// https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md
#[derive(Clone, PartialEq, Hash, Debug)]
pub struct BlockchainAccountId {
    account_address: String,
    chain_id: String,
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

impl BlockchainAccountId {
    /// Check that a given JWK corresponds to this account id
    pub fn verify(&self, jwk: &JWK) -> Result<(), BlockchainAccountIdVerifyError> {
        match self.chain_id.split(':').collect::<Vec<&str>>().as_slice() {
            ["tezos", _net] => {
                let hash = blakesig::hash_public_key(&jwk)
                    .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string()))?;
                if hash != self.account_address {
                    return Err(BlockchainAccountIdVerifyError::KeyMismatch(
                        hash,
                        self.account_address.clone(),
                    ));
                }
                Ok(())
            }
            _ => Err(BlockchainAccountIdVerifyError::UnknownChainId(
                self.chain_id.clone(),
            )),
        }
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
}

impl FromStr for BlockchainAccountId {
    type Err = BlockchainAccountIdParseError;
    fn from_str(account_id: &str) -> Result<Self, Self::Err> {
        let mut account_address = String::with_capacity(63);
        let mut chain_id = String::with_capacity(64);
        let mut chars = account_id.chars();
        while let Some(c) = chars.next() {
            match c {
                'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm'
                | 'n' | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z'
                | 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'G' | 'H' | 'I' | 'J' | 'K' | 'L' | 'M'
                | 'N' | 'O' | 'P' | 'Q' | 'R' | 'S' | 'T' | 'U' | 'V' | 'W' | 'X' | 'Y' | 'Z'
                | '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' => {
                    account_address.push(c);
                }
                '@' => {
                    break;
                }
                c => {
                    return Err(BlockchainAccountIdParseError::AddressChar(c));
                }
            }
        }
        let address_len = account_address.len();
        if address_len < 1 || address_len > 63 {
            return Err(BlockchainAccountIdParseError::AddressLength(address_len));
        }
        for c in chars {
            match c {
                'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l' | 'm'
                | 'n' | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y' | 'z'
                | 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'G' | 'H' | 'I' | 'J' | 'K' | 'L' | 'M'
                | 'N' | 'O' | 'P' | 'Q' | 'R' | 'S' | 'T' | 'U' | 'V' | 'W' | 'X' | 'Y' | 'Z'
                | '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' | ':' | '-' => {
                    chain_id.push(c);
                }
                c => {
                    return Err(BlockchainAccountIdParseError::ChainChar(c));
                }
            }
        }
        let chain_len = chain_id.len();
        if chain_len < 5 || chain_len > 64 {
            return Err(BlockchainAccountIdParseError::ChainLength(chain_len));
        }
        Ok(Self {
            account_address,
            chain_id,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[async_std::test]
    async fn parse_account_id() {
        // https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md#test-cases
        let dummy_max_length = "bd57219062044ed77c7e5b865339a6d727309c548763141f11e26e9242bbd34@max-namespace-16:xip3343-8c3444cf8970a9e41a706fab93e7a6c4-xxxyyy";
        BlockchainAccountId::from_str(&dummy_max_length).unwrap();
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
            BlockchainAccountId::from_str("tz1iY7Am8EqrewptzQXYRZDPKvYnFLzWRgBK@tezos:mainnet")
                .unwrap();
        account_id.verify(&jwk).unwrap();
    }
}
