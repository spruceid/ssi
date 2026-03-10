use std::str::FromStr;

#[derive(Debug, thiserror::Error)]
#[error("invalid network `{0}`")]
pub struct InvalidNetwork(String);

pub enum NetworkChain {
    Mainnet,
    Goerli,
    Sepolia,
    Other(u64),
}

impl NetworkChain {
    pub fn id(&self) -> u64 {
        match self {
            Self::Mainnet => 1,
            Self::Goerli => 5,
            Self::Sepolia => 11155111,
            Self::Other(i) => *i,
        }
    }
}

impl FromStr for NetworkChain {
    type Err = InvalidNetwork;

    fn from_str(network_name: &str) -> Result<Self, Self::Err> {
        match network_name {
            "mainnet" => Ok(Self::Mainnet),
            "goerli" => Ok(Self::Goerli),
            "sepolia" => Ok(Self::Sepolia),
            // Deprecated testnets — still parse for backward compatibility
            "morden" => Ok(Self::Other(2)),
            "ropsten" => Ok(Self::Other(3)),
            "rinkeby" => Ok(Self::Other(4)),
            "kovan" => Ok(Self::Other(42)),
            network_chain_id if network_chain_id.starts_with("0x") => {
                match u64::from_str_radix(&network_chain_id[2..], 16) {
                    Ok(chain_id) => Ok(Self::Other(chain_id)),
                    Err(_) => Err(InvalidNetwork(network_name.to_owned())),
                }
            }
            _ => Err(InvalidNetwork(network_name.to_owned())),
        }
    }
}

pub(crate) struct DecodedMethodSpecificId {
    pub(crate) network_name: String,
    pub(crate) network_chain: NetworkChain,
    pub(crate) address_or_public_key: String,
}

impl DecodedMethodSpecificId {
    /// Return the network name used for provider lookup
    pub(crate) fn network_name(&self) -> String {
        self.network_name.clone()
    }

    /// Extract the Ethereum address hex string (with 0x prefix).
    /// For public-key DIDs, derives the address from the public key.
    pub(crate) fn account_address_hex(&self) -> String {
        if self.address_or_public_key.len() == 42 {
            self.address_or_public_key.clone()
        } else {
            // Public key DID — derive the address
            let pk_hex = &self.address_or_public_key;
            if !pk_hex.starts_with("0x") {
                return String::new();
            }
            let pk_bytes = match hex::decode(&pk_hex[2..]) {
                Ok(b) => b,
                Err(_) => return String::new(),
            };
            let pk_jwk = match ssi_jwk::secp256k1_parse(&pk_bytes) {
                Ok(j) => j,
                Err(_) => return String::new(),
            };
            match ssi_jwk::eip155::hash_public_key_eip55(&pk_jwk) {
                Ok(addr) => addr,
                Err(_) => String::new(),
            }
        }
    }
}

impl FromStr for DecodedMethodSpecificId {
    type Err = InvalidNetwork;

    fn from_str(method_specific_id: &str) -> Result<Self, Self::Err> {
        // https://github.com/decentralized-identity/ethr-did-resolver/blob/master/doc/did-method-spec.md#method-specific-identifier
        let (network_name, address_or_public_key) = match method_specific_id.split_once(':') {
            None => ("mainnet".to_string(), method_specific_id.to_string()),
            Some((network, address_or_public_key)) => {
                (network.to_string(), address_or_public_key.to_string())
            }
        };

        Ok(DecodedMethodSpecificId {
            network_chain: network_name.parse()?,
            network_name,
            address_or_public_key,
        })
    }
}

/// Parse a hex address string (with 0x prefix) into 20 bytes
pub(crate) fn parse_address_bytes(addr_hex: &str) -> Option<[u8; 20]> {
    if !addr_hex.starts_with("0x") || addr_hex.len() != 42 {
        return None;
    }
    let bytes = hex::decode(&addr_hex[2..]).ok()?;
    if bytes.len() != 20 {
        return None;
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Some(addr)
}
