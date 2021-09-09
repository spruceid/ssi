use std::fmt;
use std::str::FromStr;

use thiserror::Error;

/// <https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md>
#[derive(Clone, PartialEq, Hash, Debug)]
pub struct ChainId {
    pub namespace: String,
    pub reference: String,
}

const NAMESPACE_MIN_LENGTH: usize = 3;
const NAMESPACE_MAX_LENGTH: usize = 8;
const REFERENCE_MIN_LENGTH: usize = 1;
const REFERENCE_MAX_LENGTH: usize = 32;

#[derive(Error, Debug)]
pub enum ChainIdParseError {
    #[error("Unexpected character in namesapce: {0}")]
    NamespaceChar(char),
    #[error("Namespace too long")]
    NamespaceTooLong,
    #[error("Namespace too long")]
    NamespaceTooShort,
    #[error("Unexpected character in reference: {0}")]
    ReferenceChar(char),
    #[error("Reference too long")]
    ReferenceTooLong,
    #[error("Reference too short")]
    ReferenceTooShort,
    #[error("Missing separator between namespace and reference")]
    MissingSeparator,
}

impl FromStr for ChainId {
    type Err = ChainIdParseError;
    fn from_str(chain_id: &str) -> Result<Self, Self::Err> {
        // namespace:   [-a-z0-9]{3,8}
        let mut namespace = String::with_capacity(NAMESPACE_MAX_LENGTH);
        // reference:   [-a-zA-Z0-9]{1,32}
        let mut reference = String::with_capacity(REFERENCE_MAX_LENGTH);
        let mut chars = chain_id.chars();
        let mut separated = false;
        while let Some(c) = chars.next() {
            match c {
                '-' | 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l'
                | 'm' | 'n' | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y'
                | 'z' | '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' => {
                    if namespace.len() >= NAMESPACE_MAX_LENGTH {
                        return Err(ChainIdParseError::NamespaceTooLong);
                    }
                    namespace.push(c);
                }
                ':' => {
                    separated = true;
                    break;
                }
                c => return Err(ChainIdParseError::NamespaceChar(c)),
            }
        }
        if namespace.len() < NAMESPACE_MIN_LENGTH {
            return Err(ChainIdParseError::NamespaceTooShort);
        }
        if !separated {
            // Allow use of deprecated/invalid pre-CAIP-30 Solana
            if namespace != "solana" {
                return Err(ChainIdParseError::MissingSeparator);
            }
        }

        for c in chars {
            match c {
                '-' | 'a' | 'b' | 'c' | 'd' | 'e' | 'f' | 'g' | 'h' | 'i' | 'j' | 'k' | 'l'
                | 'm' | 'n' | 'o' | 'p' | 'q' | 'r' | 's' | 't' | 'u' | 'v' | 'w' | 'x' | 'y'
                | 'z' | 'A' | 'B' | 'C' | 'D' | 'E' | 'F' | 'G' | 'H' | 'I' | 'J' | 'K' | 'L'
                | 'M' | 'N' | 'O' | 'P' | 'Q' | 'R' | 'S' | 'T' | 'U' | 'V' | 'W' | 'X' | 'Y'
                | 'Z' | '0' | '1' | '2' | '3' | '4' | '5' | '6' | '7' | '8' | '9' => {
                    if reference.len() >= REFERENCE_MAX_LENGTH {
                        return Err(ChainIdParseError::ReferenceTooLong);
                    }
                    reference.push(c);
                }
                c => return Err(ChainIdParseError::NamespaceChar(c)),
            }
        }
        if reference.len() < REFERENCE_MIN_LENGTH {
            return Err(ChainIdParseError::ReferenceTooShort);
        }

        Ok(Self {
            namespace,
            reference,
        })
    }
}

impl fmt::Display for ChainId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.namespace == "solana" && self.reference == "" {
            // Special case for backwards-compatibility
            return write!(f, "{}", self.namespace);
        }
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn chain_id() {
        // https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md#test-cases
        let dummy_max_length = "chainstd:8c3444cf8970a9e41a706fab93e7a6c4";
        let chain_id = ChainId::from_str(&dummy_max_length).unwrap();
        assert_eq!(chain_id.to_string(), dummy_max_length);

        let reference_too_long = format!("{}0", dummy_max_length);
        ChainId::from_str(&reference_too_long).unwrap_err();
        let reference_too_short = format!("{}:", chain_id.reference);
        ChainId::from_str(&reference_too_short).unwrap_err();
        let namespace_too_long = format!("0{}", dummy_max_length);
        ChainId::from_str(&namespace_too_long).unwrap_err();
        let namespace_too_short = format!("ch:{}", chain_id.reference);
        ChainId::from_str(&namespace_too_short).unwrap_err();
    }
}
