//! [CAIP-2] Blockchain IDs
//!
//! This module provides a struct [ChainId] to represent a CAIP-2 blockchain id, that can be
//! converted to and from a string.
//!
//! ## Example
//! Round-trip parse and serialize a CAIP-2 string.
//! ```
//! use ssi_caips::caip2::ChainId;
//! use std::str::FromStr;
//!
//! let chain_id_str = "chainstd:8c3444cf8970a9e41a706fab93e7a6c4";
//! let chain_id = ChainId::from_str(&chain_id_str)?;
//! assert_eq!(chain_id.to_string(), chain_id_str);
//! # Ok::<(),ssi_caips::caip2::ChainIdParseError>(())
//! ```
//! More test cases may be found in the [CAIP-2 specification] [test cases].
//!
//! [test cases]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md#test-cases
//! [CAIP-2]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
use std::fmt;
use std::str::FromStr;

use thiserror::Error;

/// A parsed [CAIP-2] chain id.
///
/// [CAIP-2]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct ChainId {
    /// The `namespace` part of a CAIP-2 string, i.e. the "virtual machine" or type of chain.
    pub namespace: String,
    /// The `reference` part of a CAIP-2 string, i.e. the chain identifier.
    pub reference: String,
}

const NAMESPACE_MIN_LENGTH: usize = 3;
const NAMESPACE_MAX_LENGTH: usize = 8;
const REFERENCE_MIN_LENGTH: usize = 1;
const REFERENCE_MAX_LENGTH: usize = 32;

/// An error resulting from [parsing a CAIP-2 chain id][`ChainId::from_str`].
#[derive(Error, Debug)]
pub enum ChainIdParseError {
    /// The namespace part contained a character outside the expected range.
    #[error("Unexpected character in namespace: {0}")]
    NamespaceChar(char),
    /// The namespace part is above the maximum length allowed.
    #[error("Namespace too long")]
    NamespaceTooLong,
    /// The namespace part is below the minimum length allowed.
    #[error("Namespace too long")]
    NamespaceTooShort,
    /// The reference part contained a character outside the expected range.
    #[error("Unexpected character in reference: {0}")]
    ReferenceChar(char),
    /// The reference part is above the maximum length allowed.
    #[error("Reference too long")]
    ReferenceTooLong,
    /// The reference part is below the minimum length allowed.
    #[error("Reference too short")]
    ReferenceTooShort,
    /// The colon (`:`) is missing to separate the namespace and reference part.
    #[error("Missing separator between namespace and reference")]
    MissingSeparator,
}

impl FromStr for ChainId {
    type Err = ChainIdParseError;
    /// Parse a CAIP-2 string to construct a [ChainId].
    fn from_str(chain_id: &str) -> Result<Self, Self::Err> {
        // namespace:   [-a-z0-9]{3,8}
        let mut namespace = String::with_capacity(NAMESPACE_MAX_LENGTH);
        // reference:   [-a-zA-Z0-9]{1,32}
        let mut reference = String::with_capacity(REFERENCE_MAX_LENGTH);
        let mut chars = chain_id.chars();
        let mut separated = false;
        for c in &mut chars {
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
            return Err(ChainIdParseError::MissingSeparator);
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
    /// Serialize a [ChainId] as a CAIP-2 string.
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.namespace, self.reference)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn chain_id() {
        // See https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md#test-cases
        let dummy_max_length = "chainstd:8c3444cf8970a9e41a706fab93e7a6c4";
        let chain_id = ChainId::from_str(dummy_max_length).unwrap();
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
