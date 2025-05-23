//! [CAIP-10] Blockchain Account IDs
//!
//! This module provides a struct [`BlockchainAccountId`] to represent a CAIP-10 blockchain account
//! id, that can be converted to and from a string. `BlockchainAccountId` can also be
//! [verified][BlockchainAccountId::verify] for correspondence with a public key, for some account
//! id types.
//!
//! ## Example
//! Round-trip parse and serialize a CAIP-10 string.
//! ```
//! use ssi_caips::caip10::BlockchainAccountId;
//! use std::str::FromStr;
//!
//! let account_id_str = "chainstd:8c3444cf8970a9e41a706fab93e7a6c4:6d9b0b4b9994e8a6afbd3dc3ed983cd51c755afb27cd1dc7825ef59c134a39f7";
//! let account_id = BlockchainAccountId::from_str(&account_id_str)?;
//! assert_eq!(account_id.to_string(), account_id_str);
//! # Ok::<(),ssi_caips::caip10::BlockchainAccountIdParseError>(())
//! ```
//!
//! More test cases may be found in the [CAIP-10 specification][test cases].
//!
//! [CAIP-10]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md
//! [test cases]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md#test-cases

use crate::caip2::{ChainId, ChainIdParseError};
use linked_data::{
    rdf_types::{Interpretation, Vocabulary},
    LinkedDataPredicateObjects, LinkedDataSubject,
};
use ssi_jwk::{Params, JWK};
use std::str::FromStr;
use std::{fmt, marker::PhantomData, ops::Deref};

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(feature = "aleo")]
mod aleo;

#[cfg(feature = "aleo")]
pub use aleo::*;

/// A parsed [CAIP-10] blockchain account id as a string.
///
/// It includes a [ChainId] struct representing the `chain_id` ([CAIP-2]) part of a composed [CAIP-10].
///
/// [CAIP-10]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md
/// [CAIP-2]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-2.md
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct BlockchainAccountId {
    /// The `account_address` part of a CAIP-10 string.
    pub account_address: String,
    /// The `chain_id` part of a CAIP-10 string, parsed into a [ChainId] struct.
    pub chain_id: ChainId,
}

impl Serialize for BlockchainAccountId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        let string = self.to_string();
        serializer.serialize_str(&string)
    }
}

impl<'de> Deserialize<'de> for BlockchainAccountId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl serde::de::Visitor<'_> for Visitor {
            type Value = BlockchainAccountId;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                write!(formatter, "a blockchain account id")
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                v.parse()
                    .map_err(|_| E::invalid_value(serde::de::Unexpected::Str(v), &self))
            }
        }

        deserializer.deserialize_str(Visitor)
    }
}

impl<V: Vocabulary, I: Interpretation> linked_data::LinkedDataResource<I, V>
    for BlockchainAccountId
{
    fn interpretation(
        &self,
        _vocabulary: &mut V,
        _interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        use linked_data::{rdf_types::Term, CowRdfTerm, RdfLiteral, ResourceInterpretation};
        ResourceInterpretation::Uninterpreted(Some(CowRdfTerm::Owned(Term::Literal(
            RdfLiteral::Xsd(xsd_types::Value::String(self.to_string())),
        ))))
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V> for BlockchainAccountId {
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V> for BlockchainAccountId {
    fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        visitor.end()
    }
}

/// Error resulting from attempting to [verify][BlockchainAccountId::verify] a blockchain account
/// ID against a public key.
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
    /// Check that a given public key corresponds to this account id.
    ///
    /// Many kinds of blockchain account ids are derivable from public keys, whether by encoding
    /// a public key directly or by using the hash of the public key.
    ///
    /// # Supported account ids for public key verification
    ///
    /// This function supports the following patterns of account ids:
    /// - `tezos:*:tz1*`
    /// - `tezos:*:tz2*`
    /// - `tezos:*:tz3*`
    /// - `eip155:*` (requires `keccak-hash` crate feature)
    /// - `solana:*`
    /// - `bip122:000000000019d6689c085ae165831e93:1*` (requires `ripemd160` crate feature)
    /// - `bip122:1a91e3dace36e2be3bf030a65679fe82:D*` (requires `ripemd160` crate feature)
    pub fn verify(&self, jwk: &JWK) -> Result<(), BlockchainAccountIdVerifyError> {
        let hash = match (
            self.chain_id.namespace.as_str(),
            self.chain_id.reference.as_str(),
        ) {
            #[cfg(feature = "tezos")]
            ("tezos", _net) => ssi_jwk::blakesig::hash_public_key(jwk)
                .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string())),
            #[cfg(feature = "eip")]
            // If account address contains uppercase, check EIP-55 checksum.
            // Otherwise, assume EIP-55 is not being used.
            ("eip155", _net) => if self
                .account_address
                .contains(|c: char| c.is_ascii_uppercase())
            {
                ssi_jwk::eip155::hash_public_key_eip55(jwk)
            } else {
                ssi_jwk::eip155::hash_public_key(jwk)
            }
            .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string())),
            ("solana", _net) => encode_ed25519(jwk)
                .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string())),
            // Bitcoin
            #[cfg(feature = "ripemd-160")]
            ("bip122", "000000000019d6689c085ae165831e93") => {
                ssi_jwk::ripemd160::hash_public_key(jwk, 0x00)
                    .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string()))
            }
            // Dogecoin
            #[cfg(feature = "ripemd-160")]
            ("bip122", "1a91e3dace36e2be3bf030a65679fe82") => {
                ssi_jwk::ripemd160::hash_public_key(jwk, 0x1e)
                    .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string()))
            }
            #[cfg(feature = "aleo")]
            ("aleo", network_id) => encode_aleo_address(jwk, network_id)
                .map_err(|e| BlockchainAccountIdVerifyError::HashError(e.to_string())),
            _ => Err(BlockchainAccountIdVerifyError::UnknownChainId(
                self.chain_id.to_string(),
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

/// An error resulting from trying to [parse a CAIP-10 string][`BlockchainAccountId::from_str`].
#[derive(Error, Debug)]
pub enum BlockchainAccountIdParseError {
    /// The `account_address` part contains a character outside the expected range.
    #[error("Unexpected character in account address: {0}")]
    AddressChar(char),
    /// The `account_address` part is not a valid length.
    #[error("Account address bad length: {0}")]
    AddressLength(usize),
    /// The `chain_id` part contains a character outside the expected range.
    #[error("Unexpected character in chain id: {0}")]
    ChainChar(char),
    /// The `chain_id` part is not a valid length.
    #[error("Chain id bad length: {0}")]
    ChainLength(usize),
    /// The separator between the `chain_id` and `account_address` part was not found.
    ///
    /// The separator is a colon (`:`) as of the [`2021-08-11` version of CAIP-10][modern]. In the
    /// [previous ("legacy") version of CAIP-10][legacy], it was an at sign (`@`) (and the two
    /// parts appeared in the reverse order).
    ///
    /// [modern]: https://github.com/ChainAgnostic/CAIPs/blob/9b72330f70f764d6f4435617867b7aec4e50c6db/CAIPs/caip-10.md
    /// [legacy]: https://github.com/ChainAgnostic/CAIPs/blob/26af70a9598ae4f7274481ba0c25ee77f90a66a2/CAIPs/caip-10.md
    #[error("Missing separator between chain id and account address")]
    MissingSeparator,
    /// The `chain_id` part could not be parsed.
    #[error("Chain id: {0}")]
    ChainId(#[from] ChainIdParseError),
}

impl FromStr for BlockchainAccountId {
    type Err = BlockchainAccountIdParseError;
    /// Parse a CAIP-10 string into a [`BlockchainAccountId`].
    ///
    /// The [legacy CAIP-10 syntax][legacy] (`<account_address>@<chain_id>`) is allowed, as well
    /// as the modern syntax (`<chain_id>:<account_address>`).
    ///
    /// The `chain_id` (CAIP-2) part is [parsed][ChainId::from_str] into a [`ChainId`] as part of
    /// the [`BlockchainAccountId`].
    ///
    /// [legacy]: https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md#backwards-compatibility
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
        if !(CHAIN_ID_MIN_LENGTH..=CHAIN_ID_MAX_LENGTH).contains(&chain_len) {
            return Err(BlockchainAccountIdParseError::ChainLength(chain_len));
        }
        let chain_id = ChainId::from_str(&chain_id)?;
        let address_len = account_address.len();
        if !(ACCOUNT_ADDRESS_MIN_LENGTH..=ACCOUNT_ADDRESS_MAX_LENGTH).contains(&address_len) {
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

#[derive(Debug, thiserror::Error)]
pub enum AleoBlockchainAccountIdError {
    #[error(transparent)]
    Parsing(#[from] BlockchainAccountIdParseError),

    #[error("expected CAIP-2 namespace `{0}`, found `{1}`")]
    Caip2Namespace(String, String),

    #[error("unexpected network `{0}`, `{1}`")]
    Network(String, String),
}

pub trait BlockchainAccountIdType {
    const NAMESPACE: &'static str;

    const REFERENCE: &'static str;
}

#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct TypedBlockchainAccountId<T>(BlockchainAccountId, PhantomData<T>);

impl<T: BlockchainAccountIdType> TypedBlockchainAccountId<T> {
    pub fn new(id: BlockchainAccountId) -> Result<Self, AleoBlockchainAccountIdError> {
        if id.chain_id.namespace != T::NAMESPACE {
            return Err(AleoBlockchainAccountIdError::Caip2Namespace(
                T::NAMESPACE.to_owned(),
                id.chain_id.namespace.clone(),
            ));
        }

        if id.chain_id.reference != T::REFERENCE {
            return Err(AleoBlockchainAccountIdError::Network(
                T::REFERENCE.to_owned(),
                id.chain_id.reference.clone(),
            ));
        }

        Ok(Self(id, PhantomData))
    }
}

impl<T> Deref for TypedBlockchainAccountId<T> {
    type Target = BlockchainAccountId;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T: BlockchainAccountIdType> TryFrom<BlockchainAccountId> for TypedBlockchainAccountId<T> {
    type Error = AleoBlockchainAccountIdError;

    fn try_from(value: BlockchainAccountId) -> Result<Self, Self::Error> {
        Self::new(value)
    }
}

impl<T: BlockchainAccountIdType> FromStr for TypedBlockchainAccountId<T> {
    type Err = AleoBlockchainAccountIdError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let id: BlockchainAccountId = s.parse()?;
        Self::new(id)
    }
}

impl<T> Serialize for TypedBlockchainAccountId<T> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        self.0.serialize(serializer)
    }
}

impl<'de, T: BlockchainAccountIdType> Deserialize<'de> for TypedBlockchainAccountId<T> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let id = BlockchainAccountId::deserialize(deserializer)?;
        Self::new(id).map_err(serde::de::Error::custom)
    }
}

impl<V: Vocabulary, I: Interpretation, T> linked_data::LinkedDataResource<I, V>
    for TypedBlockchainAccountId<T>
{
    fn interpretation(
        &self,
        _vocabulary: &mut V,
        _interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        use linked_data::{rdf_types::Term, CowRdfTerm, RdfLiteral, ResourceInterpretation};
        ResourceInterpretation::Uninterpreted(Some(CowRdfTerm::Owned(Term::Literal(
            RdfLiteral::Xsd(xsd_types::Value::String(self.to_string())),
        ))))
    }
}

impl<V: Vocabulary, I: Interpretation, T> LinkedDataPredicateObjects<I, V>
    for TypedBlockchainAccountId<T>
{
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation, T> LinkedDataSubject<I, V> for TypedBlockchainAccountId<T> {
    fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        visitor.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[async_std::test]
    async fn account_id() {
        // https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md#test-cases
        let dummy_max_length = "chainstd:8c3444cf8970a9e41a706fab93e7a6c4:6d9b0b4b9994e8a6afbd3dc3ed983cd51c755afb27cd1dc7825ef59c134a39f7";
        let account_id = BlockchainAccountId::from_str(dummy_max_length).unwrap();
        assert_eq!(account_id.to_string(), dummy_max_length);

        // Support old format, for backwards compatibility
        let old = "6d9b0b4b9994e8a6afbd3dc3ed983cd51c755afb27cd1dc7825ef59c134a39f7@chainstd:8c3444cf8970a9e41a706fab93e7a6c4";
        let account_id_old = BlockchainAccountId::from_str(old).unwrap();
        assert_eq!(account_id_old.to_string(), dummy_max_length);
    }

    #[cfg(feature = "tezos")]
    #[test]
    fn verify() {
        use serde_json::json;
        let jwk: JWK = serde_json::from_value(json!({
          "crv": "Ed25519",
          "kty": "OKP",
          "x": "G80iskrv_nE69qbGLSpeOHJgmV4MKIzsy5l5iT6pCww"
        }))
        .unwrap();
        let account_id = BlockchainAccountId::from_str(
            "tezos:NetXdQprcVkpaWU:tz1NcJyMQzUw7h85baBA6vwRGmpwPnM1fz83",
        )
        .unwrap();
        account_id.verify(&jwk).unwrap();
    }
}
