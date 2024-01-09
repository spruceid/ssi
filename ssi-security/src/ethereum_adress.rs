use core::fmt;
use linked_data::{
    rdf_types::{Interpretation, Vocabulary},
    LinkedDataPredicateObjects, LinkedDataSubject,
};
use serde::{Deserialize, Serialize};
use std::{ops::Deref, str::FromStr};

/// Value for the `ethereumAddress` property.
///
/// An `ethereumAddress` property is used to specify the Ethereum address (as per
/// the [Ethereum Yellow Paper: ETHEREUM: A SECURE DECENTRALISED GENERALISED
/// TRANSACTION LEDGER][1]) composed of the prefix "0x", a common identifier for
/// hexadecimal, concatenated with the rightmost 20 bytes of the Keccak-256
/// hash (big endian) of the ECDSA public key (the curve used is the so-called
/// secp256k1).
///
/// In hexadecimal, 2 digits represent a byte, meaning addresses contain 40
/// hexadecimal digits. The Ethereum address should also contain a checksum as
/// per [EIP-55][2].
///
/// [1]: <https://ethereum.github.io/yellowpaper/paper.pdf>
/// [2]: <https://eips.ethereum.org/EIPS/eip-55>
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EthereumAddressBuf(String);

impl EthereumAddressBuf {
    pub fn as_ethereum_address(&self) -> &EthereumAddress {
        unsafe { std::mem::transmute(self.0.as_str()) }
    }

    pub fn into_string(self) -> String {
        self.0
    }
}

impl FromStr for EthereumAddressBuf {
    type Err = std::convert::Infallible;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Self(s.to_owned())) // TODO actually parse
    }
}

impl Deref for EthereumAddressBuf {
    type Target = EthereumAddress;

    fn deref(&self) -> &Self::Target {
        self.as_ethereum_address()
    }
}

impl fmt::Display for EthereumAddressBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

impl<V: Vocabulary, I: Interpretation> linked_data::LinkedDataResource<I, V>
    for EthereumAddressBuf
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

impl<V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V> for EthereumAddressBuf {
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V> for EthereumAddressBuf {
    fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        visitor.end()
    }
}

/// Unsized value for the `ethereumAddress` property.
///
/// An `ethereumAddress` property is used to specify the Ethereum address (as per
/// the [Ethereum Yellow Paper: ETHEREUM: A SECURE DECENTRALISED GENERALISED
/// TRANSACTION LEDGER][1]) composed of the prefix "0x", a common identifier for
/// hexadecimal, concatenated with the rightmost 20 bytes of the Keccak-256
/// hash (big endian) of the ECDSA public key (the curve used is the so-called
/// secp256k1).
///
/// In hexadecimal, 2 digits represent a byte, meaning addresses contain 40
/// hexadecimal digits. The Ethereum address should also contain a checksum as
/// per [EIP-55][2].
///
/// [1]: <https://ethereum.github.io/yellowpaper/paper.pdf>
/// [2]: <https://eips.ethereum.org/EIPS/eip-55>
pub struct EthereumAddress(str);

impl EthereumAddress {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<V: Vocabulary, I: Interpretation> linked_data::LinkedDataResource<I, V> for EthereumAddress {
    fn interpretation(
        &self,
        _vocabulary: &mut V,
        _interpretation: &mut I,
    ) -> linked_data::ResourceInterpretation<I, V> {
        use linked_data::{rdf_types::Term, CowRdfTerm, RdfLiteralRef, ResourceInterpretation};
        ResourceInterpretation::Uninterpreted(Some(CowRdfTerm::Borrowed(Term::Literal(
            RdfLiteralRef::Xsd(xsd_types::ValueRef::String(&self.0)),
        ))))
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataPredicateObjects<I, V> for EthereumAddress {
    fn visit_objects<S>(&self, mut visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::PredicateObjectsVisitor<I, V>,
    {
        visitor.object(self)?;
        visitor.end()
    }
}

impl<V: Vocabulary, I: Interpretation> LinkedDataSubject<I, V> for EthereumAddress {
    fn visit_subject<S>(&self, visitor: S) -> Result<S::Ok, S::Error>
    where
        S: linked_data::SubjectVisitor<I, V>,
    {
        visitor.end()
    }
}
