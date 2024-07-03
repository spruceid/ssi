use iref::Iri;
use static_iref::iri;
// use treeldr_rust_macros::tldr;

mod ethereum_adress;
pub use ethereum_adress::*;

pub mod multibase;
pub use multibase::{Multibase, MultibaseBuf};

// #[tldr("ssi-vc/src/schema/sec.ttl")]
// pub mod schema {
//     #[prefix("http://www.w3.org/2002/07/owl#")]
//     pub mod owl {}

//     #[prefix("http://www.w3.org/1999/02/22-rdf-syntax-ns#")]
//     pub mod rdf {}

//     #[prefix("http://www.w3.org/2000/01/rdf-schema#")]
//     pub mod rdfs {}

//     #[prefix("http://www.w3.org/2001/XMLSchema#")]
//     pub mod xsd {}

//     #[prefix("https://treeldr.org/")]
//     pub mod tldr {}

//     #[prefix("https://w3id.org/security#")]
//     pub mod sec {}
// }

// pub use schema::sec::*;

pub const CRYPTOSUITE: &Iri = iri!("https://w3id.org/security#cryptosuite");

pub const VERIFICATION_METHOD: &Iri = iri!("https://w3id.org/security#verificationMethod");

pub const PROOF_PURPOSE: &Iri = iri!("https://w3id.org/security#proofPurpose");

pub const PROOF_VALUE: &Iri = iri!("https://w3id.org/security#proofValue");

pub const PROOF: &Iri = iri!("https://w3id.org/security#proof");

pub const JWS: &Iri = iri!("https://w3id.org/security#jws");

pub const SIGNATURE_VALUE: &Iri = iri!("https://w3id.org/security#signatureValue");

/// Multibase datatype.
///
/// Range of the `publicKeyMultibase` property.
pub const MULTIBASE: &Iri = iri!("https://w3id.org/security#multibase");

/// Multibase-encoded public key property.
pub const PUBLIC_KEY_MULTIBASE: &Iri = iri!("https://w3id.org/security#publicKeyMultibase");

/// JWK public key property.
///
/// This property is missing from the `https://w3id.org/security/v1` context,
/// but is defined in `https://w3id.org/security/v3-unstable`.
pub const PUBLIC_KEY_JWK: &Iri = iri!("https://w3id.org/security#publicKeyJwk");

/// Hex-encoded public key property (deprecated).
///
/// This property is missing from the `https://w3id.org/security/v1` context,
/// but is defined in `https://w3id.org/security/v3-unstable`.
pub const PUBLIC_KEY_HEX: &Iri = iri!("https://w3id.org/security#publicKeyHex");

/// Ethereum address property (deprecated).
///
/// An `ethereumAddress` property is used to specify the Ethereum address.
///
/// As per the Ethereum Yellow Paper ["Ethereum: a secure decentralised
/// generalised transaction ledger"][1] in consists of a prefix "0x", a common
/// identifier for hexadecimal, concatenated with the rightmost 20 bytes of the
/// Keccak-256 hash (big endian) of the ECDSA public key (the curve used is the
/// so-called secp256k1). In hexadecimal, 2 digits represent a byte, meaning
/// addresses contain 40 hexadecimal digits. The Ethereum address should also
/// contain a checksum as per [EIP-55][2].
///
/// [1]: <https://ethereum.github.io/yellowpaper/paper.pdf>
/// [2]: <https://eips.ethereum.org/EIPS/eip-55>
pub const ETHEREUM_ADDRESS: &Iri = iri!("https://w3id.org/security#ethereumAddress");

/// Blockchain Account Id property (deprecated).
///
/// A `blockchainAccountId` property is used to specify a blockchain account
/// identifier, as per the [CAIP-10Account ID Specification][1].
///
/// [1]: <https://github.com/ChainAgnostic/CAIPs/blob/master/CAIPs/caip-10.md>
pub const BLOCKCHAIN_ACCOUNT_ID: &Iri = iri!("https://w3id.org/security#blockchainAccountId");
