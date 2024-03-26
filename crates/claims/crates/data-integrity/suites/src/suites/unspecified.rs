//! Group cryptographic suites that currently lack a specification.

#[cfg(feature = "aleo")]
pub mod aleo_signature_2021;

#[cfg(all(feature = "ethereum", feature = "eip712"))]
pub mod eip712_signature_2021;

#[cfg(all(feature = "ethereum", feature = "secp256k1"))]
pub mod ethereum_personal_signature_2021;

#[cfg(feature = "solana")]
pub mod solana_signature_2021;

#[cfg(feature = "tezos")]
pub mod tezos;

#[cfg(feature = "aleo")]
pub use aleo_signature_2021::AleoSignature2021;

#[cfg(all(feature = "ethereum", feature = "eip712"))]
pub use eip712_signature_2021::Eip712Signature2021;

#[cfg(all(feature = "ethereum", feature = "secp256k1"))]
pub use ethereum_personal_signature_2021::{
    EthereumPersonalSignature2021, EthereumPersonalSignature2021v0_1,
};

#[cfg(feature = "solana")]
pub use solana_signature_2021::SolanaSignature2021;

#[cfg(feature = "tezos")]
pub use tezos::*;
