//! Group cryptographic suites that currently lack a specification.

pub mod aleo_signature_2021;
mod eip712_signature_2021;
mod ethereum_personal_signature_2021;
mod solana_signature_2021;

#[cfg(feature = "tezos")]
pub mod tezos;

pub use aleo_signature_2021::AleoSignature2021;
pub use eip712_signature_2021::Eip712Signature2021;
pub use ethereum_personal_signature_2021::EthereumPersonalSignature2021;
pub use solana_signature_2021::SolanaSignature2021;

#[cfg(feature = "tezos")]
pub use tezos::*;
