//! W3C crypto suites.
//!
//! This module includes the definitions of many Data Integrity cryptographic
//! suites specified by the W3C organization.

#[cfg(feature = "rsa")]
pub mod rsa_signature_2018;
#[cfg(feature = "rsa")]
pub use rsa_signature_2018::RsaSignature2018;

#[cfg(feature = "ed25519")]
pub mod ed25519_signature_2018;
#[cfg(feature = "ed25519")]
pub use ed25519_signature_2018::Ed25519Signature2018;

#[cfg(feature = "ed25519")]
pub mod ed25519_signature_2020;
#[cfg(feature = "ed25519")]
pub use ed25519_signature_2020::Ed25519Signature2020;

#[cfg(feature = "ed25519")]
pub mod edssa_2022;
#[cfg(feature = "ed25519")]
pub use edssa_2022::EdDsa2022;

#[cfg(feature = "secp256k1")]
pub mod ecdsa_secp256k1_signature_2019;
#[cfg(feature = "secp256k1")]
pub use ecdsa_secp256k1_signature_2019::EcdsaSecp256k1Signature2019;

#[cfg(feature = "secp256r1")]
pub mod ecdsa_secp256r1_signature_2019;
#[cfg(feature = "secp256r1")]
pub use ecdsa_secp256r1_signature_2019::EcdsaSecp256r1Signature2019;

pub mod json_web_signature_2020;
pub use json_web_signature_2020::JsonWebSignature2020;
