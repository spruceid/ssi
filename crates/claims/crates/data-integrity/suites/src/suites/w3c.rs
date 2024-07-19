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
pub mod eddsa_2022;
#[cfg(feature = "ed25519")]
pub use eddsa_2022::EdDsa2022;

#[cfg(feature = "ed25519")]
pub mod eddsa_rdfc_2022;
#[cfg(feature = "ed25519")]
pub use eddsa_rdfc_2022::EdDsaRdfc2022;

#[cfg(feature = "secp256k1")]
pub mod ecdsa_secp256k1_signature_2019;
#[cfg(feature = "secp256k1")]
pub use ecdsa_secp256k1_signature_2019::EcdsaSecp256k1Signature2019;

#[cfg(any(feature = "secp256r1", feature = "secp384r1"))]
pub mod ecdsa_rdfc_2019;
#[cfg(any(feature = "secp256r1", feature = "secp384r1"))]
pub use ecdsa_rdfc_2019::EcdsaRdfc2019;

#[cfg(feature = "secp256r1")]
pub mod ecdsa_sd_2023;
#[cfg(feature = "secp256r1")]
pub use ecdsa_sd_2023::EcdsaSd2023;

#[cfg(feature = "eip712")]
pub mod ethereum_eip712_signature_2021;
#[cfg(feature = "eip712")]
pub use ethereum_eip712_signature_2021::{
    EthereumEip712Signature2021, EthereumEip712Signature2021v0_1,
};

#[cfg(feature = "secp256r1")]
pub mod ecdsa_secp256r1_signature_2019;
#[cfg(feature = "secp256r1")]
pub use ecdsa_secp256r1_signature_2019::EcdsaSecp256r1Signature2019;

pub mod json_web_signature_2020;
pub use json_web_signature_2020::JsonWebSignature2020;

#[cfg(feature = "bbs")]
pub mod bbs_2023;
#[cfg(feature = "bbs")]
pub use bbs_2023::Bbs2023;
