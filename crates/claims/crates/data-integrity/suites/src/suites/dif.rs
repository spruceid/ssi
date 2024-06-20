//! Data Integrity cryptographic suites defined by the
//! [Decentralized Identity Foundation (DIF)][dif].
//!
//! [dif]: https://identity.foundation/

#[cfg(feature = "secp256k1")]
mod ecdsa_secp256k1_recovery_signature_2020;

#[cfg(feature = "secp256k1")]
pub use ecdsa_secp256k1_recovery_signature_2020::EcdsaSecp256k1RecoverySignature2020;
