//! This library provides a flexible dynamic interface for cryptographic
//! primitives on top of RustCrypto, where algorithms can be selected at run
//! time instead of compile time.
//!
//! # Usage
//!
//! ```
//! # #[cfg(feature = "secp256r1")] {
//! use ssi_crypto::{AlgorithmInstance, KeyType, key::EcdsaCurve};
//!
//! /// Select a key type at run time.
//! let key_type = KeyType::Ecdsa(EcdsaCurve::P256);
//!
//! /// Generate a key of the given type.
//! let secret_key = key_type.generate()
//!     .expect("key generation failed");
//!
//! /// Sign a message with the given algorithm.
//! let signature = secret_key.sign_bytes(
//!   AlgorithmInstance::Es256,
//!   b"message"
//! ).expect("signature failed");
//!
//! /// Get the public key.
//! let public_key = secret_key.to_public();
//!
//! /// Verify the signature.
//! let verification = public_key.verify_bytes(
//!   AlgorithmInstance::Es256,
//!   b"message",
//!   &signature
//! ).expect("verification failed");
//!
//! assert!(verification.is_ok());
//! # }
//! ```
#[cfg(feature = "ed25519")]
pub use ed25519_dalek as ed25519;
#[cfg(feature = "secp256k1")]
pub use k256;
#[cfg(feature = "secp256r1")]
pub use p256;
#[cfg(feature = "secp384r1")]
pub use p384;
pub use rand;
#[cfg(feature = "rsa")]
pub use rsa;
pub use sha2;
#[cfg(feature = "sha3")]
pub use sha3;

pub mod algorithm;
mod error;
pub mod hash;
pub mod key;
mod options;
mod recovery;
pub mod signature;
mod utils;
mod verification;

pub use algorithm::{Algorithm, AlgorithmError, AlgorithmInstance, UnsupportedAlgorithm};
pub use error::*;
pub use hash::HashFunction;
pub use key::{KeyType, PublicKey, SecretKey};
pub use options::*;
pub use recovery::*;
pub use signature::{Issuer, Signer, SigningKey};
pub use utils::*;
pub use verification::*;
