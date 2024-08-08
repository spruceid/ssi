#![cfg_attr(docsrs, feature(doc_auto_cfg))]

#[cfg(feature = "secp256r1")]
pub use p256;

pub mod algorithm;
pub mod hashes;
pub mod key;
mod signature;
pub mod signatures;
mod verification;

pub use algorithm::{Algorithm, AlgorithmError, AlgorithmInstance, UnsupportedAlgorithm};
pub use key::{PublicKey, SecretKey};
pub use signature::*;
pub use verification::*;
