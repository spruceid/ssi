#[cfg(feature = "ed25519")]
pub use ed25519_dalek as ed25519;

#[cfg(feature = "rsa")]
pub use rsa;

#[cfg(feature = "secp256k1")]
pub use k256;

#[cfg(feature = "secp256r1")]
pub use p256;

#[cfg(feature = "secp384r1")]
pub use p384;

pub use rand;
pub mod algorithm;
pub mod hashes;
pub mod key;
mod recovering;
mod signature;
mod verification;

pub use algorithm::{Algorithm, AlgorithmError, AlgorithmInstance, UnsupportedAlgorithm};
pub use key::{KeyType, PublicKey, SecretKey};
pub use recovering::*;
pub use signature::*;
pub use verification::*;
