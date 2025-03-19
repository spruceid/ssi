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
