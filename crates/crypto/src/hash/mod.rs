use core::fmt;
use sha2::Digest;

mod sha256;
pub use sha256::sha256;

#[cfg(feature = "ripemd-160")]
pub mod ripemd160;

#[cfg(feature = "keccak")]
pub mod keccak;

/// Hash function.
///
/// Cryptographic algorithms are usually composed of a hash function to digest
/// the input message, and a signature function used to sign the digest. This
/// type lists all the hash functions supported by `ssi`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum HashFunction {
    /// SHA-256
    Sha256,

    /// SHA-384
    Sha384,

    /// SHA-512
    Sha512,

    /// Blake2b-256
    ///
    /// Implementation requires the `blake2` feature.
    Blake2b256,

    /// Keccak-256
    ///
    /// Implementation requires the `keccak` feature.
    Keccak256,
}

impl HashFunction {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Sha256 => "SHA-256",
            Self::Sha384 => "SHA-384",
            Self::Sha512 => "SHA-512",
            Self::Blake2b256 => "Blake2b-256",
            Self::Keccak256 => "Keccak-256",
        }
    }

    pub fn begin(&self) -> Result<Hasher, UnsupportedHashFunction> {
        match self {
            Self::Sha256 => Ok(Hasher::Sha256(sha2::Sha256::new())),
            Self::Sha384 => Ok(Hasher::Sha384(sha2::Sha384::new())),
            Self::Sha512 => Ok(Hasher::Sha512(sha2::Sha512::new())),

            #[cfg(feature = "blake2")]
            Self::Blake2b256 => Ok(Hasher::Blake2b256(
                blake2::Blake2b::<digest::consts::U32>::new(),
            )),

            #[cfg(feature = "keccak")]
            Self::Keccak256 => Ok(Hasher::Keccak256(sha3::Keccak256::new())),

            #[allow(unreachable_patterns)]
            _ => Err(UnsupportedHashFunction(*self)),
        }
    }

    pub fn apply(&self, data: impl AsRef<[u8]>) -> Result<Vec<u8>, UnsupportedHashFunction> {
        Ok(self.begin()?.chain_update(data).finalize())
    }
}

impl fmt::Display for HashFunction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.name().fmt(f)
    }
}

pub enum Hasher {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),

    #[cfg(feature = "blake2")]
    Blake2b256(blake2::Blake2b<digest::consts::U32>),

    #[cfg(feature = "keccak")]
    Keccak256(sha3::Keccak256),
}

impl Hasher {
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),

            #[cfg(feature = "blake2")]
            Self::Blake2b256(h) => h.update(data),

            #[cfg(feature = "keccak")]
            Self::Keccak256(h) => h.update(data),
        }
    }

    pub fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
        match self {
            Self::Sha256(h) => Self::Sha256(h.chain_update(data)),
            Self::Sha384(h) => Self::Sha384(h.chain_update(data)),
            Self::Sha512(h) => Self::Sha512(h.chain_update(data)),

            #[cfg(feature = "blake2")]
            Self::Blake2b256(h) => Self::Blake2b256(h.chain_update(data)),

            #[cfg(feature = "keccak")]
            Self::Keccak256(h) => Self::Keccak256(h.chain_update(data)),
        }
    }

    pub fn finalize(self) -> Vec<u8> {
        match self {
            Self::Sha256(h) => h.finalize().to_vec(),
            Self::Sha384(h) => h.finalize().to_vec(),
            Self::Sha512(h) => h.finalize().to_vec(),

            #[cfg(feature = "blake2")]
            Self::Blake2b256(h) => h.finalize().to_vec(),

            #[cfg(feature = "keccak")]
            Self::Keccak256(h) => h.finalize().to_vec(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("unsupported hash function `{0}`")]
pub struct UnsupportedHashFunction(HashFunction);

impl From<UnsupportedHashFunction> for crate::Error {
    fn from(value: UnsupportedHashFunction) -> Self {
        Self::HashFunctionUnsupported(value.0)
    }
}
