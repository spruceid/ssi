use digest::consts::U32;
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
pub enum HashFunction {
    /// SHA-256
    Sha256,

    /// SHA-384
    Sha384,

    /// SHA-512
    Sha512,

    /// Blake2b-256
    Blake2b256,

    /// Keccak-256
    Keccak256,
}

impl HashFunction {
    pub fn begin(&self) -> Hasher {
        match self {
            Self::Sha256 => Hasher::Sha256(sha2::Sha256::new()),
            Self::Sha384 => Hasher::Sha384(sha2::Sha384::new()),
            Self::Sha512 => Hasher::Sha512(sha2::Sha512::new()),
            Self::Blake2b256 => Hasher::Blake2b256(blake2::Blake2b::<U32>::new()),
            Self::Keccak256 => Hasher::Keccak256(sha3::Keccak256::new()),
        }
    }

    pub fn apply(&self, data: impl AsRef<[u8]>) -> Box<[u8]> {
        self.begin().chain_update(data).finalize()
    }
}

pub enum Hasher {
    Sha256(sha2::Sha256),
    Sha384(sha2::Sha384),
    Sha512(sha2::Sha512),
    Blake2b256(blake2::Blake2b<U32>),
    Keccak256(sha3::Keccak256),
}

impl Hasher {
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        match self {
            Self::Sha256(h) => h.update(data),
            Self::Sha384(h) => h.update(data),
            Self::Sha512(h) => h.update(data),
            Self::Blake2b256(h) => h.update(data),
            Self::Keccak256(h) => h.update(data),
        }
    }

    pub fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
        match self {
            Self::Sha256(h) => Self::Sha256(h.chain_update(data)),
            Self::Sha384(h) => Self::Sha384(h.chain_update(data)),
            Self::Sha512(h) => Self::Sha512(h.chain_update(data)),
            Self::Blake2b256(h) => Self::Blake2b256(h.chain_update(data)),
            Self::Keccak256(h) => Self::Keccak256(h.chain_update(data)),
        }
    }

    pub fn finalize(self) -> Box<[u8]> {
        match self {
            Self::Sha256(h) => h.finalize().to_vec().into_boxed_slice(),
            Self::Sha384(h) => h.finalize().to_vec().into_boxed_slice(),
            Self::Sha512(h) => h.finalize().to_vec().into_boxed_slice(),
            Self::Blake2b256(h) => h.finalize().to_vec().into_boxed_slice(),
            Self::Keccak256(h) => h.finalize().to_vec().into_boxed_slice(),
        }
    }
}
