pub mod sha256;

#[cfg(feature = "ripemd-160")]
pub mod ripemd160;

#[cfg(feature = "keccak")]
pub mod keccak;

/// Hash function.
pub enum HashFunction {
    /// SHA-256
    Sha256,

    /// SHA-384
    Sha384,

    /// SHA-512
    Sha512,

    /// Blake2b
    Blake2b,

    /// Keccak-256
    Keccak256,
}

impl HashFunction {
    pub fn begin(&self) -> Hasher {
        todo!()
    }

    pub fn apply(&self, data: impl AsRef<[u8]>) -> Box<[u8]> {
        self.begin().chain_update(data).end()
    }
}

pub struct Hasher;

impl Hasher {
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        todo!()
    }

    pub fn chain_update(self, data: impl AsRef<[u8]>) -> Self {
        todo!()
    }

    pub fn end(self) -> Box<[u8]> {
        todo!()
    }
}
