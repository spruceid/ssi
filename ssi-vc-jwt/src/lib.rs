use std::ops::Deref;

mod decode;
pub mod verification;

pub use decode::Decoder;

/// Credential encoded as JWT signing bytes.
pub struct Encoded<C> {
    /// Credential data.
    credential: C,

    /// JWT signing bytes.
    signing_bytes: Vec<u8>,
}

impl<C> Encoded<C> {
    pub fn new(credential: C, signing_bytes: Vec<u8>) -> Self {
        Self {
            credential,
            signing_bytes,
        }
    }

    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }
}

impl<C> Deref for Encoded<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.credential
    }
}

/// JWS proof.
pub struct Proof {
    algorithm: ssi_jwk::Algorithm,
    signature: Vec<u8>,
    method: verification::Method,
}

impl Proof {
    pub fn new(
        algorithm: ssi_jwk::Algorithm,
        signature: Vec<u8>,
        method: verification::Method,
    ) -> Self {
        Self {
            algorithm,
            signature,
            method,
        }
    }
}
