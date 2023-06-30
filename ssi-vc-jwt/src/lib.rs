use std::ops::Deref;

use ssi_jws::{CompactJWS, InvalidCompactJWS};

mod decode;
mod encode;
mod signing;
pub mod verification;

/// Credential encoded as JWT signing bytes.
pub struct VcJwt<C> {
    /// Credential data.
    credential: C,

    /// JWT signing bytes.
    signing_bytes: Vec<u8>,
}

impl<C> VcJwt<C> {
    pub fn new(credential: C, signing_bytes: Vec<u8>) -> Result<Self, InvalidCompactJWS<Vec<u8>>> {
        if CompactJWS::check_signing_bytes(&signing_bytes) {
            Ok(unsafe { Self::new_unchecked(credential, signing_bytes) })
        } else {
            Err(InvalidCompactJWS(signing_bytes))
        }
    }

    /// # Safety
    ///
    /// The `signing_bytes` must form a valid compact JWS once concatenated with
    /// a `.` followed by the signature bytes.
    pub unsafe fn new_unchecked(credential: C, signing_bytes: Vec<u8>) -> Self {
        Self {
            credential,
            signing_bytes,
        }
    }

    pub fn signing_bytes(&self) -> &[u8] {
        &self.signing_bytes
    }

    pub fn into_signing_bytes(self) -> Vec<u8> {
        self.signing_bytes
    }
}

impl<C> Deref for VcJwt<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.credential
    }
}

/// JWS proof.
pub struct Proof {
    signature: Vec<u8>,
    method: verification::Method,
}

impl Proof {
    pub fn new(signature: Vec<u8>, method: verification::Method) -> Self {
        Self { signature, method }
    }

    pub fn into_signature(self) -> Vec<u8> {
        self.signature
    }
}
