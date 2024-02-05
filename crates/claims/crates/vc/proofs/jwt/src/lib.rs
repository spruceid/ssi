use std::ops::Deref;

use ssi_claims_core::Provable;

mod decode;
mod encode;
mod signing;
pub mod verification;

/// Credential encoded as JWT signing bytes.
pub struct VcJwt<C> {
    /// Credential data.
    credential: C,

    /// JWS header.
    header: ssi_jws::Header,

    /// JWS payload.
    payload: Vec<u8>,
}

impl<C> VcJwt<C> {
    pub fn new(credential: C, header: ssi_jws::Header, payload: Vec<u8>) -> Self {
        Self {
            credential,
            header,
            payload,
        }
    }

    pub fn build_signing_bytes(&self) -> Vec<u8> {
        self.header.encode_signing_bytes(&self.payload)
    }
}

impl<C> Deref for VcJwt<C> {
    type Target = C;

    fn deref(&self) -> &Self::Target {
        &self.credential
    }
}

impl<C> Provable for VcJwt<C> {
    type Proof = Proof;
}

/// JWS proof.
pub struct Proof {
    signature: Vec<u8>,
    issuer: verification::Issuer,
}

impl Proof {
    pub fn new(signature: Vec<u8>, signer: verification::Issuer) -> Self {
        Self {
            signature,
            issuer: signer,
        }
    }

    pub fn into_signature(self) -> Vec<u8> {
        self.signature
    }
}
