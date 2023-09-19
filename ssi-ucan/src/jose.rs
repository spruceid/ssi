use crate::{
    jwt::{JwtSignatureDe, JwtSignatureSer},
    Ucan,
};
use ssi_jwk::Algorithm;

#[derive(Clone, PartialEq, Debug)]
pub enum Signature {
    ES256([u8; 64]),
    ES512([u8; 128]),
    EdDSA([u8; 64]),
    RS256(Vec<u8>),
    RS512(Vec<u8>),
    ES256K([u8; 64]),
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Incorrect Signature Length")]
    IncorrectSignatureLength,
    #[error("Unsupported algorithm")]
    UnsupportedAlgorithm,
}

impl Signature {
    pub fn new(alg: Algorithm, signature: Vec<u8>) -> Result<Self, Error> {
        Ok(match alg {
            Algorithm::ES256 => Self::ES256(
                signature
                    .try_into()
                    .map_err(|_| Error::IncorrectSignatureLength)?,
            ),
            Algorithm::EdDSA => Self::EdDSA(
                signature
                    .try_into()
                    .map_err(|_| Error::IncorrectSignatureLength)?,
            ),
            Algorithm::RS256 => Self::RS256(signature),
            Algorithm::RS512 => Self::RS512(signature),
            Algorithm::ES256K => Self::ES256K(
                signature
                    .try_into()
                    .map_err(|_| Error::IncorrectSignatureLength)?,
            ),
            _ => return Err(Error::UnsupportedAlgorithm),
        })
    }

    pub fn bytes(&self) -> &[u8] {
        match self {
            Self::ES256(sig) => sig,
            Self::ES512(sig) => sig,
            Self::EdDSA(sig) => sig,
            Self::RS256(sig) => sig,
            Self::RS512(sig) => sig,
            Self::ES256K(sig) => sig,
        }
    }

    pub fn alg(&self) -> Algorithm {
        match self {
            Signature::ES256(_) => Algorithm::ES256,
            Signature::ES512(_) => Algorithm::ES256,
            Signature::EdDSA(_) => Algorithm::EdDSA,
            Signature::RS256(_) => Algorithm::RS256,
            Signature::RS512(_) => Algorithm::RS512,
            Signature::ES256K(_) => Algorithm::ES256K,
        }
    }
}

impl<F, A> Ucan<F, A, Signature> {
    /// Get the JOSE Algorithm of the UCAN
    pub fn algorithm(&self) -> Algorithm {
        self.signature.alg()
    }

    /// Get the Signature bytes of the UCAN
    pub fn sig_bytes(&self) -> &[u8] {
        &self.signature.bytes()
    }
}

impl JwtSignatureSer for Signature {
    type Alg<'a> = Algorithm;
    type Signature<'s> = &'s [u8];
    fn alg(&self) -> Self::Alg<'_> {
        self.alg()
    }
    fn sig(&self) -> Self::Signature<'_> {
        self.bytes()
    }
}

impl JwtSignatureDe for Signature {
    type Alg = Algorithm;
    type Signature = Vec<u8>;
    type Error = Error;
    fn from_header(a: Self::Alg, s: Self::Signature) -> Result<Self, Self::Error> {
        Self::new(a, s)
    }
}
