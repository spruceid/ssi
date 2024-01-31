//! Error types for `ssi-jwk` crate
#[cfg(feature = "aleo")]
use crate::aleo::AleoGeneratePrivateKeyError;
use base64::DecodeError as Base64Error;
#[cfg(feature = "ring")]
use ring::error::{KeyRejected as KeyRejectedError, Unspecified as RingUnspecified};
#[cfg(feature = "rsa")]
use rsa::errors::Error as RsaError;
use simple_asn1::ASN1EncodeErr as ASN1EncodeError;
use std::array::TryFromSliceError;
use std::char::CharTryFromError;
use std::num::ParseIntError;
use std::string::FromUtf8Error;
use thiserror::Error;

/// Error type for `ssi-jwk`.
#[derive(Error, Debug)]
#[non_exhaustive]
pub enum Error {
    /// Missing curve in JWK
    #[error("Missing curve in JWK")]
    MissingCurve,
    /// Missing elliptic curve point in JWK
    #[error("Missing elliptic curve point in JWK")]
    MissingPoint,
    /// Missing key value for symmetric key
    #[error("Missing key value for symmetric key")]
    MissingKeyValue,
    /// Key type is not supported
    #[error("Key type not supported")]
    UnsupportedKeyType,
    /// Key type not implemented
    #[error("Key type not implemented")]
    KeyTypeNotImplemented,
    /// Curve not implemented
    #[error("Curve not implemented: '{0}'")]
    CurveNotImplemented(String),
    /// Missing private key parameter in JWK
    #[error("Missing private key parameter in JWK")]
    MissingPrivateKey,
    /// Missing modulus in RSA key
    #[error("Missing modulus in RSA key")]
    MissingModulus,
    /// Missing exponent in RSA key
    #[error("Missing exponent in RSA key")]
    MissingExponent,
    /// Missing prime in RSA key
    #[error("Missing prime in RSA key")]
    MissingPrime,
    /// Invalid key length
    #[error("Invalid key length: {0}")]
    InvalidKeyLength(usize),
    /// Error parsing a key with `ring`
    #[cfg(feature = "ring")]
    #[error("{0}")]
    KeyRejected(KeyRejectedError),
    /// Unspecified Error using `ring`
    #[cfg(feature = "ring")]
    #[error("{0}")]
    RingUnspecified(RingUnspecified),
    /// Error parsing a UTF-8 string
    #[error(transparent)]
    FromUtf8(#[from] FromUtf8Error),
    /// Error from `rsa` crate
    #[cfg(feature = "rsa")]
    #[error(transparent)]
    Rsa(#[from] RsaError),
    /// Error encoding ASN.1 data structure.
    #[error(transparent)]
    ASN1Encode(#[from] ASN1EncodeError),
    /// Error decoding Base64
    #[error(transparent)]
    Base64(#[from] Base64Error),
    /// Error parsing integer
    #[error(transparent)]
    ParseInt(#[from] ParseIntError),
    /// Error eip155 encoding a JWK
    #[error(transparent)]
    Eip155(#[from] ssi_crypto::hashes::keccak::Eip155Error),
    /// Error parsing a char
    #[error(transparent)]
    CharTryFrom(#[from] CharTryFromError),
    /// Error converting slice to array
    #[error(transparent)]
    TryFromSlice(#[from] TryFromSliceError),
    /// Error generating Aleo private key
    #[cfg(feature = "aleo")]
    #[error(transparent)]
    AleoGeneratePrivateKey(#[from] AleoGeneratePrivateKeyError),
    /// Expected 64 byte uncompressed key or 33 bytes compressed key
    #[error("Expected 64 byte uncompressed key or 33 bytes compressed key but found length: {0}")]
    P256KeyLength(usize),
    /// Expected 96 byte uncompressed key or 49 bytes compressed key (P-384)
    #[error("Expected 96 byte uncompressed key or 49 bytes compressed key but found length: {0}")]
    P384KeyLength(usize),
    /// Unable to decompress elliptic curve
    #[error("Unable to decompress elliptic curve")]
    ECDecompress,
    /// Errors from p256, k256 and ed25519-dalek
    #[cfg(feature = "k256")]
    #[error(transparent)]
    CryptoErr(#[from] k256::ecdsa::Error),
    #[cfg(all(feature = "p256", not(feature = "k256")))]
    #[error(transparent)]
    CryptoErr(#[from] p256::ecdsa::Error),
    #[cfg(all(feature = "ed25519", not(feature = "k256"), not(feature = "p256")))]
    #[error(transparent)]
    CryptoErr(#[from] ed25519_dalek::ed25519::Error),
    /// Error from `elliptic-curve` crate
    #[cfg(feature = "k256")]
    #[error(transparent)]
    EC(#[from] k256::elliptic_curve::Error),
    #[cfg(all(feature = "p256", not(feature = "k256")))]
    #[error(transparent)]
    EC(#[from] p256::elliptic_curve::Error),
    #[cfg(all(feature = "p384", not(any(feature = "p256", feature = "k256"))))]
    #[error(transparent)]
    EC(#[from] p384::elliptic_curve::Error),
    /// Unexpected length for publicKeyMultibase
    #[error("Unexpected length for publicKeyMultibase")]
    MultibaseKeyLength(usize, usize),
    /// Unexpected multibase (multicodec) key prefix multicodec
    #[error("Unexpected multibase (multicodec) key prefix multicodec")]
    MultibaseKeyPrefix,
    /// Error parsing or producing multibase
    #[error(transparent)]
    Multibase(#[from] multibase::Error),
}

#[cfg(feature = "ring")]
impl From<KeyRejectedError> for Error {
    fn from(e: KeyRejectedError) -> Error {
        Error::KeyRejected(e)
    }
}

#[cfg(feature = "ring")]
impl From<RingUnspecified> for Error {
    fn from(e: RingUnspecified) -> Error {
        Error::RingUnspecified(e)
    }
}
