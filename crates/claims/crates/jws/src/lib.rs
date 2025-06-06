//! JSON Web Signature (JWS) implementation following [RFC 7515] and [RFC 7797]
//! (Unencoded Payload Option).
//!
//! # Usage
//!
//! The entry point to store and verify JWS is the [`&Jws`][Jws] type, borrowing
//! the JWS, just like a `&str` borrows a text string.
//! The [`JwsBuf`] type is the owned version of this type, owning the JWS,
//! just like a [`String`] owns a text string.
//!
//! # Decoding & Verification
//!
//! Use [`JwsSlice::verify`] to decode a JWS.
//!
//! ```
//! # #[cfg(feature = "secp256r1")]
//! # async_std::task::block_on(async {
//! use serde_json::json;
//! use ssi_jwk::JWK;
//! use ssi_jws::Jws;
//!
//! let jws = Jws::new(b"eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA.LW6XkHmgfNnb2CA-2qdeMVGpekAoxRNsAHoeLpnton3QMaQ3dMj-5G9SlP8dHj7cHf2HtRPdy6-9LbxYKvumKw").unwrap();
//!
//! let jwk: JWK = json!({
//!     "kty": "EC",
//!     "use": "sig",
//!     "crv": "P-256",
//!     "x": "dxdB360AJqJFYhdctoKZD_a_P6vLGAxtEVaCLnyraXQ",
//!     "y": "iH6o0l5AECsfRuEw2Eghbrp-6Fob3j98-1Cbe1YOmwM",
//!     "alg": "ES256"
//! }).try_into().unwrap();
//!
//! assert!(jws.verify(&jwk).await.unwrap().is_ok());
//! # })
//! ```
//!
//! Internally [`JwsSlice::verify`] uses [`JwsSlice::decode`] to decode
//! the JWS, then [`DecodedJws::verify`] to validate the signature.
//!
//! [`DecodedJws::verify`]: DecodedJws::verify
//!
//! ```ignore
//! let decoded_jws = jws.to_decoded().unwrap();
//! let verifiable_jws = decoded_jws.into_verifiable().await.unwrap();
//! assert_eq!(verifiable_jws.verify(&jwk).await.unwrap().is_ok());
//! ```
//!
//! You can use this method to decode the payload before the verification
//! (using [`DecodedJws::try_map`] for instance) so it can be verified along the
//! signature.
//!
//! # Signature
//!
//! Use the [`JwsPayload::sign`] method to sign a payload into a compact JWS.
//!
//! ```
//! # #[cfg(feature = "secp256r1")]
//! # async_std::task::block_on(async {
//! use serde_json::json;
//! use ssi_jwk::JWK;
//! use ssi_jws::JwsPayload;
//!
//! let jwk: JWK = json!({
//!     "kty": "EC",
//!     "d": "3KSLs0_obYeQXfEI9I3BBH5y7aOm028bEx3rW6i5UN4",
//!     "use": "sig",
//!     "crv": "P-256",
//!     "x": "dxdB360AJqJFYhdctoKZD_a_P6vLGAxtEVaCLnyraXQ",
//!     "y": "iH6o0l5AECsfRuEw2Eghbrp-6Fob3j98-1Cbe1YOmwM",
//!     "alg": "ES256"
//! }).try_into().unwrap();
//!
//! let jwt = "payload".sign(&jwk).await.unwrap();
//! assert_eq!(jwt, "eyJhbGciOiJFUzI1NiJ9.cGF5bG9hZA.LW6XkHmgfNnb2CA-2qdeMVGpekAoxRNsAHoeLpnton3QMaQ3dMj-5G9SlP8dHj7cHf2HtRPdy6-9LbxYKvumKw")
//! # })
//! ```
//!
//! # URL safety and JWS types
//!
//! [RFC 7515] originally defines JWS as URL safe strings due to the payload
//! being base64 URL-safe encoded.
//! However, [RFC 7797] introduces a `b64` header option that makes this
//! encoding optional. If set to `false`, the JWS may not be URL-safe. In fact
//! it may not be UTF-8 encoded at all.
//!
//! To deal with these different encoding expectations this library provides
//! three families of types for representing JWS:
//! - [`Jws`] and [`JwsBuf`]: This is the most common type family that follows
//!   [RFC 7515] to the letter, expecting an URL-safe JWS.
//!   It is still possible to use the `b64` header to embed unencoded payloads
//!   but those payloads *must* use URL-safe base64 bytes/characters.
//! - [`JwsStr`] and [`JwsString`]: This family relaxes the URL-safe payload
//!   constraint.
//!   Unencoded payloads may use bytes outside of the URL-safe base64 alphabet,
//!   but they *must* be valid UTF-8 strings. This guarantees that the overall
//!   JWS is a valid UTF-8 string, even if it is not URL-safe.
//! - [`JwsSlice`] and [`JwsVec`]: This family does not imposes any constraint
//!   on unencoded payloads.
//!   There is no guaranty that the overall JWS will be an UTF-8 string.
//!
//! [RFC 7515]: <https://datatracker.ietf.org/doc/html/rfc7515>
//! [RFC 7797]: <https://datatracker.ietf.org/doc/html/rfc7797>
#![cfg_attr(docsrs, feature(doc_auto_cfg))]
pub mod error;
pub use base64::DecodeError as Base64DecodeError;
use base64::Engine;
pub use error::Error;
use serde::{Deserialize, Serialize};
use ssi_claims_core::{
    ProofValidationError, ResolverProvider, ValidateClaims, VerifiableClaims, Verification,
};
use ssi_jwk::{Algorithm, Base64urlUInt, JWKResolver, Params as JWKParams, JWK};
use std::{borrow::Cow, collections::BTreeMap};

pub type VerificationWarnings = Vec<String>;

pub(crate) mod utils;

mod compact;
pub use compact::*;

mod signature;
pub use signature::*;

mod verification;
pub use verification::*;

/// Decoded JWS parts.
#[derive(Clone, PartialEq, Eq)]
pub struct JwsParts<T = Vec<u8>> {
    /// JOSE Header.
    pub header: Header,

    /// Payload.
    pub payload: T,

    /// Signature.
    pub signature: JwsSignature,
}

impl<T> JwsParts<T> {
    pub fn new(header: Header, payload: T, signature: JwsSignature) -> Self {
        Self {
            header,
            payload,
            signature,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> JwsParts<U> {
        JwsParts {
            header: self.header,
            payload: f(self.payload),
            signature: self.signature,
        }
    }

    pub fn try_map<U, E>(self, f: impl FnOnce(T) -> Result<U, E>) -> Result<JwsParts<U>, E> {
        Ok(JwsParts {
            header: self.header,
            payload: f(self.payload)?,
            signature: self.signature,
        })
    }
}

impl<T: ?Sized + ToOwned> JwsParts<Cow<'_, T>> {
    pub fn into_owned(self) -> JwsParts<T::Owned> {
        JwsParts::new(self.header, self.payload.into_owned(), self.signature)
    }
}

/// Decoded JWS.
///
/// JWS with its signing bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedJws<'a, T = Vec<u8>> {
    pub signing_bytes: DecodedSigningBytes<'a, T>,
    pub signature: JwsSignature,
}

impl<'a, T> DecodedJws<'a, T> {
    pub fn new(signing_bytes: DecodedSigningBytes<'a, T>, signature: JwsSignature) -> Self {
        Self {
            signing_bytes,
            signature,
        }
    }

    pub fn header(&self) -> &Header {
        &self.signing_bytes.header
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> DecodedJws<'a, U> {
        DecodedJws::new(self.signing_bytes.map(f), self.signature)
    }

    pub fn try_map<U, E>(self, f: impl FnOnce(T) -> Result<U, E>) -> Result<DecodedJws<'a, U>, E> {
        Ok(DecodedJws::new(
            self.signing_bytes.try_map(f)?,
            self.signature,
        ))
    }

    pub fn into_jws(self) -> JwsParts<T> {
        JwsParts::new(
            self.signing_bytes.header,
            self.signing_bytes.payload,
            self.signature,
        )
    }

    pub fn into_jws_and_signing_bytes(self) -> (JwsParts<T>, Cow<'a, [u8]>) {
        (
            JwsParts::new(
                self.signing_bytes.header,
                self.signing_bytes.payload,
                self.signature,
            ),
            self.signing_bytes.bytes,
        )
    }

    pub fn into_encoded(self) -> JwsVec {
        JwsVec::from_signing_bytes_and_signature(
            self.signing_bytes.bytes.into_owned(),
            self.signature.encode().as_bytes(),
        )
        .unwrap()
    }

    /// Verify the JWS signature.
    ///
    /// This will check the signature and the validity of the decoded payload.
    ///
    /// The `params` argument provides all the verification parameters required
    /// to validate the claims and proof.
    ///
    /// # What verification parameters should I use?
    ///
    /// It really depends on the claims type, but `P` must at least provide
    /// a `JWKResolver` through the `ResolverProvider` trait.
    /// Notable implementors are:
    /// - [`VerificationParameters`](ssi_claims_core::VerificationParameters):
    ///   A good default providing many other common verification parameters that
    ///   are not necessary here.
    /// - [`JWK`]: allows you to put a JWK as `params`, which
    ///   will resolve into itself. Can be useful if you don't need key resolution
    ///   because you know in advance what key was used to sign the JWS.
    ///
    /// # Passing the parameters by reference
    ///
    /// If the validation traits are implemented for `P`, they will be
    /// implemented for `&P` as well. This means the parameters can be passed
    /// by move *or* by reference.
    pub async fn verify<P>(&self, params: P) -> Result<Verification, ProofValidationError>
    where
        T: ValidateJwsHeader<P> + ValidateClaims<P, JwsSignature>,
        P: ResolverProvider,
        P::Resolver: JWKResolver,
    {
        VerifiableClaims::verify(self, params).await
    }
}

impl<T: ?Sized + ToOwned> DecodedJws<'_, &T> {
    pub fn to_owned(&self) -> DecodedJws<'static, T::Owned> {
        DecodedJws {
            signing_bytes: self.signing_bytes.to_owned(),
            signature: self.signature.to_owned(),
        }
    }
}

impl<T: ?Sized + ToOwned> DecodedJws<'_, Cow<'_, T>> {
    pub fn into_owned(self) -> DecodedJws<'static, T::Owned> {
        DecodedJws::new(self.signing_bytes.into_owned(), self.signature)
    }
}

/// JWS decoded signing bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedSigningBytes<'a, T = Vec<u8>> {
    /// Encoded bytes.
    pub bytes: Cow<'a, [u8]>,

    /// Decoded JOSE Header.
    pub header: Header,

    /// Decoded payload.
    pub payload: T,
}

impl<'a, T> DecodedSigningBytes<'a, T> {
    pub fn new(bytes: Cow<'a, [u8]>, header: Header, payload: T) -> Self {
        Self {
            bytes,
            header,
            payload,
        }
    }

    pub fn map<U>(self, f: impl FnOnce(T) -> U) -> DecodedSigningBytes<'a, U> {
        DecodedSigningBytes {
            bytes: self.bytes,
            header: self.header,
            payload: f(self.payload),
        }
    }

    pub fn try_map<U, E>(
        self,
        f: impl FnOnce(T) -> Result<U, E>,
    ) -> Result<DecodedSigningBytes<'a, U>, E> {
        Ok(DecodedSigningBytes {
            bytes: self.bytes,
            header: self.header,
            payload: f(self.payload)?,
        })
    }
}

impl<T: ?Sized + ToOwned> DecodedSigningBytes<'_, &T> {
    pub fn to_owned(&self) -> DecodedSigningBytes<'static, T::Owned> {
        DecodedSigningBytes {
            bytes: Cow::Owned(self.bytes.as_ref().to_owned()),
            header: self.header.clone(),
            payload: self.payload.to_owned(),
        }
    }
}

impl<T: ?Sized + ToOwned> DecodedSigningBytes<'_, Cow<'_, T>> {
    pub fn into_owned(self) -> DecodedSigningBytes<'static, T::Owned> {
        DecodedSigningBytes {
            bytes: Cow::Owned(self.bytes.into_owned()),
            header: self.header,
            payload: self.payload.into_owned(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum DecodeError {
    #[error("invalid header: {0}")]
    Header(InvalidHeader),

    #[error("invalid payload: {0}")]
    Payload(Base64DecodeError),

    #[error("invalid signature: {0}")]
    Signature(Base64DecodeError),
}

/// JOSE Header.
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Eq, Default)]
pub struct Header {
    #[serde(rename = "alg")]
    pub algorithm: Algorithm,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "jku")]
    pub jwk_set_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub jwk: Option<JWK>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "kid")]
    pub key_id: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5u")]
    pub x509_url: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5c")]
    pub x509_certificate_chain: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t")]
    pub x509_thumbprint_sha1: Option<Base64urlUInt>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "x5t#S256")]
    pub x509_thumbprint_sha256: Option<Base64urlUInt>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "typ")]
    pub type_: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "cty")]
    pub content_type: Option<String>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "crit")]
    pub critical: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(rename = "b64")]
    pub base64urlencode_payload: Option<bool>,

    #[serde(skip_serializing_if = "BTreeMap::is_empty")]
    #[serde(flatten)]
    pub additional_parameters: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, thiserror::Error)]
pub enum InvalidHeader {
    #[error(transparent)]
    Base64(Base64DecodeError),

    #[error(transparent)]
    Json(serde_json::Error),
}

impl From<Base64DecodeError> for InvalidHeader {
    fn from(value: Base64DecodeError) -> Self {
        InvalidHeader::Base64(value)
    }
}

impl From<serde_json::Error> for InvalidHeader {
    fn from(value: serde_json::Error) -> Self {
        InvalidHeader::Json(value)
    }
}

impl Header {
    /// Create a new header for a JWS with detached payload.
    ///
    /// Unencoded means the payload will not be base64 encoded
    /// when the `encode_signing_bytes` function is called.
    /// This is done by setting the `b64` header parameter to `true`,
    /// while adding `b64` to the list of critical parameters the
    /// receiver must understand to decode the JWS.
    pub fn new_unencoded(algorithm: Algorithm, key_id: Option<String>) -> Self {
        Self {
            algorithm,
            key_id,
            base64urlencode_payload: Some(false),
            critical: Some(vec!["b64".to_string()]),
            ..Default::default()
        }
    }

    /// Decode a JWS Protected Header.
    pub fn decode(base_64: &[u8]) -> Result<Self, InvalidHeader> {
        let header_json = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(base_64)?;
        Ok(serde_json::from_slice(&header_json)?)
    }

    pub fn to_json_string(&self) -> String {
        serde_json::to_string(self).unwrap()
    }

    pub fn encode(&self) -> String {
        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(self.to_json_string())
    }

    pub fn encode_signing_bytes(&self, payload: &[u8]) -> Vec<u8> {
        let mut result = self.encode().into_bytes();
        result.push(b'.');

        if self.base64urlencode_payload.unwrap_or(true) {
            let encoded_payload = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(payload);
            result.extend(encoded_payload.into_bytes())
        } else {
            result.extend(payload)
        }

        result
    }
}

fn base64_encode_json<T: Serialize>(object: &T) -> Result<String, Error> {
    let json = serde_json::to_string(&object)?;
    Ok(base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(json))
}

#[allow(unreachable_code, unused_variables)]
pub fn sign_bytes(algorithm: Algorithm, data: &[u8], key: &JWK) -> Result<Vec<u8>, Error> {
    let signature = match &key.params {
        #[cfg(all(feature = "rsa", feature = "ring"))]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            let key_pair = ring::signature::RsaKeyPair::try_from(rsa_params)?;
            let padding_alg: &dyn ring::signature::RsaEncoding = match algorithm {
                Algorithm::RS256 => &ring::signature::RSA_PKCS1_SHA256,
                Algorithm::PS256 => &ring::signature::RSA_PSS_SHA256,
                _ => return Err(Error::AlgorithmNotImplemented(algorithm.to_string())),
            };
            let mut sig = vec![0u8; key_pair.public_modulus_len()];
            let rng = ring::rand::SystemRandom::new();
            key_pair.sign(padding_alg, &rng, data, &mut sig)?;
            sig
        }
        #[cfg(all(feature = "rsa", not(feature = "ring")))]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            let private_key = rsa::RsaPrivateKey::try_from(rsa_params)?;
            let padding;
            let hashed;
            match algorithm {
                Algorithm::RS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    padding = rsa::padding::PaddingScheme::new_pkcs1v15_sign(Some(hash));
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                Algorithm::PS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    let rng = rand::rngs::OsRng {};
                    padding =
                        rsa::PaddingScheme::new_pss_with_salt::<sha2::Sha256, _>(rng, hash.size());
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                _ => return Err(Error::AlgorithmNotImplemented(algorithm.to_string())),
            }
            private_key
                .sign(padding, &hashed)
                .map_err(ssi_jwk::Error::from)?
        }
        #[cfg(any(feature = "ring", feature = "ed25519"))]
        JWKParams::OKP(okp) => {
            use blake2::digest::{consts::U32, Digest};
            if algorithm != Algorithm::EdDSA && algorithm != Algorithm::EdBlake2b {
                return Err(Error::UnsupportedAlgorithm(algorithm.to_string()));
            }
            if okp.curve != *"Ed25519" {
                return Err(ssi_jwk::Error::CurveNotImplemented(okp.curve.to_string()).into());
            }
            let hash = match algorithm {
                Algorithm::EdBlake2b => blake2::Blake2b::<U32>::new_with_prefix(data)
                    .finalize()
                    .to_vec(),
                _ => data.to_vec(),
            };
            #[cfg(feature = "ring")]
            {
                let key_pair = ring::signature::Ed25519KeyPair::try_from(okp)?;
                key_pair.sign(&hash).as_ref().to_vec()
            }
            // TODO: SymmetricParams
            #[cfg(all(feature = "ed25519", not(feature = "ring")))]
            {
                let secret = ed25519_dalek::SigningKey::try_from(okp)?;
                use ed25519_dalek::Signer;
                secret.sign(&hash).to_bytes().to_vec()
            }
        }
        #[allow(unused)]
        JWKParams::EC(ec) => match algorithm {
            #[cfg(feature = "secp384r1")]
            Algorithm::ES384 => {
                use p384::ecdsa::{signature::Signer, Signature};
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let secret_key = p384::SecretKey::try_from(ec)?;
                let signing_key = p384::ecdsa::SigningKey::from(secret_key);
                let sig: p384::ecdsa::Signature =
                    signing_key.try_sign(data).map_err(ssi_jwk::Error::from)?;
                sig.to_bytes().to_vec()
            }
            #[cfg(feature = "secp256r1")]
            Algorithm::ES256 => {
                use p256::ecdsa::{signature::Signer, Signature};
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let secret_key = p256::SecretKey::try_from(ec)?;
                let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                let sig: p256::ecdsa::Signature =
                    signing_key.try_sign(data).map_err(ssi_jwk::Error::from)?; // Uses SHA-256 by default.
                sig.to_bytes().to_vec()
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ES256K => {
                use k256::ecdsa::{signature::Signer, Signature};
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let secret_key = k256::SecretKey::try_from(ec)?;
                let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                let sig: Signature = signing_key.try_sign(data).map_err(ssi_jwk::Error::from)?; // Uses SHA-256 by default.
                sig.to_bytes().to_vec()
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ES256KR => {
                use k256::ecdsa::{
                    signature::{digest::Digest, Signer},
                    Signature,
                };
                let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                let secret_key = k256::SecretKey::try_from(ec)?;
                let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                // NOTE: in `k256` version 0.11, `recoverable::Signature`
                //       uses Keccack as default hash function, not sha256.
                //       See: <https://docs.rs/k256/0.11.0/k256/ecdsa/recoverable/struct.Signature.html#impl-PrehashSignature>
                let (sig, rec_id) =
                    signing_key.sign_digest_recoverable(sha2::Sha256::new_with_prefix(data))?;
                let mut res = sig.to_bytes().to_vec();
                res.push(rec_id.to_byte());
                res
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ESKeccakKR => {
                use k256::ecdsa::{
                    signature::{digest::Digest, Signer},
                    Signature,
                };
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let secret_key = k256::SecretKey::try_from(ec)?;
                let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                // NOTE: in `k256` version 0.11, `recoverable::Signature`
                //       uses Keccack as default hash function, not sha256.
                //       See: <https://docs.rs/k256/0.11.0/k256/ecdsa/recoverable/struct.Signature.html#impl-PrehashSignature>
                let (sig, rec_id) = signing_key
                    .sign_digest_recoverable(sha3::Keccak256::new_with_prefix(data))
                    .map_err(ssi_jwk::Error::from)?;
                let mut res = sig.to_bytes().to_vec();
                res.push(rec_id.to_byte());
                res
            }
            #[cfg(feature = "secp256r1")]
            Algorithm::ESBlake2b => {
                use p256::ecdsa::{
                    signature::{
                        digest::{consts::U32, Digest},
                        DigestSigner,
                    },
                    Signature,
                };
                let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                let secret_key = p256::SecretKey::try_from(ec)?;
                let signing_key = p256::ecdsa::SigningKey::from(secret_key);
                let sig: p256::ecdsa::Signature =
                    signing_key.try_sign_digest(blake2::Blake2b::<U32>::new_with_prefix(data))?;
                sig.to_bytes().to_vec()
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ESBlake2bK => {
                use k256::ecdsa::{
                    signature::{
                        digest::{consts::U32, Digest},
                        DigestSigner,
                    },
                    Signature,
                };
                let curve = ec.curve.as_ref().ok_or(Error::MissingCurve)?;
                let secret_key = k256::SecretKey::try_from(ec)?;
                let signing_key = k256::ecdsa::SigningKey::from(secret_key);
                let sig: k256::ecdsa::Signature =
                    signing_key.try_sign_digest(blake2::Blake2b::<U32>::new_with_prefix(data))?;
                sig.to_bytes().to_vec()
            }
            _ => {
                return Err(Error::UnsupportedAlgorithm(algorithm.to_string()));
            }
        },
        _ => {
            return Err(Error::Jwk(ssi_jwk::Error::KeyTypeNotImplemented(Box::new(
                key.to_public(),
            ))))
        }
    };
    clear_on_drop::clear_stack(1);
    Ok(signature)
}

pub fn sign_bytes_b64(algorithm: Algorithm, data: &[u8], key: &JWK) -> Result<String, Error> {
    let signature = sign_bytes(algorithm, data, key)?;
    let sig_b64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(signature);
    Ok(sig_b64)
}

#[allow(unreachable_code, unused_variables, unused_mut)]
pub fn verify_bytes_warnable(
    algorithm: Algorithm,
    data: &[u8],
    key: &JWK,
    signature: &[u8],
) -> Result<VerificationWarnings, Error> {
    let mut warnings = VerificationWarnings::default();
    if let Some(key_algorithm) = key.algorithm {
        if key_algorithm != algorithm
            && !(key_algorithm == Algorithm::EdDSA && algorithm == Algorithm::EdBlake2b)
            && !(key_algorithm == Algorithm::ES256 && algorithm == Algorithm::ESBlake2b)
            && !(key_algorithm == Algorithm::ES256K && algorithm == Algorithm::ESBlake2bK)
            && !(key_algorithm == Algorithm::ES256KR && algorithm == Algorithm::ESBlake2bK)
        {
            return Err(Error::AlgorithmMismatch);
        }
    }
    match &key.params {
        #[cfg(all(feature = "rsa", feature = "ring"))]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            use ring::signature::RsaPublicKeyComponents;
            let public_key = RsaPublicKeyComponents::try_from(rsa_params)?;
            let parameters = match algorithm {
                Algorithm::RS256 => &ring::signature::RSA_PKCS1_2048_8192_SHA256,
                Algorithm::PS256 => &ring::signature::RSA_PSS_2048_8192_SHA256,
                _ => return Err(Error::AlgorithmNotImplemented(algorithm.to_string())),
            };
            public_key.verify(parameters, data, signature)?
        }
        #[cfg(all(feature = "rsa", not(feature = "ring")))]
        JWKParams::RSA(rsa_params) => {
            rsa_params.validate_key_size()?;
            use rsa::PublicKey;
            let public_key = rsa::RsaPublicKey::try_from(rsa_params)?;
            let padding;
            let hashed;
            match algorithm {
                Algorithm::RS256 => {
                    let hash = rsa::hash::Hash::SHA2_256;
                    padding = rsa::padding::PaddingScheme::new_pkcs1v15_sign(Some(hash));
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                Algorithm::PS256 => {
                    let rng = rand::rngs::OsRng {};
                    padding = rsa::PaddingScheme::new_pss::<sha2::Sha256, _>(rng);
                    hashed = ssi_crypto::hashes::sha256::sha256(data);
                }
                _ => return Err(Error::AlgorithmNotImplemented(algorithm.to_string())),
            }
            public_key
                .verify(padding, &hashed, signature)
                .map_err(ssi_jwk::Error::from)?;
        }
        // TODO: SymmetricParams
        #[cfg(any(feature = "ring", feature = "ed25519"))]
        JWKParams::OKP(okp) => {
            use blake2::digest::{consts::U32, Digest};
            if okp.curve != *"Ed25519" {
                return Err(ssi_jwk::Error::CurveNotImplemented(okp.curve.to_string()).into());
            }
            let hash = match algorithm {
                Algorithm::EdBlake2b => <blake2::Blake2b<U32> as Digest>::new_with_prefix(data)
                    .finalize()
                    .to_vec(),
                _ => data.to_vec(),
            };
            #[cfg(feature = "ring")]
            {
                use ring::signature::UnparsedPublicKey;
                let verification_algorithm = &ring::signature::ED25519;
                let public_key = UnparsedPublicKey::new(verification_algorithm, &okp.public_key.0);
                public_key.verify(&hash, signature)?;
            }
            #[cfg(feature = "ed25519")]
            {
                use ed25519_dalek::Verifier;
                let public_key = ed25519_dalek::VerifyingKey::try_from(okp)?;
                let signature: ed25519_dalek::Signature =
                    signature.try_into().map_err(ssi_jwk::Error::from)?;
                public_key
                    .verify(&hash, &signature)
                    .map_err(ssi_jwk::Error::from)?;
            }
        }
        #[allow(unused)]
        JWKParams::EC(ec) => match algorithm {
            #[cfg(feature = "secp256r1")]
            Algorithm::ES256 => {
                use p256::ecdsa::signature::Verifier;
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = p256::PublicKey::try_from(ec)?;
                let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    p256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify(data, &sig)
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ES256K => {
                use k256::ecdsa::signature::Verifier;
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    k256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                let normalized_sig = if let Some(s) = sig.normalize_s() {
                    // For user convenience, output the normalized signature.
                    let sig_normalized_b64 =
                        base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(s.to_bytes());
                    warnings.push(format!(
                        "Non-normalized ES256K signature. Normalized: {sig_normalized_b64}"
                    ));
                    s
                } else {
                    sig
                };
                verifying_key
                    .verify(data, &normalized_sig)
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ES256KR => {
                use k256::ecdsa::{
                    signature::{
                        digest::{consts::U32, Digest},
                        DigestVerifier, Verifier,
                    },
                    RecoveryId, VerifyingKey,
                };
                if signature.len() != 65 {
                    Err(k256::ecdsa::Error::new())?;
                }
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig = k256::ecdsa::Signature::try_from(&signature[..64])
                    .map_err(ssi_jwk::Error::from)?;
                let rec_id = k256::ecdsa::RecoveryId::try_from(signature[64])
                    .map_err(ssi_jwk::Error::from)?;
                match VerifyingKey::recover_from_digest(
                    <sha2::Sha256 as Digest>::new_with_prefix(data),
                    &sig,
                    rec_id,
                ) {
                    Err(_e) => {
                        // Legacy mode: allow using Keccak-256 instead of SHA-256
                        verify_bytes(Algorithm::ESKeccakKR, data, key, signature)?;
                        warnings.push(
                            "Signature uses legacy mode ES256K-R with Keccak-256".to_string(),
                        );
                    }
                    Ok(recovered_key) => match recovered_key == verifying_key {
                        true => (),
                        false => Err(k256::ecdsa::Error::new())?,
                    },
                }
            }
            #[cfg(feature = "eip")]
            Algorithm::ESKeccakKR => {
                use k256::ecdsa::{
                    signature::{
                        digest::{consts::U32, Digest},
                        DigestVerifier, Verifier,
                    },
                    RecoveryId, VerifyingKey,
                };
                if signature.len() != 65 {
                    Err(k256::ecdsa::Error::new())?;
                }
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig = k256::ecdsa::Signature::try_from(&signature[..64])
                    .map_err(ssi_jwk::Error::from)?;
                let rec_id = k256::ecdsa::RecoveryId::try_from(signature[64])
                    .map_err(ssi_jwk::Error::from)?;
                let recovered_key = VerifyingKey::recover_from_digest(
                    sha3::Keccak256::new_with_prefix(data),
                    &sig,
                    rec_id,
                )
                .map_err(ssi_jwk::Error::from)?;
                match recovered_key == verifying_key {
                    true => (),
                    false => Err(k256::ecdsa::Error::new())?,
                }
            }
            #[cfg(feature = "secp256r1")]
            Algorithm::ESBlake2b => {
                use p256::ecdsa::{
                    signature::{
                        digest::{consts::U32, Digest},
                        DigestVerifier,
                    },
                    Signature,
                };
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = p256::PublicKey::try_from(ec)?;
                let verifying_key = p256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    p256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify_digest(
                        <blake2::Blake2b<U32> as Digest>::new_with_prefix(data),
                        &sig,
                    )
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp256k1")]
            Algorithm::ESBlake2bK => {
                use k256::ecdsa::signature::{
                    digest::{consts::U32, Digest},
                    DigestVerifier,
                };
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = k256::PublicKey::try_from(ec)?;
                let verifying_key = k256::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    k256::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify_digest(
                        <blake2::Blake2b<U32> as Digest>::new_with_prefix(data),
                        &sig,
                    )
                    .map_err(ssi_jwk::Error::from)?;
            }
            #[cfg(feature = "secp384r1")]
            Algorithm::ES384 => {
                use p384::ecdsa::signature::Verifier;
                let curve = ec.curve.as_ref().ok_or(ssi_jwk::Error::MissingCurve)?;
                let public_key = p384::PublicKey::try_from(ec)?;
                let verifying_key = p384::ecdsa::VerifyingKey::from(public_key);
                let sig =
                    p384::ecdsa::Signature::try_from(signature).map_err(ssi_jwk::Error::from)?;
                verifying_key
                    .verify(data, &sig)
                    .map_err(ssi_jwk::Error::from)?;
            }
            _ => {
                return Err(Error::UnsupportedAlgorithm(algorithm.to_string()));
            }
        },
        _ => {
            return Err(Error::Jwk(ssi_jwk::Error::KeyTypeNotImplemented(Box::new(
                key.to_public(),
            ))))
        }
    }
    Ok(warnings)
}

pub fn verify_bytes(
    algorithm: Algorithm,
    data: &[u8],
    key: &JWK,
    signature: &[u8],
) -> Result<(), Error> {
    verify_bytes_warnable(algorithm, data, key, signature)?;
    Ok(())
}

/// Recover a key from a signature and message, if the algorithm supports this.  (e.g.
/// [ES256K-R](https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r))
pub fn recover(algorithm: Algorithm, data: &[u8], signature: &[u8]) -> Result<JWK, Error> {
    match algorithm {
        #[cfg(feature = "secp256k1")]
        Algorithm::ES256KR => {
            use k256::ecdsa::VerifyingKey;
            if signature.len() != 65 {
                Err(k256::ecdsa::Error::new())?;
            }
            let sig =
                k256::ecdsa::Signature::try_from(&signature[..64]).map_err(ssi_jwk::Error::from)?;
            let rec_id =
                k256::ecdsa::RecoveryId::try_from(signature[64]).map_err(ssi_jwk::Error::from)?;
            let hash = ssi_crypto::hashes::sha256::sha256(data);
            let digest = k256::elliptic_curve::FieldBytes::<k256::Secp256k1>::from_slice(&hash);
            let recovered_key = VerifyingKey::recover_from_prehash(digest, &sig, rec_id)
                .map_err(ssi_jwk::Error::from)?;
            use ssi_jwk::ECParams;
            let jwk = JWK {
                params: JWKParams::EC(ECParams::from(
                    &k256::PublicKey::from_sec1_bytes(&recovered_key.to_sec1_bytes())
                        .map_err(ssi_jwk::Error::from)?,
                )),
                public_key_use: None,
                key_operations: None,
                algorithm: None,
                key_id: None,
                x509_url: None,
                x509_certificate_chain: None,
                x509_thumbprint_sha1: None,
                x509_thumbprint_sha256: None,
            };
            Ok(jwk)
        }
        #[cfg(feature = "secp256k1")]
        Algorithm::ESKeccakKR => {
            use k256::ecdsa::{signature::digest::Digest, VerifyingKey};
            if signature.len() != 65 {
                Err(k256::ecdsa::Error::new())?;
            }
            let sig =
                k256::ecdsa::Signature::try_from(&signature[..64]).map_err(ssi_jwk::Error::from)?;
            let rec_id =
                k256::ecdsa::RecoveryId::try_from(signature[64]).map_err(ssi_jwk::Error::from)?;
            let recovered_key = VerifyingKey::recover_from_digest(
                sha3::Keccak256::new_with_prefix(data),
                &sig,
                rec_id,
            )
            .map_err(ssi_jwk::Error::from)?;
            use ssi_jwk::ECParams;
            let jwk = JWK::from(JWKParams::EC(ECParams::from(
                &k256::PublicKey::from_sec1_bytes(&recovered_key.to_sec1_bytes())
                    .map_err(ssi_jwk::Error::from)?,
            )));
            Ok(jwk)
        }
        _ => {
            let _ = data;
            let _ = signature;
            Err(Error::UnsupportedAlgorithm(algorithm.to_string()))
        }
    }
}

pub fn detached_sign_unencoded_payload(
    algorithm: Algorithm,
    payload: &[u8],
    key: &JWK,
) -> Result<String, Error> {
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        critical: Some(vec!["b64".to_string()]),
        base64urlencode_payload: Some(false),
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let signing_input = [header_b64.as_bytes(), b".", payload].concat();
    let sig_b64 = sign_bytes_b64(header.algorithm, &signing_input, key)?;
    let jws = header_b64 + ".." + &sig_b64;
    Ok(jws)
}

pub fn prepare_detached_unencoded_payload(
    algorithm: Algorithm,
    payload: &[u8],
) -> Result<(Header, Vec<u8>), Error> {
    let header = Header {
        algorithm,
        critical: Some(vec!["b64".to_string()]),
        base64urlencode_payload: Some(false),
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let signing_input = [header_b64.as_bytes(), b".", payload].concat().to_vec();
    Ok((header, signing_input))
}

pub fn complete_sign_unencoded_payload(header: &Header, sig_b64: &str) -> Result<String, Error> {
    let header_b64 = base64_encode_json(header)?;
    let jws = header_b64 + ".." + sig_b64;
    Ok(jws)
}

pub fn encode_sign(algorithm: Algorithm, payload: &str, key: &JWK) -> Result<String, Error> {
    let header = Header {
        algorithm,
        key_id: key.key_id.clone(),
        ..Default::default()
    };
    encode_sign_custom_header(payload, key, &header)
}

pub fn encode_sign_custom_header(
    payload: &str,
    key: &JWK,
    header: &Header,
) -> Result<String, Error> {
    let header_b64 = base64_encode_json(header)?;
    let payload_b64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(payload);
    let signing_input = header_b64 + "." + &payload_b64;
    let sig_b64 = sign_bytes_b64(header.algorithm, signing_input.as_bytes(), key)?;
    let jws = [signing_input, sig_b64].join(".");
    Ok(jws)
}

pub fn encode_unsigned(payload: &str) -> Result<String, Error> {
    let header = Header {
        algorithm: Algorithm::None,
        ..Default::default()
    };
    let header_b64 = base64_encode_json(&header)?;
    let payload_b64 = base64::prelude::BASE64_URL_SAFE_NO_PAD.encode(payload);
    Ok(header_b64 + "." + &payload_b64 + ".")
}

pub fn split_jws(jws: &str) -> Result<(&str, &str, &str), Error> {
    let mut parts = jws.splitn(3, '.');
    Ok(
        match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(a), Some(b), Some(c), None) => (a, b, c),
            _ => return Err(Error::InvalidJws),
        },
    )
}

pub fn split_detached_jws(jws: &str) -> Result<(&str, &str), Error> {
    let (header_b64, omitted_payload, signature_b64) = split_jws(jws)?;
    if !omitted_payload.is_empty() {
        return Err(Error::InvalidJws);
    }
    Ok((header_b64, signature_b64))
}

/// Decode JWS parts (JOSE header, payload, and signature) into useful values.
/// The payload argument is bytes since it may be unencoded if the b64:false header parameter is used; otherwise it must be a base64url-encoded string. Header and signature are always expected to be base64url-encoded.
/// "crit" (critical) header parameters are checked and disallowed if unrecognized/unsupported.
pub fn decode_jws_parts(
    header_b64: &str,
    payload_enc: &[u8],
    signature_b64: &str,
) -> Result<DecodedJws<'static>, Error> {
    let signature = base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(signature_b64)?;
    let header = Header::decode(header_b64.as_bytes())?;
    let payload = if header.base64urlencode_payload.unwrap_or(true) {
        base64::prelude::BASE64_URL_SAFE_NO_PAD.decode(payload_enc)?
    } else {
        payload_enc.to_vec()
    };
    for name in header.critical.iter().flatten() {
        match name.as_str() {
            "alg" | "jku" | "jwk" | "kid" | "x5u" | "x5c" | "x5t" | "x5t#S256" | "typ" | "cty"
            | "crit" => return Err(Error::InvalidCriticalHeader),
            "b64" => {}
            _ => return Err(Error::UnknownCriticalHeader),
        }
    }
    let signing_input = [header_b64.as_bytes(), b".", payload_enc].concat();
    Ok(DecodedJws::new(
        DecodedSigningBytes::new(Cow::Owned(signing_input), header, payload),
        signature.into(),
    ))
}

/// Verify a JWS with detached payload. Returns the JWS header on success.
pub fn detached_verify(jws: &str, payload_enc: &[u8], key: &JWK) -> Result<Header, Error> {
    let (header_b64, signature_b64) = split_detached_jws(jws)?;
    let (jws, signing_bytes) =
        decode_jws_parts(header_b64, payload_enc, signature_b64)?.into_jws_and_signing_bytes();
    verify_bytes(
        jws.header.algorithm,
        &signing_bytes,
        key,
        jws.signature.as_bytes(),
    )?;
    Ok(jws.header)
}

/// Recover a JWK from a JWS and payload, if the algorithm supports that (such as [ES256K-R](https://github.com/decentralized-identity/EcdsaSecp256k1RecoverySignature2020#es256k-r)).
pub fn detached_recover(jws: &str, payload_enc: &[u8]) -> Result<(Header, JWK), Error> {
    let (header_b64, signature_b64) = split_detached_jws(jws)?;
    let (jws, signing_bytes) =
        decode_jws_parts(header_b64, payload_enc, signature_b64)?.into_jws_and_signing_bytes();
    let key = recover(
        jws.header.algorithm,
        &signing_bytes,
        jws.signature.as_bytes(),
    )?;
    Ok((jws.header, key))
}

pub fn detached_recover_legacy_keccak_es256kr(
    jws: &str,
    payload_enc: &[u8],
) -> Result<(Header, JWK), Error> {
    let (header_b64, signature_b64) = split_detached_jws(jws)?;
    let (mut jws, signing_bytes) =
        decode_jws_parts(header_b64, payload_enc, signature_b64)?.into_jws_and_signing_bytes();
    // Allow ESKeccakK-R misimplementation of ES256K-R, for legacy reasons.
    if jws.header.algorithm != Algorithm::ES256KR {
        return Err(Error::AlgorithmMismatch);
    }
    jws.header.algorithm = Algorithm::ESKeccakKR;
    let key = recover(
        jws.header.algorithm,
        &signing_bytes,
        jws.signature.as_bytes(),
    )?;
    Ok((jws.header, key))
}

pub fn decode_verify(jws: &str, key: &JWK) -> Result<(Header, Vec<u8>), Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;
    let (jws, signing_bytes) = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?
        .into_jws_and_signing_bytes();
    verify_bytes(
        jws.header.algorithm,
        &signing_bytes,
        key,
        jws.signature.as_bytes(),
    )?;
    Ok((jws.header, jws.payload))
}

pub fn decode_unverified(jws: &str) -> Result<(Header, Vec<u8>), Error> {
    let (header_b64, payload_enc, signature_b64) = split_jws(jws)?;
    let jws = decode_jws_parts(header_b64, payload_enc.as_bytes(), signature_b64)?.into_jws();
    Ok((jws.header, jws.payload))
}

#[cfg(test)]
mod tests {
    #[allow(unused_imports)]
    use super::*;

    #[test]
    #[cfg(feature = "rsa")]
    fn jws_encode() {
        // https://tools.ietf.org/html/rfc7515#appendix-A.2
        let payload =
            "{\"iss\":\"joe\",\r\n \"exp\":1300819380,\r\n \"http://example.com/is_root\":true}";

        use serde_json::json;
        // https://tools.ietf.org/html/rfc7515#page-41
        let key: JWK = serde_json::from_value(json!({"kty":"RSA",
         "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
         "e":"AQAB",
         "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ",
         "p":"4BzEEOtIpmVdVEZNCqS7baC4crd0pqnRH_5IB3jw3bcxGn6QLvnEtfdUdiYrqBdss1l58BQ3KhooKeQTa9AB0Hw_Py5PJdTJNPY8cQn7ouZ2KKDcmnPGBY5t7yLc1QlQ5xHdwW1VhvKn-nXqhJTBgIPgtldC-KDV5z-y2XDwGUc", "q":"uQPEfgmVtjL0Uyyx88GZFF1fOunH3-7cepKmtH4pxhtCoHqpWmT8YAmZxaewHgHAjLYsp1ZSe7zFYHj7C6ul7TjeLQeZD_YwD66t62wDmpe_HlB-TnBA-njbglfIsRLtXlnDzQkv5dTltRJ11BKBBypeeF6689rjcJIDEz9RWdc",
         "dp":"BwKfV3Akq5_MFZDFZCnW-wzl-CCo83WoZvnLQwCTeDv8uzluRSnm71I3QCLdhrqE2e9YkxvuxdBfpT_PI7Yz-FOKnu1R6HsJeDCjn12Sk3vmAktV2zb34MCdy7cpdTh_YVr7tss2u6vneTwrA86rZtu5Mbr1C1XsmvkxHQAdYo0",
         "dq":"h_96-mK1R_7glhsum81dZxjTnYynPbZpHziZjeeHcXYsXaaMwkOlODsWa7I9xXDoRwbKgB719rrmI2oKr6N3Do9U0ajaHF-NKJnwgjMd2w9cjz3_-kyNlxAr2v4IKhGNpmM5iIgOS1VZnOZ68m6_pbLBSp3nssTdlqvd0tIiTHU",
         "qi":"IYd7DHOhrWvxkwPQsRM2tOgrjbcrfvtQJipd-DlcxyVuuM9sQLdgjVk2oy26F0EmpScGLq2MowX7fhd_QJQ3ydy5cY7YIBi87w93IKLEdfnbJtoOPLUW0ITrJReOgo1cq9SbsxYawBgfp_gh6A5603k2-ZQwVK0JKSHuLFkuQ3U"
        }))
        .unwrap();

        // https://tools.ietf.org/html/rfc7515#page-43
        let jws = encode_sign(Algorithm::RS256, payload, &key).unwrap();
        assert_eq!(jws, "eyJhbGciOiJSUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.cC4hiUPoj9Eetdgtv3hF80EGrhuB__dzERat0XF9g2VtQgr9PJbu3XOiZj5RZmh7AAuHIm4Bh-0Qc_lF5YKt_O8W2Fp5jujGbds9uJdbF9CUAr7t1dnZcAcQjbKBYNX4BAynRFdiuB--f_nZLgrnbyTyWzO75vRK5h6xBArLIARNPvkSjtQBMHlb1L07Qe7K0GarZRmB_eSN9383LcOLn6_dO--xi12jzDwusC-eOkHWEsqtFZESc6BfI7noOPqvhJ1phCnvWh6IeYI2w9QOYEUipUTI8np6LbgGY9Fs98rqVt5AXLIhWkWywlVmtVrBp0igcN_IoypGlUPQGe77Rw");

        decode_verify(&jws, &key).unwrap();
    }

    #[test]
    #[cfg(feature = "secp256k1")]
    fn secp256k1_sign_verify() {
        let key = JWK::generate_secp256k1();
        let data = b"asdf";
        let bad_data = b"no";
        let sig = sign_bytes(Algorithm::ES256K, data, &key).unwrap();
        verify_bytes(Algorithm::ES256K, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256K, bad_data, &key, &sig).unwrap_err();

        // ES256K-R
        let key = JWK {
            algorithm: Some(Algorithm::ES256KR),
            ..key
        };
        verify_bytes(Algorithm::ES256KR, data, &key, &sig).unwrap_err();
        verify_bytes(Algorithm::ES256KR, bad_data, &key, &sig).unwrap_err();

        // Test recovery
        let sig = sign_bytes(Algorithm::ES256KR, data, &key).unwrap();
        verify_bytes(Algorithm::ES256KR, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256KR, bad_data, &key, &sig).unwrap_err();
        let recovered_key = recover(Algorithm::ES256KR, data, &sig).unwrap();
        verify_bytes(Algorithm::ES256KR, data, &recovered_key, &sig).unwrap();
        let other_key = JWK::generate_secp256k1();
        verify_bytes(Algorithm::ES256KR, data, &other_key, &sig).unwrap_err();
    }

    #[test]
    #[cfg(feature = "eip")]
    fn keccak_sign_verify() {
        let key = JWK::generate_secp256k1();
        let data = b"asdf";
        let bad_data = b"no";
        // ESKeccakK-R
        let key = JWK {
            algorithm: Some(Algorithm::ESKeccakKR),
            ..key
        };

        let sig = sign_bytes(Algorithm::ES256KR, data, &key).unwrap();
        let other_key = JWK::generate_secp256k1();
        // TODO check the error type
        verify_bytes(Algorithm::ESKeccakKR, data, &key, &sig).unwrap_err();
        verify_bytes(Algorithm::ESKeccakKR, bad_data, &key, &sig).unwrap_err();

        // Test recovery (ESKeccakK-R)
        let sig = sign_bytes(Algorithm::ESKeccakKR, data, &key).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, bad_data, &key, &sig).unwrap_err();
        let recovered_key = recover(Algorithm::ESKeccakKR, data, &sig).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, data, &recovered_key, &sig).unwrap();
        verify_bytes(Algorithm::ESKeccakKR, data, &other_key, &sig).unwrap_err();
    }

    #[test]
    #[cfg(feature = "secp256r1")]
    fn p256_sign_verify() {
        let key = JWK::generate_p256();
        let data = b"asdf";
        let bad_data = b"no";
        let sig = sign_bytes(Algorithm::ES256, data, &key).unwrap();
        verify_bytes(Algorithm::ES256, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES256, bad_data, &key, &sig).unwrap_err();

        let key: JWK = serde_json::from_str(include_str!(
            "../../../../../tests/secp256r1-2021-03-18.json"
        ))
        .unwrap();
        let payload = "{\"iss\":\"did:example:foo\",\"vp\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":\"VerifiablePresentation\"}}";
        let jws = encode_sign(Algorithm::ES256, payload, &key).unwrap();
        assert_eq!(jws, "eyJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpmb28iLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJ9fQ.rJzO6MmTNS8Tn-L3baIf9_2Jr9OoK8E06MxJtofz8xMUGSom6eRUmWGZ7oQVjgP3HogOD80miTvuvKTWa54Nvw");
        decode_verify(&jws, &key).unwrap();
    }

    #[test]
    #[cfg(feature = "secp384r1")]
    fn p384_sign_verify() {
        let key = JWK::generate_p384();
        let data = b"asdf";
        let bad_data = b"no";
        let sig = sign_bytes(Algorithm::ES384, data, &key).unwrap();
        verify_bytes(Algorithm::ES384, data, &key, &sig).unwrap();
        verify_bytes(Algorithm::ES384, bad_data, &key, &sig).unwrap_err();

        let key: JWK = serde_json::from_str(include_str!(
            "../../../../../tests/secp384r1-2022-05-10.json"
        ))
        .unwrap();
        let payload = "{\"iss\":\"did:example:foo\",\"vp\":{\"@context\":[\"https://www.w3.org/2018/credentials/v1\"],\"type\":\"VerifiablePresentation\"}}";
        let jws = encode_sign(Algorithm::ES384, payload, &key).unwrap();
        dbg!(&jws);
        decode_verify(&jws, &key).unwrap();

        const JWS: &str = "eyJhbGciOiJFUzM4NCJ9.eyJpc3MiOiJkaWQ6ZXhhbXBsZTpmb28iLCJ2cCI6eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvMjAxOC9jcmVkZW50aWFscy92MSJdLCJ0eXBlIjoiVmVyaWZpYWJsZVByZXNlbnRhdGlvbiJ9fQ.2vpBSFN7DxuS57epgq_e7-NyNiJ5eOOrExmi65C_wtZOC2-9i6fVvMnfUig7QmgiirznAg1wr_b7_kH-bbMCI5Pdf8pAnxQg3LL9I9OhzttyG06qAl9L7BE6aNS-aqnf";
        decode_verify(JWS, &key).unwrap();
    }
}
