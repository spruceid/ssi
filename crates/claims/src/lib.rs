//! Verifiable Claims.
use ::serde::{Deserialize, Serialize};
use data_integrity::{
    CloneCryptographicSuite, CryptographicSuite, DataIntegrity, DebugCryptographicSuite,
    DeserializeCryptographicSuite, SerializeCryptographicSuite,
};
use educe::Educe;
pub use ssi_claims_core::*;

/// JSON Web signature (JWS).
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7515>
pub use ssi_jws as jws;

pub use jws::{CompactJWS, CompactJWSBuf, CompactJWSStr, CompactJWSString, JWSPayload};

/// JSON Web tokens (JWT).
///
/// See: <https://datatracker.ietf.org/doc/html/rfc7519>
pub use ssi_jwt as jwt;

pub use jwt::JWTClaims;

/// Selective Disclosure for JWTs (SD-JWT).
///
/// See: <https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-08.html>
pub use ssi_sd_jwt as sd_jwt;

/// W3C Verifiable Credentials (VC).
///
/// See: <https://www.w3.org/TR/vc-data-model>
pub use ssi_vc as vc;

pub use vc::{
    Credential, JsonCredential, JsonPresentation, Presentation, SpecializedJsonCredential,
    VerifiableCredential, VerifiablePresentation,
};

/// Data-Integrity Proofs.
///
/// See: <https://www.w3.org/TR/vc-data-integrity>
pub use ssi_data_integrity as data_integrity;

/// JSON-like verifiable credential or JWS (presumably JWT).
#[derive(Educe, Serialize, Deserialize)]
#[serde(
    untagged,
    bound(
        serialize = "S: SerializeCryptographicSuite",
        deserialize = "S: DeserializeCryptographicSuite<'de>"
    )
)]
#[educe(Clone(bound("S: CloneCryptographicSuite")))]
#[educe(Debug(bound("S: DebugCryptographicSuite")))]
pub enum JsonCredentialOrJws<S: CryptographicSuite = data_integrity::AnySuite> {
    /// JSON-like verifiable credential.
    Credential(DataIntegrity<vc::JsonCredential, S>),

    /// JSON Web Signature.
    Jws(jws::CompactJWSString),
}

/// JSON-like verifiable presentation or JWS (presumably JWT).
#[derive(Educe, Serialize, Deserialize)]
#[serde(
    untagged,
    bound(
        serialize = "S: SerializeCryptographicSuite",
        deserialize = "S: DeserializeCryptographicSuite<'de>"
    )
)]
#[educe(Clone(bound("S: CloneCryptographicSuite")))]
#[educe(Debug(bound("S: DebugCryptographicSuite")))]
pub enum JsonPresentationOrJws<S: CryptographicSuite = data_integrity::AnySuite> {
    /// JSON-like verifiable presentation.
    Presentation(DataIntegrity<vc::JsonPresentation, S>),

    /// JSON Web Signature.
    Jws(jws::CompactJWSString),
}
