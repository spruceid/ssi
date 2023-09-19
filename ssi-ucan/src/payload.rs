use super::{jose, jwt, version::SemanticVersion, Ucan};
use libipld::Cid;
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::{serde_as, DisplayFromStr};
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::sign_bytes;
use std::collections::BTreeMap;

use capabilities::Capabilities;
pub use ucan_capabilities_object as capabilities;

/// The Payload of a UCAN, with JWS registered claims and UCAN specific claims
#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash)]
#[serde(deny_unknown_fields)]
pub struct Payload<F = JsonValue, A = JsonValue> {
    #[serde(rename = "ucv")]
    semantic_version: SemanticVersion,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "aud")]
    pub audience: String,
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none", default)]
    pub issued_at: Option<u64>,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none", default)]
    pub not_before: Option<u64>,
    // no expiration should serialize to null in JSON
    #[serde(rename = "exp")]
    pub expiration: Option<u64>,
    #[serde(rename = "nnc", skip_serializing_if = "Option::is_none", default)]
    pub nonce: Option<String>,
    #[serde(
        rename = "fct",
        skip_serializing_if = "Option::is_none",
        default = "Option::default"
    )]
    pub facts: Option<BTreeMap<String, F>>,
    #[serde_as(as = "Option<Vec<DisplayFromStr>>")]
    #[serde(rename = "prf", skip_serializing_if = "Option::is_none", default)]
    pub proof: Option<Vec<Cid>>,
    #[serde(rename = "cap")]
    pub capabilities: Capabilities<A>,
}

impl<F, A> Payload<F, A> {
    /// Create a new UCAN payload
    pub fn new(issuer: String, audience: String) -> Self {
        Self {
            semantic_version: SemanticVersion,
            issuer,
            audience,
            issued_at: None,
            not_before: None,
            expiration: None,
            nonce: None,
            facts: None,
            proof: None,
            capabilities: Capabilities::new(),
        }
    }

    /// Validate the time bounds of the UCAN payload
    ///
    /// Passing `None` will use the current system time.
    pub fn validate_time<T: PartialOrd<u64>>(&self, time: Option<T>) -> Result<(), TimeInvalid> {
        match time {
            Some(t) => cmp_time(t, self.not_before, self.expiration),
            None => cmp_time(now(), self.not_before, self.expiration),
        }
    }

    /// Sign the payload with the given key and algorithm
    ///
    /// This will use the canonical form of the UCAN for signing
    pub fn sign_with_jwk(self, key: &JWK, algorithm: Option<Algorithm>) -> Result<Ucan<F, A>, Error>
    where
        F: Serialize,
        A: Serialize,
    {
        let alg = algorithm.or(key.algorithm).ok_or(Error::AlgUnknown)?;
        let signature = sign_bytes(alg, self.encode_for_signing_jwt(alg)?.as_ref(), key)?;

        Ok(self.sign(jose::Signature::new(alg, signature)?))
    }

    /// Encode the payload and header in cannonical form for signing
    pub fn encode_for_signing_jwt<Alg>(&self, alg: Alg) -> Result<String, jwt::EncodeError>
    where
        F: Serialize,
        A: Serialize,
        Alg: Serialize,
    {
        Ok([
            base64::encode_config(
                serde_jcs::to_string(&jwt::DummyHeader::new(alg))?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(serde_jcs::to_string(&self)?, base64::URL_SAFE_NO_PAD),
        ]
        .join("."))
    }

    /// Sign the payload with the given signature
    ///
    /// This will not ensure that the signature is valid for the payload and will
    /// not canonicalize the payload before signing.
    pub fn sign<S>(self, signature: S) -> Ucan<F, A, S> {
        Ucan {
            payload: self,
            signature,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Unable to infer algorithm")]
    AlgUnknown,
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    Encoding(#[from] jwt::EncodeError),
    #[error(transparent)]
    InvalidSignature(#[from] jose::Error),
}

#[derive(thiserror::Error, Debug)]
pub enum TimeInvalid {
    #[error("UCAN not yet valid")]
    TooEarly,
    #[error("UCAN has expired")]
    TooLate,
}

fn now() -> f64 {
    (chrono::prelude::Utc::now()
        .timestamp_nanos_opt()
        .expect("value can not be represented in a timestamp with nanosecond precision.")
        as f64)
        / 1e+9_f64
}

fn cmp_time<T: PartialOrd<u64>>(
    t: T,
    nbf: Option<u64>,
    exp: Option<u64>,
) -> Result<(), TimeInvalid> {
    match (nbf, exp) {
        (_, Some(exp)) if t >= exp => Err(TimeInvalid::TooLate),
        (Some(nbf), _) if t < nbf => Err(TimeInvalid::TooEarly),
        _ => Ok(()),
    }
}
