use super::{
    jose::Signature, jwt::DummyHeader, version::SemanticVersion, webauthn::Webauthn, Error, Ucan,
};
use libipld::{codec::Codec, error::Error as IpldError, json::DagJsonCodec, serde::to_ipld, Cid};
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
    pub fn sign_canonicalized_jws(
        self,
        alg: Algorithm,
        key: &JWK,
    ) -> Result<Ucan<Signature, F, A>, Error>
    where
        F: Serialize,
        A: Serialize,
    {
        let signature = sign_bytes(alg, self.encode_for_signing_jws(alg)?.as_bytes(), key)?;

        Ok(self.sign_jws(Signature::new_jws(alg, signature)?))
    }

    pub fn encode_for_signing_jws(&self, alg: Algorithm) -> Result<String, Error>
    where
        F: Serialize,
        A: Serialize,
    {
        Ok([
            base64::encode_config(
                DagJsonCodec.encode(&to_ipld(&DummyHeader::new(alg)).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(
                DagJsonCodec.encode(&to_ipld(&self).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
        ]
        .join(".")
        .into())
    }

    pub fn encode_for_signing_webauthn(&self) -> Result<String, Error>
    where
        F: Serialize,
        A: Serialize,
    {
        Ok([
            base64::encode_config(
                DagJsonCodec
                    .encode(&to_ipld(&DummyHeader::new("webauthn")).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(
                DagJsonCodec.encode(&to_ipld(&self).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
        ]
        .join(".")
        .into())
    }

    /// Sign the payload with the given header and signature
    ///
    /// This will not ensure that the signature is valid for the payload and will
    /// not canonicalize the payload before signing.
    pub fn sign_jws(self, signature: Signature) -> Ucan<Signature, F, A> {
        Ucan {
            payload: self,
            signature,
        }
    }

    /// Sign the payload with the given header and signature
    ///
    /// This will not ensure that the signature is valid for the payload and will
    /// not canonicalize the payload before signing.
    pub fn sign_webauthn(self, signature: Webauthn) -> Ucan<Webauthn, F, A> {
        Ucan {
            payload: self,
            signature,
        }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum TimeInvalid {
    #[error("UCAN not yet valid")]
    TooEarly,
    #[error("UCAN has expired")]
    TooLate,
}

pub fn now() -> u64 {
    chrono::prelude::Utc::now().timestamp() as u64
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
