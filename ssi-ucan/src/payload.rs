use super::{version::SemanticVersion, Error, Ucan};
use libipld::{codec::Codec, error::Error as IpldError, json::DagJsonCodec, serde::to_ipld, Cid};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::{serde_as, DisplayFromStr};
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{sign_bytes, Header};
use std::collections::BTreeMap;

use capabilities::Capabilities;
pub use ucan_capabilities_object as capabilities;

/// The Payload of a UCAN, with JWS registered claims and UCAN specific claims
#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug, Hash)]
pub struct Payload<F = JsonValue, A = JsonValue> {
    #[serde(rename = "ucv")]
    semantic_version: SemanticVersion,
    #[serde(rename = "iss")]
    issuer: String,
    #[serde(rename = "aud")]
    audience: String,
    #[serde(rename = "iat", skip_serializing_if = "Option::is_none", default)]
    issued_at: Option<u64>,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none", default)]
    not_before: Option<u64>,
    // no expiration should serialize to null in JSON
    #[serde(rename = "exp")]
    expiration: Option<u64>,
    #[serde(rename = "nnc", skip_serializing_if = "Option::is_none", default)]
    nonce: Option<String>,
    #[serde(
        rename = "fct",
        skip_serializing_if = "Option::is_none",
        default = "Option::default"
    )]
    facts: Option<BTreeMap<String, F>>,
    #[serde_as(as = "Option<Vec<DisplayFromStr>>")]
    #[serde(rename = "prf", skip_serializing_if = "Option::is_none", default)]
    proof: Option<Vec<Cid>>,
    #[serde(rename = "cap")]
    capabilities: Capabilities<A>,
}

impl<F, A> Payload<F, A> {
    /// Create a new UCAN payload builder
    pub fn builder(issuer: String, audience: String) -> PayloadBuilder<F, A> {
        PayloadBuilder::new(issuer, audience)
    }

    /// Get the issuer of the UCAN payload
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Get the audience of the UCAN payload
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// Get the issuance time of the UCAN payload
    pub fn issued_at(&self) -> Option<u64> {
        self.issued_at
    }

    /// Get the starting validity time of the UCAN payload
    pub fn not_before(&self) -> Option<u64> {
        self.not_before
    }

    /// Get the expiration time of the UCAN payload
    pub fn expiration(&self) -> Option<u64> {
        self.expiration
    }

    /// Get the nonce of the UCAN payload
    pub fn nonce(&self) -> Option<&str> {
        self.nonce.as_deref()
    }

    /// Get the facts of the UCAN payload
    pub fn facts(&self) -> Option<&BTreeMap<String, F>> {
        self.facts.as_ref()
    }

    /// Get the supporting proof set of the UCAN payload
    pub fn proof(&self) -> Option<&[Cid]> {
        self.proof.as_deref()
    }

    /// Get the capabilities of the UCAN payload
    pub fn capabilities(&self) -> &Capabilities<A> {
        &self.capabilities
    }

    /// Validate the time bounds of the UCAN payload
    ///
    /// Passing `None` will use the current system time.
    pub fn validate_time<T: PartialOrd<u64>>(&self, time: Option<T>) -> Result<(), TimeInvalid> {
        match time {
            Some(t) => cmp_time(t, self.not_before(), self.expiration()),
            None => cmp_time(now(), self.not_before(), self.expiration()),
        }
    }

    /// Sign the payload with the given key and algorithm
    ///
    /// This will use the canonical form of the UCAN for signing
    pub fn sign_canonicalized(self, algorithm: Algorithm, key: &JWK) -> Result<Ucan<F, A>, Error>
    where
        F: Serialize,
        A: Serialize,
    {
        let header = Header {
            algorithm,
            type_: Some("JWT".to_string()),
            jwk: if self.issuer.starts_with("did:pkh:") {
                Some(key.to_public())
            } else {
                None
            },
            ..Default::default()
        };

        let signature = sign_bytes(
            algorithm,
            [
                base64::encode_config(
                    DagJsonCodec.encode(&to_ipld(&header).map_err(IpldError::new)?)?,
                    base64::URL_SAFE_NO_PAD,
                ),
                base64::encode_config(
                    DagJsonCodec.encode(&to_ipld(&self).map_err(IpldError::new)?)?,
                    base64::URL_SAFE_NO_PAD,
                ),
            ]
            .join(".")
            .as_bytes(),
            key,
        )?;

        Ok(self.sign(header, signature))
    }

    /// Sign the payload with the given header and signature
    ///
    /// This will not ensure that the header and signature are valid for the payload and will
    /// not canonicalize the payload before signing. All header fields except for `alg` and `jwk`
    /// will be ignored.
    pub fn sign(self, mut header: Header, signature: Vec<u8>) -> Ucan<F, A> {
        header = Header {
            algorithm: header.algorithm,
            type_: Some("JWT".to_string()),
            jwk: header.jwk,
            ..Default::default()
        };
        Ucan {
            header,
            payload: self,
            signature,
        }
    }
}

/// A builder for a UCAN payload
#[derive(Clone, PartialEq, Eq, Debug, Hash)]
pub struct PayloadBuilder<F, A> {
    issuer: String,
    audience: String,
    issued_at: Option<u64>,
    not_before: Option<u64>,
    expiration: Option<u64>,
    nonce: Option<String>,
    facts: Option<BTreeMap<String, F>>,
    proof: Option<Vec<Cid>>,
    capabilities: Capabilities<A>,
}

impl<F, A> PayloadBuilder<F, A> {
    fn new(issuer: String, audience: String) -> Self {
        Self {
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

    /// Set the issuance time of the UCAN payload
    pub fn issued_at(&mut self, issued_at: u64) -> &mut Self {
        self.issued_at = Some(issued_at);
        self
    }

    /// Set the starting validity time of the UCAN payload
    pub fn not_before(&mut self, not_before: u64) -> &mut Self {
        self.not_before = Some(not_before);
        self
    }

    /// Set the expiration time of the UCAN payload
    pub fn expiration(&mut self, expiration: u64) -> &mut Self {
        self.expiration = Some(expiration);
        self
    }

    /// Set the nonce of the UCAN payload
    pub fn nonce(&mut self, nonce: String) -> &mut Self {
        self.nonce = Some(nonce);
        self
    }

    /// Get a mutable reference to the facts of the UCAN payload
    pub fn facts(&mut self) -> &mut BTreeMap<String, F> {
        match self.facts {
            Some(ref mut f) => f,
            None => self.set_facts(BTreeMap::new()).facts(),
        }
    }

    /// Set the facts of the UCAN payload
    pub fn set_facts(&mut self, facts: BTreeMap<String, F>) -> &mut Self {
        self.facts = Some(facts);
        self
    }

    /// Set the proof of the UCAN payload
    pub fn proof(&mut self, proof: impl IntoIterator<Item = Cid>) -> &mut Self {
        self.proof = Some(proof.into_iter().collect());
        self
    }

    /// Get a mutable reference to the capabilities of the UCAN payload
    pub fn capabilities(&mut self) -> &mut Capabilities<A> {
        &mut self.capabilities
    }

    /// Set the capabilities of the UCAN payload
    pub fn set_capabilities(&mut self, capabilities: Capabilities<A>) -> &mut Self {
        self.capabilities = capabilities;
        self
    }

    /// Build the UCAN payload
    pub fn build(self) -> Payload<F, A> {
        Payload {
            semantic_version: SemanticVersion,
            issuer: self.issuer,
            audience: self.audience,
            issued_at: self.issued_at,
            not_before: self.not_before,
            expiration: self.expiration,
            nonce: self.nonce,
            facts: self.facts,
            proof: self.proof,
            capabilities: self.capabilities,
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
