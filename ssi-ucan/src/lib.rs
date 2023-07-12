pub mod error;
pub use error::Error;
use libipld::{
    codec::Codec,
    error::Error as IpldError,
    json::DagJsonCodec,
    multihash::{Code, MultihashDigest},
    serde::to_ipld,
    Cid,
};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as, DeserializeFromStr, DisplayFromStr, SerializeDisplay,
};
use ssi_dids::{
    did_resolve::{dereference, Content, DIDResolver},
    Document, Resource, VerificationMethod, VerificationMethodMap,
};
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{decode_jws_parts, sign_bytes, split_jws, verify_bytes, Header};
use std::collections::BTreeMap;

use capabilities::Capabilities;
pub use ucan_capabilities_object as capabilities;

/// A deserialized UCAN
#[derive(Clone, PartialEq, Debug)]
pub struct Ucan<F = JsonValue, A = JsonValue> {
    header: Header,
    payload: Payload<F, A>,
    signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Debug, SerializeDisplay, DeserializeFromStr, Default)]
struct SemanticVersion;

impl std::fmt::Display for SemanticVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "0.2.0")
    }
}

#[derive(thiserror::Error, Debug)]
enum VersionError {
    #[error("Invalid version: expected 0.2.0, found {0}")]
    InvalidVersion(String),
}

impl std::str::FromStr for SemanticVersion {
    type Err = VersionError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "0.2.0" {
            Ok(Self)
        } else {
            Err(VersionError::InvalidVersion(s.to_string()))
        }
    }
}

impl<F, A> Ucan<F, A> {
    /// Get the Header of the UCAN
    pub fn header(&self) -> &Header {
        &self.header
    }

    /// Get the Payload of the UCAN
    pub fn payload(&self) -> &Payload<F, A> {
        &self.payload
    }

    /// Get the Signature of the UCAN
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }

    pub fn into_inner(self) -> (Header, Payload<F, A>, Vec<u8>) {
        (self.header, self.payload, self.signature)
    }

    /// Extract or resolve the JWK used to issue this UCAN
    pub async fn get_verification_key(&self, resolver: &dyn DIDResolver) -> Result<JWK, Error> {
        match (
            self.payload.issuer.get(..4),
            self.payload.issuer.get(4..8),
            &self.header.jwk,
            dereference(resolver, &self.payload.issuer, &Default::default())
                .await
                .1,
        ) {
            // did:pkh without fragment
            (Some("did:"), Some("pkh:"), Some(jwk), Content::DIDDocument(d)) => {
                match_key_with_did_pkh(jwk, &d)?;
                Ok(jwk.clone())
            }
            // did:pkh with fragment
            (
                Some("did:"),
                Some("pkh:"),
                Some(jwk),
                Content::Object(Resource::VerificationMethod(vm)),
            ) => {
                match_key_with_vm(jwk, &vm)?;
                Ok(jwk.clone())
            }
            // did:key without fragment
            (Some("did:"), Some("key:"), _, Content::DIDDocument(d)) => d
                .verification_method
                .iter()
                .flatten()
                .next()
                .and_then(|v| match v {
                    VerificationMethod::Map(vm) => Some(vm),
                    _ => None,
                })
                .ok_or(Error::VerificationMethodMismatch)?
                .get_jwk()
                .map_err(Error::from),
            // general case, did with fragment
            (Some("did:"), Some(_), _, Content::Object(Resource::VerificationMethod(vm))) => {
                Ok(vm.get_jwk()?)
            }
            _ => Err(Error::VerificationMethodMismatch),
        }
    }

    /// Decode the UCAN and verify it's signature
    ///
    /// This method will resolve the DID of the issuer and verify the signature
    /// using their public key. This method works over a JWT as the original
    /// encoding is not retained by the UCAN struct.
    pub async fn decode_and_verify(jwt: &str, resolver: &dyn DIDResolver) -> Result<Self, Error>
    where
        F: for<'a> Deserialize<'a>,
        A: for<'a> Deserialize<'a>,
    {
        let ucan = Self::decode(jwt)?;
        let jwk = ucan.get_verification_key(resolver).await?;

        verify_bytes(
            ucan.header.algorithm,
            jwt.rsplit_once('.')
                .ok_or(ssi_jws::Error::InvalidJWS)?
                .0
                .as_bytes(),
            &jwk,
            &ucan.signature,
        )?;

        Ok(ucan)
    }

    /// Decode the UCAN
    pub fn decode(jwt: &str) -> Result<Self, Error>
    where
        F: for<'a> Deserialize<'a>,
        A: for<'a> Deserialize<'a>,
    {
        let parts = split_jws(jwt).and_then(|(h, p, s)| decode_jws_parts(h, p.as_bytes(), s))?;
        let payload: Payload<F, A> = serde_json::from_slice(&parts.payload)?;

        if parts.header.type_.as_deref() != Some("JWT") {
            return Err(Error::MissingUCANHeaderField("type: JWT"));
        }

        if !payload.audience.starts_with("did:") {
            return Err(Error::DIDURL);
        }

        Ok(Self {
            header: parts.header,
            payload,
            signature: parts.signature,
        })
    }

    /// Encode the UCAN in canonicalized form, by encoding the JWS segments
    /// as JCS/DAG-JSON
    pub fn encode_as_canonicalized_jwt(&self) -> Result<String, Error>
    where
        F: Serialize,
        A: Serialize,
    {
        Ok([
            base64::encode_config(
                DagJsonCodec.encode(&to_ipld(&self.header).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(
                DagJsonCodec.encode(&to_ipld(&self.payload).map_err(IpldError::new)?)?,
                base64::URL_SAFE_NO_PAD,
            ),
            base64::encode_config(&self.signature, base64::URL_SAFE_NO_PAD),
        ]
        .join("."))
    }
}

/// Calculate the canonical CID of a UCAN
///
/// This function does not verify that the given string is a valid UCAN.
pub fn canonical_cid(jwt: &str) -> Cid {
    Cid::new_v1(0x55, Code::Sha2_256.digest(jwt.as_bytes()))
}

fn match_key_with_did_pkh(key: &JWK, doc: &Document) -> Result<(), Error> {
    doc.verification_method
        .iter()
        .flatten()
        .find_map(|vm| match vm {
            VerificationMethod::Map(vm) if vm.blockchain_account_id.is_some() => {
                Some(match_key_with_vm(key, vm))
            }
            _ => None,
        })
        .unwrap_or(Err(Error::VerificationMethodMismatch))
}

fn match_key_with_vm(key: &JWK, vm: &VerificationMethodMap) -> Result<(), Error> {
    use std::str::FromStr;
    Ok(ssi_caips::caip10::BlockchainAccountId::from_str(
        vm.blockchain_account_id
            .as_ref()
            .ok_or(Error::VerificationMethodMismatch)?,
    )?
    .verify(key)?)
}

/// The Payload of a UCAN, with JWS registered claims and UCAN specific claims
#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
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

#[derive(thiserror::Error, Debug)]
pub enum TimeInvalid {
    #[error("UCAN not yet valid")]
    TooEarly,
    #[error("UCAN has expired")]
    TooLate,
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

    /// Validate the time bounds of the UCAN
    pub fn validate_time<T: PartialOrd<u64>>(&self, time: Option<T>) -> Result<(), TimeInvalid> {
        match time {
            Some(t) => cmp_time(t, self.not_before, self.expiration),
            None => cmp_time(now(), self.not_before, self.expiration),
        }
    }

    /// Sign the payload with the given key and optional custom header claims
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

        Ok(Ucan {
            header,
            payload: self,
            signature,
        })
    }
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

#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct UcanRevocation {
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde_as(as = "DisplayFromStr")]
    pub revoke: Cid,
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub challenge: Vec<u8>,
}

impl UcanRevocation {
    pub fn sign(
        issuer: String,
        revoke: Cid,
        jwk: &JWK,
        algorithm: Algorithm,
    ) -> Result<Self, Error> {
        Ok(Self {
            issuer,
            revoke,
            challenge: sign_bytes(algorithm, format!("REVOKE:{revoke}").as_bytes(), jwk)?,
        })
    }
    pub async fn verify_signature(
        &self,
        resolver: &dyn DIDResolver,
        algorithm: Algorithm,
        jwk: Option<&JWK>,
    ) -> Result<(), Error> {
        let key: JWK = match (
            self.issuer.get(..4),
            self.issuer.get(4..8),
            jwk,
            dereference(resolver, &self.issuer, &Default::default())
                .await
                .1,
        ) {
            // did:pkh without fragment
            (Some("did:"), Some("pkh:"), Some(jwk), Content::DIDDocument(d)) => {
                match_key_with_did_pkh(jwk, &d)?;
                jwk.clone()
            }
            // did:pkh with fragment
            (
                Some("did:"),
                Some("pkh:"),
                Some(jwk),
                Content::Object(Resource::VerificationMethod(vm)),
            ) => {
                match_key_with_vm(jwk, &vm)?;
                jwk.clone()
            }
            // did:key without fragment
            (Some("did:"), Some("key:"), _, Content::DIDDocument(d)) => d
                .verification_method
                .iter()
                .flatten()
                .next()
                .and_then(|v| match v {
                    VerificationMethod::Map(vm) => Some(vm),
                    _ => None,
                })
                .ok_or(Error::VerificationMethodMismatch)?
                .get_jwk()?,
            // general case, did with fragment
            (Some("did:"), Some(_), _, Content::Object(Resource::VerificationMethod(vm))) => {
                vm.get_jwk()?
            }
            _ => return Err(Error::VerificationMethodMismatch),
        };

        Ok(verify_bytes(
            algorithm,
            format!("REVOKE:{}", self.revoke).as_bytes(),
            &key,
            &self.challenge,
        )?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_method_key::DIDKey;
    use ssi_dids::{DIDMethod, Source};

    #[async_std::test]
    async fn valid() {
        let cases: Vec<ValidTestVector> =
            serde_json::from_str(include_str!("../../tests/ucan-v0.10.0-valid.json")).unwrap();

        for case in cases {
            let ucan = Ucan::decode_and_verify(&case.token, DIDKey.to_resolver())
                .await
                .unwrap();

            assert_eq!(ucan.payload, case.assertions.payload);
            assert_eq!(ucan.header, case.assertions.header);
        }
    }

    #[async_std::test]
    async fn invalid() {
        let cases: Vec<InvalidTestVector> =
            serde_json::from_str(include_str!("../../tests/ucan-v0.10.0-invalid.json")).unwrap();
        for case in cases {
            match Ucan::<JsonValue>::decode(&case.token) {
                Ok(u) => {
                    if u.payload.validate_time::<u64>(None).is_ok()
                        && Ucan::<JsonValue>::decode_and_verify(&case.token, DIDKey.to_resolver())
                            .await
                            .is_ok()
                    {
                        assert!(false, "{}", case.comment);
                    }
                }
                Err(_e) => {}
            };
        }
    }

    #[async_std::test]
    async fn basic() {
        let key = JWK::generate_ed25519().unwrap();
        let iss = DIDKey.generate(&Source::Key(&key)).unwrap();
        let aud = "did:example:123".to_string();
        let mut payload = Payload::<JsonValue, JsonValue>::new(iss, aud);
        payload.expiration = Some(now() + 60);
        payload.not_before = Some(now() - 60);
        payload
            .capabilities
            .with_action_convert("https://example.com/resource", "https/get", [])
            .unwrap();
        payload.proof = Some(vec![canonical_cid("hello")]);

        let ucan = payload.sign_canonicalized(Algorithm::EdDSA, &key).unwrap();

        let encoded = ucan.encode_as_canonicalized_jwt().unwrap();
        Ucan::<JsonValue>::decode_and_verify(&encoded, DIDKey.to_resolver())
            .await
            .unwrap();
    }

    #[derive(Deserialize)]
    struct ValidAssertions {
        pub header: Header,
        pub payload: Payload,
    }

    #[derive(Deserialize)]
    struct ValidTestVector {
        pub token: String,
        pub assertions: ValidAssertions,
    }

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct InvalidAssertions {
        pub header: Option<JsonValue>,
        pub payload: Option<JsonValue>,
        pub type_errors: Option<Vec<String>>,
        pub validation_errors: Option<Vec<String>>,
    }

    #[derive(Deserialize)]
    struct InvalidTestVector {
        pub comment: String,
        pub token: String,
        pub assertions: InvalidAssertions,
    }
}
