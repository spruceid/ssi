pub mod error;
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
pub use error::Error;
use iref::UriBuf;
use libipld::{
    codec::{Codec, Decode, Encode},
    error::Error as IpldError,
    json::DagJsonCodec,
    serde::{from_ipld, to_ipld},
    Block, Cid, Ipld,
};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use serde_json::Value as JsonValue;
use serde_with::{
    base64::{Base64, UrlSafe},
    serde_as, DisplayFromStr,
};
use ssi_caips::caip10::{BlockchainAccountId, BlockchainAccountIdParseError};
use ssi_dids_core::{
    document::{DIDVerificationMethod, Resource},
    resolution::{Content, DerefOutput},
    DIDBuf, DIDResolver, DIDURLBuf, Document,
};
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{decode_jws_parts, sign_bytes, split_jws, verify_bytes, Header, JwsSignature};
use ssi_jwt::NumericDate;
use ssi_verification_methods::{GenericVerificationMethod, InvalidVerificationMethod};
use std::{
    borrow::Cow,
    fmt::Display,
    io::{Read, Seek, Write},
    str::Utf8Error,
};

#[derive(Clone, PartialEq, Debug)]
pub struct Ucan<F = JsonValue, A = JsonValue> {
    pub header: Header,
    pub payload: Payload<F, A>,
    pub signature: JwsSignature,
    // unfortunately this matters for sig verification
    // we have to keep track of how this ucan was created
    // alternatively we could have 2 different types?
    // e.g. DagJsonUcan and RawJwtUcan
    codec: UcanCodec,
}

#[derive(Clone, PartialEq, Debug)]
enum UcanCodec {
    // maintain serialization
    Raw(String),
    DagJson,
}

impl Default for UcanCodec {
    fn default() -> Self {
        Self::DagJson
    }
}

impl<F, A> Ucan<F, A> {
    pub async fn verify_signature(&self, resolver: &impl DIDResolver) -> Result<(), Error>
    where
        F: Serialize,
        A: Serialize,
    {
        // extract or deduce signing key
        let key: JWK = match (
            self.payload.issuer.get(..4),
            self.payload.issuer.get(4..8),
            &self.header.jwk,
            resolver
                .dereference(&self.payload.issuer)
                .await
                .map(DerefOutput::into_content)?,
        ) {
            // did:pkh without fragment
            (Some("did:"), Some("pkh:"), Some(jwk), Content::Resource(Resource::Document(d))) => {
                match_key_with_did_pkh(jwk, &d)?;
                jwk.clone()
            }
            // did:pkh with fragment
            (
                Some("did:"),
                Some("pkh:"),
                Some(jwk),
                Content::Resource(Resource::VerificationMethod(vm)),
            ) => {
                match_key_with_vm(jwk, &vm)?;
                jwk.clone()
            }
            // did:key without fragment
            (Some("did:"), Some("key:"), _, Content::Resource(Resource::Document(d))) => d
                .verification_method
                .first()
                .ok_or(Error::VerificationMethodMismatch)?
                .public_key_jwk()?
                .ok_or(Error::MissingPublicKey)?,
            // general case, did with fragment
            (Some("did:"), Some(_), _, Content::Resource(Resource::VerificationMethod(vm))) => {
                vm.public_key_jwk()?.ok_or(Error::MissingPublicKey)?
            }
            _ => return Err(Error::VerificationMethodMismatch),
        };

        Ok(verify_bytes(
            self.header.algorithm,
            self.encode()?
                .rsplit_once('.')
                .ok_or(ssi_jws::Error::InvalidJws)?
                .0
                .as_bytes(),
            &key,
            &self.signature,
        )?)
    }

    pub fn decode(jwt: &str) -> Result<Self, Error>
    where
        F: DeserializeOwned,
        A: DeserializeOwned,
    {
        let parts = split_jws(jwt).and_then(|(h, p, s)| decode_jws_parts(h, p.as_bytes(), s))?;
        let (payload, codec): (Payload<F, A>, UcanCodec) =
            match serde_json::from_slice(&parts.signing_bytes.payload) {
                Ok(p) => Ok((p, UcanCodec::Raw(jwt.to_string()))),
                Err(e) => match DagJsonCodec.decode(&parts.signing_bytes.payload) {
                    Ok(p) => Ok((p, UcanCodec::DagJson)),
                    Err(_) => Err(e),
                },
            }?;

        if parts.signing_bytes.header.type_.as_deref() != Some("JWT") {
            return Err(Error::MissingUCANHeaderField("type: JWT"));
        }

        match parts.signing_bytes.header.additional_parameters.get("ucv") {
            Some(JsonValue::String(v)) if v == "0.9.0" => (),
            _ => return Err(Error::MissingUCANHeaderField("ucv: 0.9.0")),
        }

        if !payload.audience.starts_with("did:") {
            return Err(Error::DIDURL);
        }

        Ok(Self {
            header: parts.signing_bytes.header,
            payload,
            signature: parts.signature,
            codec,
        })
    }

    pub fn encode(&self) -> Result<String, Error>
    where
        F: Serialize,
        A: Serialize,
    {
        Ok(match &self.codec {
            UcanCodec::Raw(r) => r.clone(),
            UcanCodec::DagJson => [
                BASE64_URL_SAFE_NO_PAD
                    .encode(DagJsonCodec.encode(&to_ipld(&self.header).map_err(IpldError::new)?)?),
                BASE64_URL_SAFE_NO_PAD.encode(DagJsonCodec.encode(&self.payload)?),
                BASE64_URL_SAFE_NO_PAD.encode(&self.signature),
            ]
            .join("."),
        })
    }

    pub fn to_block<S, H>(&self, hash: H) -> Result<Block<S>, IpldError>
    where
        F: Serialize,
        A: Serialize,
        S: libipld::store::StoreParams,
        H: Into<S::Hashes>,
        S::Codecs: From<DagJsonCodec> + From<libipld::raw::RawCodec>,
    {
        match &self.codec {
            UcanCodec::Raw(r) => Block::encode(libipld::raw::RawCodec, hash.into(), r.as_bytes()),
            UcanCodec::DagJson => Block::encode(
                DagJsonCodec,
                hash.into(),
                &to_ipld(ipld_encoding::DagJsonUcanRef::from(self))?,
            ),
        }
    }

    pub fn from_block<S>(block: &Block<S>) -> Result<Self, FromIpldBlockError>
    where
        F: DeserializeOwned,
        A: DeserializeOwned,
        S: libipld::store::StoreParams,
        S::Codecs: From<DagJsonCodec> + From<libipld::raw::RawCodec>,
        Ipld: Decode<S::Codecs>,
    {
        if block.cid().codec() == S::Codecs::from(DagJsonCodec).into() {
            let ipld: Ipld = S::Codecs::from(DagJsonCodec).decode(block.data())?;
            let du: ipld_encoding::DagJsonUcan<F, A> = from_ipld(ipld)?;
            Ok(du.into())
        } else if block.cid().codec() == S::Codecs::from(libipld::raw::RawCodec).into() {
            Ok(Self::decode(std::str::from_utf8(block.data())?)?)
        } else {
            Err(FromIpldBlockError::InvalidCodec)
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FromIpldBlockError {
    #[error(transparent)]
    Ipld(#[from] libipld::error::Error),

    #[error(transparent)]
    Decode(#[from] libipld::error::SerdeError),

    #[error(transparent)]
    Utf8(#[from] Utf8Error),

    #[error(transparent)]
    Ucan(#[from] Error),

    #[error("Invalid codec: expected `raw` or `dagJson`")]
    InvalidCodec,
}

fn match_key_with_did_pkh(key: &JWK, doc: &Document) -> Result<(), Error> {
    for vm in &doc.verification_method {
        if let Some(id) = vm.blockchain_account_id()? {
            if id.verify(key).is_ok() {
                return Ok(());
            }
        }
    }

    Err(Error::VerificationMethodMismatch)
}

fn match_key_with_vm(key: &JWK, vm: &DIDVerificationMethod) -> Result<(), Error> {
    Ok(vm
        .blockchain_account_id()?
        .ok_or(Error::VerificationMethodMismatch)?
        .verify(key)?)
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Debug)]
pub struct Payload<F = JsonValue, A = JsonValue> {
    #[serde(rename = "iss")]
    pub issuer: DIDURLBuf,
    #[serde(rename = "aud")]
    pub audience: DIDBuf,
    #[serde(rename = "nbf", skip_serializing_if = "Option::is_none")]
    pub not_before: Option<NumericDate>,
    #[serde(rename = "exp")]
    pub expiration: NumericDate,
    #[serde(rename = "nnc", skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    #[serde(rename = "fct", skip_serializing_if = "Option::is_none")]
    pub facts: Option<Vec<F>>,
    #[serde_as(as = "Vec<DisplayFromStr>")]
    #[serde(rename = "prf")]
    pub proof: Vec<Cid>,
    #[serde(rename = "att")]
    pub attenuation: Vec<Capability<A>>,
}

#[derive(thiserror::Error, Debug)]
pub enum TimeInvalid {
    #[error("UCAN not yet valid")]
    TooEarly,
    #[error("UCAN has expired")]
    TooLate,
}

impl<F, A> Payload<F, A> {
    pub fn validate_time(&self, time: Option<f64>) -> Result<(), TimeInvalid> {
        let t = time.unwrap_or_else(now);
        match (self.not_before, t > self.expiration.as_seconds()) {
            (_, true) => Err(TimeInvalid::TooLate),
            (Some(nbf), _) if t < nbf.as_seconds() => Err(TimeInvalid::TooEarly),
            _ => Ok(()),
        }
    }

    // NOTE IntoIter::new is deprecated, but into_iter() returns references until we move to 2021 edition
    #[allow(deprecated)]
    pub fn sign(self, algorithm: Algorithm, key: &JWK) -> Result<Ucan<F, A>, Error>
    where
        F: Serialize,
        A: Serialize,
    {
        let header = Header {
            algorithm,
            type_: Some("JWT".to_string()),
            additional_parameters: std::array::IntoIter::new([(
                "ucv".to_string(),
                serde_json::Value::String("0.9.0".to_string()),
            )])
            .collect(),
            ..Default::default()
        };

        let signature = sign_bytes(
            algorithm,
            [
                BASE64_URL_SAFE_NO_PAD
                    .encode(DagJsonCodec.encode(&to_ipld(&header).map_err(IpldError::new)?)?),
                BASE64_URL_SAFE_NO_PAD.encode(DagJsonCodec.encode(&self)?),
            ]
            .join(".")
            .as_bytes(),
            key,
        )?
        .into();

        Ok(Ucan {
            header,
            payload: self,
            signature,
            codec: UcanCodec::DagJson,
        })
    }
}

/// Extension for the `DIDVerificationMethod` type.
trait DIDVerificationMethodExt {
    /// Returns the public key of a DID verification method as a JWK.
    ///
    /// The verification method must be known by `ssi` and well-formed, or this
    /// function will return an `InvalidVerificationMethod` error.
    fn public_key_jwk(&self) -> Result<Option<JWK>, InvalidVerificationMethod>;

    /// Returns the blockchain account id of a DID verification method.
    fn blockchain_account_id(
        &self,
    ) -> Result<Option<BlockchainAccountId>, BlockchainAccountIdError>;
}

impl DIDVerificationMethodExt for DIDVerificationMethod {
    fn public_key_jwk(&self) -> Result<Option<JWK>, InvalidVerificationMethod> {
        let vm: GenericVerificationMethod = self.clone().into();
        Ok(ssi_verification_methods::AnyMethod::try_from(vm)?
            .public_key_jwk()
            .map(Cow::into_owned))
    }

    fn blockchain_account_id(
        &self,
    ) -> Result<Option<BlockchainAccountId>, BlockchainAccountIdError> {
        match self.properties.get("blockchainAccountId") {
            Some(serde_json::Value::String(value)) => Ok(Some(value.parse()?)),
            Some(_) => Err(BlockchainAccountIdError::InvalidValue),
            None => Ok(None),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum BlockchainAccountIdError {
    #[error("Invalid JSON value")]
    InvalidValue,

    #[error(transparent)]
    Parse(#[from] BlockchainAccountIdParseError),
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
#[serde(untagged)]
pub enum UcanResource {
    Proof(#[serde_as(as = "DisplayFromStr")] UcanProofRef),
    URI(UriBuf),
}

impl Display for UcanResource {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        match &self {
            Self::Proof(p) => write!(f, "{p}"),
            Self::URI(u) => write!(f, "{u}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UcanProofRef(pub Cid);

impl Display for UcanProofRef {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "ucan:{}", self.0)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum ProofRefParseErr {
    #[error("Missing ucan prefix")]
    Format,
    #[error("Invalid Cid reference")]
    ParseCid(#[from] libipld::cid::Error),
}

impl std::str::FromStr for UcanProofRef {
    type Err = ProofRefParseErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(UcanProofRef(
            s.strip_prefix("ucan:")
                .map(Cid::from_str)
                .ok_or(ProofRefParseErr::Format)??,
        ))
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct UcanScope {
    pub namespace: String,
    pub capability: String,
}

impl std::fmt::Display for UcanScope {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{}/{}", self.namespace, self.capability)
    }
}

#[derive(thiserror::Error, Debug)]
pub enum UcanScopeParseErr {
    #[error("Missing namespace")]
    Namespace,
}

impl std::str::FromStr for UcanScope {
    type Err = UcanScopeParseErr;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (ns, cap) = s.split_once('/').ok_or(UcanScopeParseErr::Namespace)?;
        Ok(UcanScope {
            namespace: ns.to_string(),
            capability: cap.to_string(),
        })
    }
}

/// 3.2.5 A JSON capability MUST include the with and can fields and
/// MAY have additional fields needed to describe the capability
#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Capability<A = JsonValue> {
    pub with: UcanResource,
    #[serde_as(as = "DisplayFromStr")]
    pub can: UcanScope,
    #[serde(rename = "nb", skip_serializing_if = "Option::is_none")]
    pub additional_fields: Option<A>,
}

fn now() -> f64 {
    let now = chrono::prelude::Utc::now();
    match now.timestamp_nanos_opt() {
        Some(nano) => nano as f64 / 1e+9_f64,
        None => now.timestamp_micros() as f64 / 1e+6_f64,
    }
}

#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct UcanRevocation {
    #[serde(rename = "iss")]
    pub issuer: DIDURLBuf,
    #[serde_as(as = "DisplayFromStr")]
    pub revoke: Cid,
    #[serde_as(as = "Base64<UrlSafe>")]
    pub challenge: Vec<u8>,
}

impl UcanRevocation {
    pub fn sign(
        issuer: DIDURLBuf,
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
        resolver: &impl DIDResolver,
        algorithm: Algorithm,
        jwk: Option<&JWK>,
    ) -> Result<(), Error> {
        let key: JWK = match (
            self.issuer.get(..4),
            self.issuer.get(4..8),
            jwk,
            resolver
                .dereference(&self.issuer)
                .await
                .map(DerefOutput::into_content)?,
        ) {
            // did:pkh without fragment
            (Some("did:"), Some("pkh:"), Some(jwk), Content::Resource(Resource::Document(d))) => {
                match_key_with_did_pkh(jwk, &d)?;
                jwk.clone()
            }
            // did:pkh with fragment
            (
                Some("did:"),
                Some("pkh:"),
                Some(jwk),
                Content::Resource(Resource::VerificationMethod(vm)),
            ) => {
                match_key_with_vm(jwk, &vm)?;
                jwk.clone()
            }
            // did:key without fragment
            (Some("did:"), Some("key:"), _, Content::Resource(Resource::Document(d))) => d
                .verification_method
                .first()
                .ok_or(Error::VerificationMethodMismatch)?
                .public_key_jwk()?
                .ok_or(Error::MissingPublicKey)?,
            // general case, did with fragment
            (Some("did:"), Some(_), _, Content::Resource(Resource::VerificationMethod(vm))) => {
                vm.public_key_jwk()?.ok_or(Error::MissingPublicKey)?
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

mod ipld_encoding {
    use super::*;

    #[derive(Serialize, Clone, PartialEq, Debug)]
    pub struct DagJsonUcanRef<'a, F = JsonValue, A = JsonValue> {
        header: &'a Header,
        payload: DagJsonPayloadRef<'a, F, A>,
        signature: &'a [u8],
    }

    #[derive(Deserialize, Clone, PartialEq, Debug)]
    pub struct DagJsonUcan<F = JsonValue, A = JsonValue> {
        header: Header,
        payload: DagJsonPayload<F, A>,
        signature: Vec<u8>,
    }

    #[derive(Serialize, Clone, PartialEq, Debug)]
    pub struct DagJsonPayloadRef<'a, F = JsonValue, A = JsonValue> {
        pub iss: &'a str,
        pub aud: &'a str,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nbf: &'a Option<NumericDate>,
        pub exp: &'a NumericDate,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nnc: &'a Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fct: &'a Option<Vec<F>>,
        pub prf: &'a Vec<Cid>,
        pub att: &'a Vec<Capability<A>>,
    }

    #[derive(Deserialize, Clone, PartialEq, Debug)]
    pub struct DagJsonPayload<F = JsonValue, A = JsonValue> {
        pub iss: DIDURLBuf,
        pub aud: DIDBuf,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nbf: Option<NumericDate>,
        pub exp: NumericDate,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub nnc: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        pub fct: Option<Vec<F>>,
        pub prf: Vec<Cid>,
        pub att: Vec<Capability<A>>,
    }

    impl<F, A> Encode<DagJsonCodec> for Ucan<F, A>
    where
        F: Serialize,
        A: Serialize,
    {
        fn encode<W: Write>(&self, c: DagJsonCodec, w: &mut W) -> Result<(), IpldError> {
            to_ipld(ipld_encoding::DagJsonUcanRef::from(self))?.encode(c, w)
        }
    }

    impl<F, A> Decode<DagJsonCodec> for Ucan<F, A>
    where
        F: DeserializeOwned,
        A: DeserializeOwned,
    {
        fn decode<R: Read + Seek>(c: DagJsonCodec, r: &mut R) -> Result<Self, IpldError> {
            let u: ipld_encoding::DagJsonUcan<F, A> = from_ipld(Ipld::decode(c, r)?)?;
            Ok(u.into())
        }
    }

    impl<F, A> Encode<DagJsonCodec> for Payload<F, A>
    where
        F: Serialize,
        A: Serialize,
    {
        fn encode<W: Write>(&self, c: DagJsonCodec, w: &mut W) -> Result<(), IpldError> {
            to_ipld(ipld_encoding::DagJsonPayloadRef::from(self))?.encode(c, w)
        }
    }

    impl<F, A> Decode<DagJsonCodec> for Payload<F, A>
    where
        F: DeserializeOwned,
        A: DeserializeOwned,
    {
        fn decode<R: Read + Seek>(c: DagJsonCodec, r: &mut R) -> Result<Self, IpldError> {
            let p: ipld_encoding::DagJsonPayload<F, A> = from_ipld(Ipld::decode(c, r)?)?;
            Ok(p.into())
        }
    }

    impl<'a, F, A> From<&'a Ucan<F, A>> for DagJsonUcanRef<'a, F, A> {
        fn from(u: &'a Ucan<F, A>) -> Self {
            Self {
                header: &u.header,
                payload: DagJsonPayloadRef::from(&u.payload),
                signature: &u.signature,
            }
        }
    }

    impl<F, A> From<DagJsonUcan<F, A>> for Ucan<F, A> {
        fn from(u: DagJsonUcan<F, A>) -> Self {
            Self {
                header: u.header,
                payload: u.payload.into(),
                signature: u.signature.into(),
                codec: UcanCodec::DagJson,
            }
        }
    }

    impl<'a, F, A> From<&'a Payload<F, A>> for DagJsonPayloadRef<'a, F, A> {
        fn from(p: &'a Payload<F, A>) -> Self {
            Self {
                iss: &p.issuer,
                aud: &p.audience,
                nbf: &p.not_before,
                exp: &p.expiration,
                nnc: &p.nonce,
                fct: &p.facts,
                prf: &p.proof,
                att: &p.attenuation,
            }
        }
    }

    impl<F, A> From<DagJsonPayload<F, A>> for Payload<F, A> {
        fn from(p: DagJsonPayload<F, A>) -> Self {
            Self {
                issuer: p.iss,
                audience: p.aud,
                not_before: p.nbf,
                expiration: p.exp,
                nonce: p.nnc,
                facts: p.fct,
                proof: p.prf,
                attenuation: p.att,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use did_method_key::DIDKey;

    #[async_std::test]
    async fn valid() {
        let cases: Vec<ValidTestVector> =
            serde_json::from_str(include_str!("../../../tests/ucan-v0.9.0-valid.json")).unwrap();

        for case in cases {
            let ucan = match Ucan::decode(&case.token) {
                Ok(u) => u,
                Err(e) => Err(e).unwrap(),
            };

            match ucan.verify_signature(&DIDKey).await {
                Err(e) => Err(e).unwrap(),
                _ => {}
            };

            assert_eq!(ucan.payload, case.assertions.payload);
            assert_eq!(ucan.header, case.assertions.header);
        }
    }

    #[async_std::test]
    async fn invalid() {
        let cases: Vec<InvalidTestVector> =
            serde_json::from_str(include_str!("../../../tests/ucan-v0.9.0-invalid.json")).unwrap();
        for case in cases {
            match Ucan::<JsonValue>::decode(&case.token) {
                Ok(u) => {
                    if u.payload.validate_time(None).is_ok()
                        && u.verify_signature(&DIDKey).await.is_ok()
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
        let case = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsInVjdiI6IjAuOS4wIn0.eyJhdHQiOltdLCJhdWQiOiJkaWQ6ZXhhbXBsZToxMjMiLCJleHAiOjkwMDAwMDAwMDEuMCwiaXNzIjoiZGlkOmtleTp6Nk1ram16ZXBUcGc0NFJvejhKbk45QXhUS0QyMjk1Z2p6M3h0NDhQb2k3MjYxR1MiLCJwcmYiOltdfQ.V38liNHsdVO0Zk_davTBsewq-2XCxs_3qIRLuwUNj87aqdlMfa9X5O5IRR5u7apzWm7sUiR0FS3J3Nnu7IWtBQ";
        let u = Ucan::<JsonValue>::decode(case).unwrap();
        u.verify_signature(&DIDKey).await.unwrap();
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
    #[allow(dead_code)]
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
        #[allow(dead_code)]
        pub assertions: InvalidAssertions,
    }
}
