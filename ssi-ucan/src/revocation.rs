use super::{util::get_verification_key, version::RevocationSemanticVersion};
use libipld::Cid;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as, DisplayFromStr,
};
use ssi_dids::did_resolve::DIDResolver;
use ssi_jwk::{Algorithm, JWK};
use ssi_jws::{sign_bytes, verify_bytes};

#[serde_as]
#[derive(Serialize, Deserialize, Clone, PartialEq, Eq, Debug)]
pub struct Revocation {
    #[serde(rename = "urv")]
    semantic_version: RevocationSemanticVersion,
    #[serde(rename = "iss")]
    pub issuer: String,
    #[serde(rename = "rvk")]
    #[serde_as(as = "DisplayFromStr")]
    pub revoke: Cid,
    #[serde(rename = "sig")]
    #[serde_as(as = "Base64<UrlSafe, Unpadded>")]
    pub signature: Vec<u8>,
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    JWS(#[from] ssi_jws::Error),
    #[error(transparent)]
    DID(#[from] ssi_dids::Error),
    #[error("Unable to infer algorithm")]
    AlgUnknown,
}

impl Revocation {
    pub fn new(issuer: String, revoke: Cid, signature: Vec<u8>) -> Self {
        Self {
            semantic_version: RevocationSemanticVersion,
            issuer,
            revoke,
            signature,
        }
    }

    pub fn encode_for_signing(revoke: &Cid) -> String {
        format!("REVOKE-UCAN:{}", revoke)
    }

    pub fn sign_with_jwk(
        issuer: String,
        revoke: Cid,
        jwk: &JWK,
        algorithm: Option<Algorithm>,
    ) -> Result<Self, Error> {
        Ok(Self::new(
            issuer,
            revoke,
            sign_bytes(
                algorithm.or(jwk.algorithm).ok_or(Error::AlgUnknown)?,
                Self::encode_for_signing(&revoke).as_bytes(),
                jwk,
            )?,
        ))
    }

    pub async fn verify_signature(
        &self,
        resolver: &dyn DIDResolver,
        algorithm: Option<Algorithm>,
    ) -> Result<(), Error> {
        let key: JWK = get_verification_key(&self.issuer, resolver).await?;

        Ok(verify_bytes(
            algorithm.or(key.algorithm).ok_or(Error::AlgUnknown)?,
            Self::encode_for_signing(&self.revoke).as_bytes(),
            &key,
            &self.signature,
        )?)
    }
}
