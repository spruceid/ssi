use super::{version::RevocationSemanticVersion, Error};
use libipld::Cid;
use serde::{Deserialize, Serialize};
use serde_with::{
    base64::{Base64, UrlSafe},
    formats::Unpadded,
    serde_as, DisplayFromStr,
};
use ssi_dids::{
    did_resolve::{dereference, Content, DIDResolver},
    Resource, VerificationMethod,
};
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

impl Revocation {
    pub fn sign(
        issuer: String,
        revoke: Cid,
        jwk: &JWK,
        algorithm: Algorithm,
    ) -> Result<Self, Error> {
        Ok(Self {
            semantic_version: RevocationSemanticVersion,
            issuer,
            revoke,
            signature: sign_bytes(algorithm, format!("REVOKE-UCAN:{}", revoke).as_bytes(), jwk)?,
        })
    }
    pub async fn verify_signature(
        &self,
        resolver: &dyn DIDResolver,
        algorithm: Option<Algorithm>,
    ) -> Result<(), Error> {
        let key: JWK = match (
            self.issuer.get(..4),
            self.issuer.get(4..8),
            dereference(resolver, &self.issuer, &Default::default())
                .await
                .1,
        ) {
            // did:key without fragment
            (Some("did:"), Some("key:"), Content::DIDDocument(d)) => d
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
            (Some("did:"), Some(_), Content::Object(Resource::VerificationMethod(vm))) => {
                vm.get_jwk()?
            }
            _ => return Err(Error::VerificationMethodMismatch),
        };

        Ok(verify_bytes(
            algorithm.or(key.algorithm).ok_or(Error::AlgUnknown)?,
            format!("REVOKE-UCAN:{}", self.revoke).as_bytes(),
            &key,
            &self.signature,
        )?)
    }
}
