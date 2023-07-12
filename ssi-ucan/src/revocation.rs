use super::{
    util::{match_key_with_did_pkh, match_key_with_vm},
    Error,
};
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
            challenge: sign_bytes(algorithm, format!("REVOKE:{}", revoke).as_bytes(), jwk)?,
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
