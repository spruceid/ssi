use libipld::{
    multihash::{Code, MultihashDigest},
    Cid,
};
use ssi_dids::{
    did_resolve::{dereference, Content, DIDResolver},
    Error, Resource, VerificationMethod,
};
use ssi_jwk::JWK;

/// Calculate the canonical CID of a UCAN
///
/// This function does not verify that the given string is a valid UCAN.
pub fn canonical_cid(jwt: &str) -> Cid {
    Cid::new_v1(0x55, Code::Sha2_256.digest(jwt.as_bytes()))
}

/// Extract or resolve the JWK for the given DID, if possible
pub async fn get_verification_key(id: &str, resolver: &dyn DIDResolver) -> Result<JWK, Error> {
    match (
        id.get(..4),
        id.get(4..8),
        dereference(resolver, id, &Default::default()).await.1,
    ) {
        // TODO here we will have some complicated cases w.r.t. did:pkh
        // some did:pkh's have recoverable signatures, some don't and will need
        // a query param on the did
        //
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
            .ok_or(Error::MissingKey)?
            .get_jwk()
            .map_err(Error::from),
        // general case, did with fragment
        (Some("did:"), Some(_), Content::Object(Resource::VerificationMethod(vm))) => {
            Ok(vm.get_jwk()?)
        }
        _ => Err(Error::MissingKey),
    }
}

pub trait UcanDecode<E> {
    type Error;
    type Encoded<'e>;
    /// Decode the UCAN
    fn decode(encoded: Self::Encoded<'_>) -> Result<Self, Self::Error>
    where
        Self: Sized;
}

pub trait UcanEncode<E> {
    type Error;
    type Encoded<'a>
    where
        Self: 'a;
    /// Encode the UCAN
    fn encode(&self) -> Result<Self::Encoded<'_>, Self::Error>;
}
