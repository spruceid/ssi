use std::marker::PhantomData;

use iref::Uri;
use ssi_dids_core::{
    resolution::{self, DIDMethodResolver, Error, HTTPDIDResolver, Output},
    DIDBuf, DIDMethod, DIDResolver,
};

use super::Sidetree;

/// DID Resolver using ION/Sidetree REST API
#[derive(Debug, Clone)]
pub struct HTTPSidetreeDIDResolver<S: Sidetree> {
    pub http_did_resolver: HTTPDIDResolver,
    pub _marker: PhantomData<S>,
}

impl<S: Sidetree> HTTPSidetreeDIDResolver<S> {
    pub fn new(sidetree_api_url: &Uri) -> Self {
        let mut identifiers_url = sidetree_api_url.to_owned();
        identifiers_url
            .path_mut()
            .push(iref::uri::Segment::new("identifiers").unwrap());
        // let identifiers_url = format!("{}identifiers/", sidetree_api_url);
        Self {
            http_did_resolver: HTTPDIDResolver::new(&identifiers_url),
            _marker: PhantomData,
        }
    }
}

impl<S: Sidetree> DIDMethod for HTTPSidetreeDIDResolver<S> {
    const DID_METHOD_NAME: &'static str = S::METHOD;
}

impl<S: Sidetree> DIDMethodResolver for HTTPSidetreeDIDResolver<S> {
    async fn resolve_method_representation<'a>(
        &'a self,
        method_specific_id: &'a str,
        options: resolution::Options,
    ) -> Result<Output<Vec<u8>>, Error> {
        let did = DIDBuf::from_string(format!("did:{}:{method_specific_id}", S::METHOD)).unwrap();
        self.http_did_resolver
            .resolve_representation(&did, options)
            .await
    }
}
