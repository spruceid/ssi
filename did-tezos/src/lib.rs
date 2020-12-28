use ssi::did::{
    Contexts, Document, PublicKey, PublicKeyEntry, PublicKeyObject, VerificationMethod,
    DEFAULT_CONTEXT,
};
use ssi_did_resolve::{DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use chrono::prelude::*;
use serde_json;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::vec;
use thiserror::Error;
use tokio::stream::{self, Stream};

pub struct TezosDIDResolver {}

#[async_trait]
impl DIDResolver for TezosDIDResolver {
    async fn resolve(
        &self,
        did: &str,
        _input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Option<Document>,
        Option<DocumentMetadata>,
    ) {
        let did = match TezosDID::from_str(did) {
            Ok(did) => did,
            Err(e) => {
                return (
                    ResolutionMetadata {
                        error: Some(e.to_string()),
                        content_type: None,
                        property_set: None,
                    },
                    None,
                    None,
                );
            }
        };
        let doc = self.derive(did);

        let res_meta = ResolutionMetadata {
            error: None,
            content_type: None,
            property_set: None,
        };

        let doc_meta = DocumentMetadata {
            created: Some(Utc::now()),
            updated: None,
            property_set: None,
        };

        (res_meta, Some(doc), Some(doc_meta))
    }

    async fn resolve_stream(
        &self,
        did: &str,
        input_metadata: &ResolutionInputMetadata,
    ) -> (
        ResolutionMetadata,
        Box<dyn Stream<Item = Result<Bytes, hyper::Error>> + Unpin + Send>,
        Option<DocumentMetadata>,
    ) {
        // Implement resolveStream in terms of resolve,
        // until resolveStream has its own HTTP(S) binding:
        // https://github.com/w3c-ccg/did-resolution/issues/57
        let (mut res_meta, doc, doc_meta) = self.resolve(did, input_metadata).await;
        let stream: Box<dyn Stream<Item = Result<Bytes, hyper::Error>> + Unpin + Send> = match doc {
            None => Box::new(stream::empty()),
            Some(doc) => match serde_json::to_vec_pretty(&doc) {
                Ok(bytes) => Box::new(stream::iter(vec![Ok(Bytes::from(bytes))])),
                Err(err) => {
                    res_meta.error =
                        Some("Error serializing JSON: ".to_string() + &err.to_string());
                    Box::new(stream::empty())
                }
            },
        };
        (res_meta, stream, doc_meta)
    }
}

pub enum TezosDIDAddress {
    TZ1([u8; 33]),
    TZ2([u8; 33]),
    TZ3([u8; 33]),
    KT1([u8; 33]),
}

impl fmt::Display for TezosDIDAddress {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            TezosDIDAddress::TZ1(b) => write!(f, "tz1{}", std::str::from_utf8(b).unwrap()),
            TezosDIDAddress::TZ2(b) => write!(f, "tz2{}", std::str::from_utf8(b).unwrap()),
            TezosDIDAddress::TZ3(b) => write!(f, "tz3{}", std::str::from_utf8(b).unwrap()),
            TezosDIDAddress::KT1(b) => write!(f, "KT1{}", std::str::from_utf8(b).unwrap()),
        }
    }
}

#[derive(Error, Debug)]
pub enum ParseTezosDIDAddressError {
    #[error("Unknown prefix: {0})")]
    UnknownPrefix(String),
    #[error("Length of address should be 36, found: {0})")]
    InvalidLength(usize),
}

impl FromStr for TezosDIDAddress {
    type Err = ParseTezosDIDAddressError;

    fn from_str(s: &str) -> Result<Self, ParseTezosDIDAddressError> {
        if s.len() != 36 {
            return Err(ParseTezosDIDAddressError::InvalidLength(s.len()));
        }

        match &s[0..3] {
            "tz1" => {
                let mut b: [u8; 33] = [0; 33];
                b.copy_from_slice(&s[3..36].as_bytes()[..33]);
                Ok(TezosDIDAddress::TZ1(b))
            }
            "tz2" => {
                let mut b: [u8; 33] = [0; 33];
                b.copy_from_slice(&s[3..36].as_bytes()[..3]);
                Ok(TezosDIDAddress::TZ2(b))
            }
            "tz3" => {
                let mut b: [u8; 33] = [0; 33];
                b.copy_from_slice(&s[3..36].as_bytes()[..3]);
                Ok(TezosDIDAddress::TZ3(b))
            }
            "KT1" => {
                let mut b: [u8; 33] = [0; 33];
                b.copy_from_slice(&s[3..36].as_bytes()[..3]);
                Ok(TezosDIDAddress::KT1(b))
            }
            p => Err(ParseTezosDIDAddressError::UnknownPrefix(p.to_string())),
        }
    }
}

// TODO
impl TezosDIDAddress {
    fn get_type(&self) -> String {
        match self {
            TezosDIDAddress::TZ1(_) => {
                "Ed25519PublicKeyBLAKE2BDigestSize20Base58Encoded2020".to_string()
            }
            TezosDIDAddress::TZ2(_) => "".to_string(),
            TezosDIDAddress::TZ3(_) => "".to_string(),
            TezosDIDAddress::KT1(_) => "".to_string(),
        }
    }
}

pub struct TezosDID {
    network: String,
    address: TezosDIDAddress,
}

impl fmt::Display for TezosDID {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "did:tz:{}:{}", self.network, self.address)
    }
}

#[derive(Error, Debug)]
pub enum ParseTezosDIDError {
    #[error(transparent)]
    Address(#[from] ParseTezosDIDAddressError),
    #[error("Expected DID of format `did:tz:[network:]address` but found: {0}")]
    Invalid(String),
}

impl FromStr for TezosDID {
    type Err = ParseTezosDIDError;

    fn from_str(s: &str) -> Result<Self, ParseTezosDIDError> {
        match s.split(':').collect::<Vec<&str>>().as_slice() {
            ["did", "tz", address] => Ok(Self {
                network: "mainnet".to_string(),
                address: TezosDIDAddress::from_str(address)?,
            }),
            ["did", "tz", network, address] => Ok(Self {
                network: network.to_string(),
                address: TezosDIDAddress::from_str(address)?,
            }),
            _ => Err(ParseTezosDIDError::Invalid(s.to_string())),
        }
    }
}

impl TezosDIDResolver {
    fn derive(&self, did: TezosDID) -> Document {
        let mut property_set = HashMap::new();
        property_set.insert(
            "blockchainAccountId".to_string(),
            serde_json::Value::String(format!("{}@tezos:{}", did.address.to_string(), did.network)),
        );
        Document {
            context: Contexts::One(DEFAULT_CONTEXT.to_string()),
            id: did.to_string(),
            created: None,
            updated: None,
            authentication: Some(vec![
                VerificationMethod::PublicKey(PublicKey::One(
                    PublicKeyEntry::PublicKeyObject(PublicKeyObject {
                        id: format!("{}#blockchainAccountId", did.to_string()),
                        type_: did.address.get_type(),
                        controller: did.to_string(),
                        property_set: Some(property_set),
                    })
                ));
                1
            ]),
            service: None,
            public_key: None,
            controller: None,
            proof: None,
            property_set: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi_did_resolve::ResolutionInputMetadata;

    #[test]
    fn test_from_str() -> Result<()> {
        let address = "tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8";
        TezosDIDAddress::from_str(address)?;
        Ok(())
    }

    #[tokio::test]
    async fn test_derivation() {
        let resolver = TezosDIDResolver {};
        let resolved_doc = resolver
            .resolve(
                "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
                &ResolutionInputMetadata {
                    accept: None,
                    property_set: None,
                },
            )
            .await;
        let doc = resolved_doc.1;
        assert!(doc.is_some());
        assert_eq!(
            serde_json::to_value(doc.unwrap()).unwrap(),
            json!({
              "@context": "https://www.w3.org/ns/did/v1",
              "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
              "authentication": [{
                "id": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8#blockchainAccountId",
                "type": "Ed25519PublicKeyBLAKE2BDigestSize20Base58Encoded2020",
                "controller": "did:tz:mainnet:tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8",
                "blockchainAccountId": "tz1TzrmTBSuiVHV2VfMnGRMYvTEPCP42oSM8@tezos:mainnet"
              }]
            })
        );
    }
}
