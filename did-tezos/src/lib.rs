use ssi::did::{
    Contexts, Document, VerificationMethod, VerificationMethodMap, DEFAULT_CONTEXT, DIDURL,
};
use ssi::did_resolve::{
    DIDResolver, DocumentMetadata, ResolutionInputMetadata, ResolutionMetadata, TYPE_DID_LD_JSON,
};
use ssi::jwk::{Base64urlUInt, OctetParams, Params, JWK};
use std::convert::TryFrom;

use anyhow::Result;
use async_trait::async_trait;
use chrono::prelude::*;
use serde_json;
use std::collections::HashMap;
use std::fmt;
use std::str::FromStr;
use std::vec;
use thiserror::Error;

const TZ1_EDPK: [u8; 4] = [0x65, 0x64, 0x70, 0x6b];
const TZ2_SPPK: [u8; 4] = [0x73, 0x70, 0x70, 0x6b];
const TZ3_P2PK: [u8; 4] = [0x70, 0x32, 0x70, 0x6b];

/*
const TZ1_HASH: [u8; 3] = [0x06, 0xa1, 0x9f];
const TZ2_HASH: [u8; 3] = [0x06, 0xa1, 0xa1];
const TZ3_HASH: [u8; 3] = [0x06, 0xa1, 0xa4];
*/

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
        let doc = match self.derive(did) {
            Ok(doc) => doc,
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

        let res_meta = ResolutionMetadata {
            error: None,
            content_type: Some(TYPE_DID_LD_JSON.to_string()),
            property_set: None,
        };

        let doc_meta = DocumentMetadata {
            created: Some(Utc::now()),
            updated: None,
            property_set: None,
        };

        (res_meta, Some(doc), Some(doc_meta))
    }
}

#[derive(Clone, Debug)]
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

#[derive(Clone, Debug)]
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

#[derive(Error, Debug)]
pub enum JWKToTezosDIDError {
    #[error(transparent)]
    Resolve(#[from] ResolveTezosDIDError),
    #[error("Not Implemented")]
    NotImplemented,
    /*
    #[error(transparent)]
    Address(#[from] ParseTezosDIDAddressError),
    #[error("Expected DID of format `did:tz:[network:]address` but found: {0}")]
    Invalid(String),
    */
    #[error("Unsupported key type")]
    UnsupportedKeyType,
    #[error("Unknown curve: {0})")]
    UnknownCurve(String),
    #[error("Invalid key size. Expected {1} but found {0}")]
    InvalidSize(usize, usize),
}

/*
    pub fn get_tezos_address(&self) -> Result<String, Error> {
        match &self.curve[..] {
            "Ed25519" | "secp256k1" | "P-256" => {
                let pk = self.get_b58_public_key().unwrap();

                let mut hasher = blake2b_simd::Params::new();
                hasher.hash_length(20);

                let blake2b = hasher.hash(&pk[..]);
                let blake2b = blake2b.as_bytes();

                let encoding = self.get_encoding_bytes().unwrap();
                let mut to_encode = Vec::with_capacity(23);
                to_encode.extend_from_slice(encoding);
                to_encode.extend_from_slice(&blake2b[..]);

                let address = bs58::encode(&to_encode).with_check().into_string();

                Ok(address)
            }
            _ => return Err(Error::UnsupportedKeyType),
        }
    }
*/

/*
fn get_encoding_bytes(params: &OctetParams) -> Result<&[u8], JWKToTezosDIDError> {
    match &params.curve[..] {
        "Ed25519" => Ok(&TZ1_HASH),
        "secp256k1" => Ok(&TZ2_HASH),
        "P-256" => Ok(&TZ3_HASH),
        _ => Err(JWKToTezosDIDError::UnsupportedKeyType),
    }
}
*/

impl TryFrom<&OctetParams> for TezosDIDAddress {
    type Error = JWKToTezosDIDError;
    fn try_from(params: &OctetParams) -> Result<TezosDIDAddress, Self::Error> {
        let mut data: [u8; 33] = [0; 33];
        if params.public_key.0.len() != 33 {
            return Err(JWKToTezosDIDError::InvalidSize(
                params.public_key.0.len(),
                33,
            ));
        }
        data.copy_from_slice(&params.public_key.0);
        let addr = match &params.curve[..] {
            "Ed25519" => {
                data.copy_from_slice(&params.public_key.0);
                TezosDIDAddress::TZ1(data)
            }
            "secp256k1" => {
                data.copy_from_slice(&params.public_key.0);
                TezosDIDAddress::TZ2(data)
            }
            "P-256" => {
                data.copy_from_slice(&params.public_key.0);
                TezosDIDAddress::TZ3(data)
            }
            _ => {
                return Err(JWKToTezosDIDError::UnknownCurve(params.curve.clone()));
            }
        };
        Ok(addr)
    }
}

impl TryFrom<&JWK> for TezosDIDAddress {
    type Error = JWKToTezosDIDError;
    fn try_from(jwk: &JWK) -> Result<TezosDIDAddress, Self::Error> {
        match jwk.params {
            Params::OKP(ref okp) => Self::try_from(okp),
            _ => return Err(JWKToTezosDIDError::UnsupportedKeyType),
        }
    }
}

#[derive(Error, Debug)]
pub enum TezosToJWKDIDError {
    /*
    #[error("Not Implemented")]
    NotImplemented,
    */
    #[error("Unsupported key type")]
    UnsupportedKeyType,
}

impl TryFrom<&TezosDIDAddress> for JWK {
    type Error = TezosToJWKDIDError;
    fn try_from(addr: &TezosDIDAddress) -> Result<JWK, Self::Error> {
        let params = match addr {
            TezosDIDAddress::TZ1(data) => Params::OKP(OctetParams {
                curve: "Ed25519".to_string(),
                public_key: Base64urlUInt(data.to_vec()),
                private_key: None,
            }),
            TezosDIDAddress::TZ2(data) => Params::OKP(OctetParams {
                curve: "secp256k1".to_string(),
                public_key: Base64urlUInt(data.to_vec()),
                private_key: None,
            }),
            TezosDIDAddress::TZ3(data) => Params::OKP(OctetParams {
                curve: "P-256".to_string(),
                public_key: Base64urlUInt(data.to_vec()),
                private_key: None,
            }),
            _ => return Err(TezosToJWKDIDError::UnsupportedKeyType),
        };
        // Err(Self::Error::NotImplemented)
        let jwk = JWK {
            params: params,
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        };
        Ok(jwk)
    }
}

#[derive(Error, Debug)]
pub enum ResolveTezosDIDError {
    #[error("Unknown curve: {0})")]
    UnknownCurve(String),
}

pub fn public_key_base58(params: &OctetParams) -> Result<Vec<u8>, ResolveTezosDIDError> {
    let encoded = bs58::encode(&params.public_key.0).into_vec();
    let mut data = Vec::with_capacity(4 + encoded.len());

    match &params.curve[..] {
        "Ed25519" => {
            data.extend_from_slice(&TZ1_EDPK);
        }
        "secp256k1" => {
            data.extend_from_slice(&TZ2_SPPK);
        }
        "P-256" => {
            data.extend_from_slice(&TZ3_P2PK);
        }
        _ => {
            return Err(ResolveTezosDIDError::UnknownCurve(params.curve.clone()));
        }
    };

    data.extend(encoded);
    Ok(data)
}

#[derive(Error, Debug)]
pub enum DeriveTezosDIDDocumentError {
    #[error(transparent)]
    DID(#[from] TezosToJWKDIDError),
}

impl TezosDIDResolver {
    fn derive(&self, did: TezosDID) -> Result<Document, DeriveTezosDIDDocumentError> {
        let mut property_set = HashMap::new();
        property_set.insert(
            "blockchainAccountId".to_string(),
            serde_json::Value::String(format!("{}@tezos:{}", did.address.to_string(), did.network)),
        );
        let vm_didurl = DIDURL {
            did: did.to_string(),
            fragment: Some("blockchainAccountId".to_string()),
            ..Default::default()
        };
        let jwk = JWK::try_from(&did.address)?;
        // let pk_b58 = self.public_key_base58()?;
        let doc = Document {
            context: Contexts::One(DEFAULT_CONTEXT.to_string()),
            id: did.to_string(),
            authentication: Some(vec![VerificationMethod::DIDURL(vm_didurl.clone())]),
            verification_method: Some(vec![VerificationMethod::Map(VerificationMethodMap {
                id: String::from(vm_didurl),
                type_: did.address.get_type(),
                controller: did.to_string(),
                // public_key_base58: None,
                public_key_jwk: Some(jwk),
                // public_key_base58: Some(pk_b58),
                property_set: Some(property_set),
                ..Default::default()
            })]),
            ..Default::default()
        };
        Ok(doc)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use ssi::did_resolve::ResolutionInputMetadata;

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
                &ResolutionInputMetadata::default(),
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

    const TZ1: &'static str = "did:tz:tz1VFda3KmzRecjsYptDq5bJh1M1NyAqgBJf";

    #[test]
    fn jwk_to_did_tezos() {
        // TODO: add tz2 and tz3 test cases
        let json = "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"GvidwVqGgicuL68BRM89OOtDzK1gjs8IqUXFkjKkm8Iwg18slw==\",\"d\":\"K44dAtJ-MMl-JKuOupfcGRPI5n3ZVH_Gk65c6Rcgn_IV28987PMw_b6paCafNOBOi5u-FZMgGJd3mc5MkfxfwjCrXQM-\"}";
        let jwk: JWK = serde_json::from_str(&json).unwrap();
        let tz1 = jwk.to_did_tezos().unwrap();
        assert_eq!(tz1, TZ1);
    }
}
