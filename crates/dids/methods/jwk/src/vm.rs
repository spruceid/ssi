use multibase::Base;
use ssi_dids_core::{resolution::Error, ssi_json_ld::syntax::ContextEntry};
use ssi_jwk::JWK;
use static_iref::iri_ref;

#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub enum VerificationMethodType {
    Multikey,
    JsonWebKey2020,
}

impl VerificationMethodType {
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "Multikey" => Some(Self::Multikey),
            "JsonWebKey2020" => Some(Self::JsonWebKey2020),
            _ => None,
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            Self::Multikey => "Multikey",
            Self::JsonWebKey2020 => "JsonWebKey2020",
        }
    }

    pub fn encode_public_key(&self, jwk: JWK) -> Result<PublicKey, Error> {
        match self {
            Self::Multikey => {
                let multicodec = jwk.to_multicodec().map_err(Error::internal)?;
                let encoded = multibase::encode(Base::Base58Btc, multicodec.as_bytes());
                Ok(PublicKey::Multibase(encoded))
            }
            Self::JsonWebKey2020 => Ok(PublicKey::Jwk(Box::new(jwk))),
        }
    }

    pub fn context_entry(&self) -> ContextEntry {
        match self {
            Self::Multikey => {
                ContextEntry::IriRef(iri_ref!("https://w3id.org/security/multikey/v1").to_owned())
            }
            Self::JsonWebKey2020 => ContextEntry::IriRef(
                iri_ref!("https://w3id.org/security/suites/jws-2020/v1").to_owned(),
            ),
        }
    }
}

pub enum PublicKey {
    Jwk(Box<JWK>),
    Multibase(String),
}

impl PublicKey {
    pub fn property(&self) -> &'static str {
        match self {
            Self::Jwk(_) => "publicKeyJwk",
            Self::Multibase(_) => "publicKeyMultibase",
        }
    }

    pub fn into_json(self) -> serde_json::Value {
        match self {
            Self::Jwk(jwk) => serde_json::to_value(jwk).unwrap(),
            Self::Multibase(s) => serde_json::Value::String(s),
        }
    }
}
