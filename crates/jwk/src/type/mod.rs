use serde::{Deserialize, Serialize};
use ssi_crypto::{key::KeyConversionError, KeyType};

pub mod ec;
pub use ec::EcParams;

pub mod rsa;
pub use rsa::RsaParams;

pub mod oct;
pub use oct::OctParams;

pub mod okp;
pub use okp::OkpParams;

use crate::JWK;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq)]
#[serde(tag = "kty")]
pub enum Params {
    #[serde(rename = "EC")]
    Ec(EcParams),

    #[serde(rename = "RSA")]
    Rsa(RsaParams),

    #[serde(rename = "oct")]
    Oct(OctParams),

    #[serde(rename = "OKP")]
    Okp(OkpParams),
}

impl Params {
    pub fn r#type(&self) -> Option<KeyType> {
        match self {
            Self::Ec(p) => p.r#type(),
            Self::Rsa(_) => Some(KeyType::Rsa),
            Self::Oct(_) => Some(KeyType::Symmetric),
            Self::Okp(p) => p.r#type(),
        }
    }

    pub fn as_ec(&self) -> Option<&EcParams> {
        match self {
            Self::Ec(p) => Some(p),
            _ => None,
        }
    }

    pub fn is_public(&self) -> bool {
        match self {
            Self::Ec(params) => params.is_public(),
            Self::Rsa(params) => params.is_public(),
            Self::Oct(params) => params.is_public(),
            Self::Okp(params) => params.is_public(),
        }
    }

    /// Strip private key material
    pub fn to_public(&self) -> Self {
        match self {
            Self::Ec(params) => Self::Ec(params.to_public()),
            Self::Rsa(params) => Self::Rsa(params.to_public()),
            Self::Oct(params) => Self::Oct(params.to_public()),
            Self::Okp(params) => Self::Okp(params.to_public()),
        }
    }
}

impl From<Params> for JWK {
    fn from(params: Params) -> Self {
        Self {
            params,
            public_key_use: None,
            key_operations: None,
            algorithm: None,
            key_id: None,
            x509_url: None,
            x509_certificate_chain: None,
            x509_thumbprint_sha1: None,
            x509_thumbprint_sha256: None,
        }
    }
}

impl TryFrom<&Params> for ssi_crypto::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: &Params) -> Result<Self, Self::Error> {
        match value {
            Params::Ec(p) => p.try_into(),
            Params::Rsa(p) => p.try_into(),
            Params::Oct(p) => Ok(p.into()),
            Params::Okp(p) => p.try_into(),
        }
    }
}

impl TryFrom<Params> for ssi_crypto::PublicKey {
    type Error = KeyConversionError;

    fn try_from(value: Params) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl TryFrom<&Params> for ssi_crypto::SecretKey {
    type Error = KeyConversionError;

    fn try_from(value: &Params) -> Result<Self, Self::Error> {
        match value {
            Params::Ec(p) => p.try_into(),
            Params::Rsa(p) => p.try_into(),
            Params::Oct(p) => p.try_into(),
            Params::Okp(p) => p.try_into(),
        }
    }
}

impl TryFrom<Params> for ssi_crypto::SecretKey {
    type Error = KeyConversionError;

    fn try_from(value: Params) -> Result<Self, Self::Error> {
        (&value).try_into()
    }
}

impl From<EcParams> for Params {
    fn from(value: EcParams) -> Self {
        Params::Ec(value)
    }
}

impl From<EcParams> for JWK {
    fn from(value: EcParams) -> Self {
        Params::Ec(value).into()
    }
}

impl From<RsaParams> for Params {
    fn from(value: RsaParams) -> Self {
        Params::Rsa(value)
    }
}

impl From<RsaParams> for JWK {
    fn from(value: RsaParams) -> Self {
        Params::Rsa(value).into()
    }
}

impl From<OkpParams> for Params {
    fn from(value: OkpParams) -> Self {
        Params::Okp(value)
    }
}

impl From<OkpParams> for JWK {
    fn from(value: OkpParams) -> Self {
        Params::Okp(value).into()
    }
}
