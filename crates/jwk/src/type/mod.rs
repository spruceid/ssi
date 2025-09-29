use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

use crate::JWK;

pub mod ec;
pub use ec::ECParams;

pub mod rsa;
pub use rsa::RSAParams;

pub mod okp;
pub use okp::OctetParams;

mod oct;
pub use oct::SymmetricParams;

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq, Hash, Eq, Zeroize)]
#[serde(tag = "kty")]
pub enum Params {
    EC(ECParams),
    RSA(RSAParams),
    #[serde(rename = "oct")]
    Symmetric(SymmetricParams),
    OKP(OctetParams),
}

impl Params {
    pub fn is_public(&self) -> bool {
        match self {
            Self::EC(params) => params.is_public(),
            Self::RSA(params) => params.is_public(),
            Self::Symmetric(params) => params.is_public(),
            Self::OKP(params) => params.is_public(),
        }
    }

    /// Strip private key material
    pub fn to_public(&self) -> Self {
        match self {
            Self::EC(params) => Self::EC(params.to_public()),
            Self::RSA(params) => Self::RSA(params.to_public()),
            Self::Symmetric(params) => Self::Symmetric(params.to_public()),
            Self::OKP(params) => Self::OKP(params.to_public()),
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
