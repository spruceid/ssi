use std::borrow::Cow;

use coset::{
    iana::{self, EnumI64},
    Algorithm, CoseKey, KeyType,
};
use ssi_crypto::AlgorithmInstance;

use crate::key::{CoseKeyDecode, EC2_CRV};

/// Converts a COSE algorithm into an SSI algorithm instance.
pub fn instantiate_algorithm(algorithm: &Algorithm) -> Option<AlgorithmInstance> {
    match algorithm {
        Algorithm::Assigned(iana::Algorithm::PS256) => Some(AlgorithmInstance::PS256),
        Algorithm::Assigned(iana::Algorithm::PS384) => Some(AlgorithmInstance::PS384),
        Algorithm::Assigned(iana::Algorithm::PS512) => Some(AlgorithmInstance::PS512),
        Algorithm::Assigned(iana::Algorithm::EdDSA) => Some(AlgorithmInstance::EdDSA),
        Algorithm::Assigned(iana::Algorithm::ES256K) => Some(AlgorithmInstance::ES256K),
        Algorithm::Assigned(iana::Algorithm::ES256) => Some(AlgorithmInstance::ES256),
        Algorithm::Assigned(iana::Algorithm::ES384) => Some(AlgorithmInstance::ES384),
        _ => None,
    }
}

/// Computes a proper display name for the give COSE algorithm.
pub fn algorithm_name(algorithm: &Algorithm) -> String {
    match algorithm {
        Algorithm::Assigned(iana::Algorithm::PS256) => "PS256".to_owned(),
        Algorithm::Assigned(iana::Algorithm::PS384) => "PS384".to_owned(),
        Algorithm::Assigned(iana::Algorithm::PS512) => "PS512".to_owned(),
        Algorithm::Assigned(iana::Algorithm::EdDSA) => "EdDSA".to_owned(),
        Algorithm::Assigned(iana::Algorithm::ES256K) => "ES256K".to_owned(),
        Algorithm::Assigned(iana::Algorithm::ES256) => "ES256".to_owned(),
        Algorithm::Assigned(iana::Algorithm::ES384) => "ES384".to_owned(),
        Algorithm::Assigned(i) => format!("assigned({})", i.to_i64()),
        Algorithm::PrivateUse(i) => format!("private_use({i})"),
        Algorithm::Text(text) => text.to_owned(),
    }
}

/// Returns the preferred signature algorithm for the give COSE key.
pub fn preferred_algorithm(key: &CoseKey) -> Option<Cow<Algorithm>> {
    key.alg
        .as_ref()
        .map(Cow::Borrowed)
        .or_else(|| match key.kty {
            KeyType::Assigned(iana::KeyType::RSA) => {
                Some(Cow::Owned(Algorithm::Assigned(iana::Algorithm::PS256)))
            }
            KeyType::Assigned(iana::KeyType::OKP) => {
                let crv = key
                    .parse_required_param(&EC2_CRV, |v| {
                        v.as_integer().and_then(|i| i64::try_from(i).ok())
                    })
                    .ok()?;

                match iana::EllipticCurve::from_i64(crv)? {
                    iana::EllipticCurve::Ed25519 => {
                        Some(Cow::Owned(Algorithm::Assigned(iana::Algorithm::EdDSA)))
                    }
                    _ => None,
                }
            }
            KeyType::Assigned(iana::KeyType::EC2) => {
                let crv = key
                    .parse_required_param(&EC2_CRV, |v| {
                        v.as_integer().and_then(|i| i64::try_from(i).ok())
                    })
                    .ok()?;

                match iana::EllipticCurve::from_i64(crv)? {
                    iana::EllipticCurve::Secp256k1 => {
                        Some(Cow::Owned(Algorithm::Assigned(iana::Algorithm::ES256K)))
                    }
                    iana::EllipticCurve::P_256 => {
                        Some(Cow::Owned(Algorithm::Assigned(iana::Algorithm::ES256)))
                    }
                    iana::EllipticCurve::P_384 => {
                        Some(Cow::Owned(Algorithm::Assigned(iana::Algorithm::ES384)))
                    }
                    _ => None,
                }
            }
            _ => None,
        })
}
