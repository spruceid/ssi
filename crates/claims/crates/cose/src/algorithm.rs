use std::borrow::Cow;

use coset::{
    iana::{self, EnumI64},
    Algorithm, CoseKey, KeyType,
};
use ssi_crypto::AlgorithmInstance;

use crate::key::{CoseKeyDecode, EC2_CRV};

pub fn instantiate_algorithm(algorithm: &Algorithm) -> Option<AlgorithmInstance> {
    match algorithm {
        Algorithm::Assigned(iana::Algorithm::ES256) => Some(AlgorithmInstance::ES256),
        _ => None,
    }
}

pub fn algorithm_name(algorithm: &Algorithm) -> String {
    match algorithm {
        Algorithm::Assigned(iana::Algorithm::ES256) => "ES256".to_owned(),
        Algorithm::Assigned(i) => format!("assigned({})", i.to_i64()),
        Algorithm::PrivateUse(i) => format!("private_use({i})"),
        Algorithm::Text(text) => text.to_owned(),
    }
}

pub fn preferred_algorithm(key: &CoseKey) -> Option<Cow<Algorithm>> {
    key.alg
        .as_ref()
        .map(Cow::Borrowed)
        .or_else(|| match key.kty {
            KeyType::Assigned(iana::KeyType::EC2) => {
                let crv = key
                    .parse_required_param(&EC2_CRV, |v| {
                        v.as_integer().and_then(|i| i64::try_from(i).ok())
                    })
                    .ok()?;

                match iana::EllipticCurve::from_i64(crv)? {
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
