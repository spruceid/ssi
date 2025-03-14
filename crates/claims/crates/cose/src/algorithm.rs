use coset::{
    iana::{self, EnumI64},
    Algorithm,
};
use ssi_crypto::AlgorithmInstance;

/// Converts an SSI algorithm into a COSE algorithm.
pub fn cose_algorithm(algorithm: ssi_crypto::Algorithm) -> Option<Algorithm> {
    match algorithm {
        ssi_crypto::Algorithm::PS256 => Some(Algorithm::Assigned(iana::Algorithm::PS256)),
        ssi_crypto::Algorithm::PS384 => Some(Algorithm::Assigned(iana::Algorithm::PS384)),
        ssi_crypto::Algorithm::PS512 => Some(Algorithm::Assigned(iana::Algorithm::PS512)),
        ssi_crypto::Algorithm::EdDsa => Some(Algorithm::Assigned(iana::Algorithm::EdDSA)),
        ssi_crypto::Algorithm::ES256K => Some(Algorithm::Assigned(iana::Algorithm::ES256K)),
        ssi_crypto::Algorithm::ES256 => Some(Algorithm::Assigned(iana::Algorithm::ES256)),
        ssi_crypto::Algorithm::ES384 => Some(Algorithm::Assigned(iana::Algorithm::PS384)),
        _ => None,
    }
}

/// Converts a COSE algorithm into an SSI algorithm instance.
pub fn instantiate_algorithm(algorithm: &Algorithm) -> Option<AlgorithmInstance> {
    match algorithm {
        Algorithm::Assigned(iana::Algorithm::PS256) => Some(AlgorithmInstance::PS256),
        Algorithm::Assigned(iana::Algorithm::PS384) => Some(AlgorithmInstance::PS384),
        Algorithm::Assigned(iana::Algorithm::PS512) => Some(AlgorithmInstance::PS512),
        Algorithm::Assigned(iana::Algorithm::EdDSA) => Some(AlgorithmInstance::EdDsa),
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
