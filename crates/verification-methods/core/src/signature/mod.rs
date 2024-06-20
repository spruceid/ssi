use ssi_claims_core::ProofValidationError;

pub mod protocol;
pub use protocol::SignatureProtocol;

mod signer;
pub use signer::*;

pub enum InvalidSignature {
    MissingValue,

    InvalidValue,

    MissingPublicKey,

    AmbiguousPublicKey,
}

impl From<InvalidSignature> for ProofValidationError {
    fn from(value: InvalidSignature) -> Self {
        match value {
            InvalidSignature::MissingValue => Self::MissingSignature,
            InvalidSignature::InvalidValue => Self::InvalidSignature,
            InvalidSignature::MissingPublicKey => Self::MissingPublicKey,
            InvalidSignature::AmbiguousPublicKey => Self::AmbiguousPublicKey,
        }
    }
}
