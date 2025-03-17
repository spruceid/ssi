use ssi_crypto::{Error, RejectedSignature, SignatureVerification};

use super::Parameters;

// #[derive(Debug, thiserror::Error)]
// pub enum ProofPreparationError {
//     #[error("claims processing failed: {0}")]
//     Claims(String),

//     #[error("proof processing failed: {0}")]
//     Proof(String),

//     #[error("{0}")]
//     Other(String),
// }

// #[derive(Debug, thiserror::Error)]
// pub enum ProofValidationError {
//     /// Input data could not be understood.
//     #[error("invalid input data: {0}")]
//     InvalidInputData(String),

//     #[error(transparent)]
//     Preparation(#[from] ProofPreparationError),

//     /// Proof could not be understood.
//     #[error("invalid proof")]
//     InvalidProof,

//     #[error("invalid proof options")]
//     InvalidProofOptions,

//     /// Key not found.
//     #[error("unknown key")]
//     UnknownKey,

//     /// Invalid key.
//     #[error("invalid key")]
//     InvalidKey,

//     /// Missing public key.
//     #[error("missing public key")]
//     MissingPublicKey,

//     /// More than one public key is provided.
//     #[error("ambiguous public key")]
//     AmbiguousPublicKey,

//     /// Unsupported controller scheme.
//     #[error("unsupported key controller `{0}`")]
//     UnsupportedKeyController(String),

//     /// Key controller was not found.
//     #[error("key controller `{0}` not found")]
//     KeyControllerNotFound(String),

//     /// Key controller is invalid.
//     #[error("invalid key controller")]
//     InvalidKeyController,

//     /// Cryptographic key is not used correctly.
//     #[error("invalid use of key")]
//     InvalidKeyUse,

//     #[error("missing signature algorithm")]
//     MissingAlgorithm,

//     #[error("missing signature")]
//     MissingSignature,

//     #[error("invalid signature")]
//     InvalidSignature,

//     #[error("invalid verification method: {0}")]
//     InvalidVerificationMethod(String),

//     #[error("{0}")]
//     Other(String),
// }

// impl ProofValidationError {
//     pub fn input_data(e: impl ToString) -> Self {
//         Self::InvalidInputData(e.to_string())
//     }

//     pub fn other(e: impl ToString) -> Self {
//         Self::Other(e.to_string())
//     }
// }

// impl From<ssi_crypto::VerificationError> for ProofValidationError {
//     fn from(value: ssi_crypto::VerificationError) -> Self {
//         match value {
//             ssi_crypto::VerificationError::KeyNotFound => Self::UnknownKey,
//             ssi_crypto::VerificationError::MalformedSignature => Self::InvalidSignature,
//             e => Self::other(e),
//         }
//     }
// }

// impl From<std::convert::Infallible> for ProofValidationError {
//     fn from(_value: std::convert::Infallible) -> Self {
//         unreachable!()
//     }
// }

/// Proof that can be validated against claims of type `T`.
pub trait ValidateProof<T, V> {
    /// Validates the input claim's proof using the given verifier.
    ///
    /// The returned value is a nested `Result`.
    /// The outer `Result` describes whether or not the proof could be verified.
    /// A proof may be valid even if the outer value is `Err`.
    /// The inner `Result` describes the validity of the proof itself.
    /// A proof is surely valid if the inner value is `Ok`.
    #[allow(async_fn_in_trait)]
    async fn validate_proof<'a>(
        &'a self,
        verifier: &'a V,
        claims: &'a T,
        params: &'a Parameters,
    ) -> Result<SignatureVerification, Error>;
}

impl<T, V, P: ValidateProof<T, V>> ValidateProof<T, V> for Vec<P> {
    async fn validate_proof<'a>(
        &'a self,
        verifier: &'a V,
        claims: &'a T,
        params: &'a Parameters,
    ) -> Result<SignatureVerification, Error> {
        if self.is_empty() {
            // No proof.
            Ok(Err(RejectedSignature::Missing))
        } else {
            for p in self {
                if let Err(e) = p.validate_proof(verifier, claims, params).await? {
                    return Ok(Err(e));
                }
            }

            Ok(Ok(()))
        }
    }
}
