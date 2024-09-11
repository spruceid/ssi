#[derive(Debug, thiserror::Error)]
pub enum ProofPreparationError {
    #[error("claims processing failed: {0}")]
    Claims(String),

    #[error("proof processing failed: {0}")]
    Proof(String),

    #[error("{0}")]
    Other(String),
}

#[derive(Debug, thiserror::Error)]
pub enum ProofValidationError {
    /// Input data could not be understood.
    #[error("invalid input data: {0}")]
    InvalidInputData(String),

    #[error(transparent)]
    Preparation(#[from] ProofPreparationError),

    /// Proof could not be understood.
    #[error("invalid proof")]
    InvalidProof,

    #[error("invalid proof options")]
    InvalidProofOptions,

    /// Key not found.
    #[error("unknown key")]
    UnknownKey,

    /// Invalid key.
    #[error("invalid key")]
    InvalidKey,

    /// Missing public key.
    #[error("missing public key")]
    MissingPublicKey,

    /// More than one public key is provided.
    #[error("ambiguous public key")]
    AmbiguousPublicKey,

    /// Unsupported controller scheme.
    #[error("unsupported key controller `{0}`")]
    UnsupportedKeyController(String),

    /// Key controller was not found.
    #[error("key controller `{0}` not found")]
    KeyControllerNotFound(String),

    /// Key controller is invalid.
    #[error("invalid key controller")]
    InvalidKeyController,

    /// Cryptographic key is not used correctly.
    #[error("invalid use of key")]
    InvalidKeyUse,

    #[error("missing signature algorithm")]
    MissingAlgorithm,

    #[error("missing signature")]
    MissingSignature,

    #[error("invalid signature")]
    InvalidSignature,

    #[error("invalid verification method: {0}")]
    InvalidVerificationMethod(String),

    #[error("{0}")]
    Other(String),
}

impl ProofValidationError {
    pub fn input_data(e: impl ToString) -> Self {
        Self::InvalidInputData(e.to_string())
    }

    pub fn other(e: impl ToString) -> Self {
        Self::Other(e.to_string())
    }
}

#[derive(Debug, thiserror::Error, PartialEq)]
pub enum InvalidProof {
    /// Proof is missing.
    #[error("missing proof")]
    Missing,

    #[error("invalid signature")]
    Signature,

    #[error("key mismatch")]
    KeyMismatch,

    #[error("algorithm mismatch")]
    AlgorithmMismatch,

    #[error("{0}")]
    Other(String),
}

impl From<std::convert::Infallible> for ProofValidationError {
    fn from(_value: std::convert::Infallible) -> Self {
        unreachable!()
    }
}

pub type ProofValidity = Result<(), InvalidProof>;

/// Proof that can be validated against `T` claims with a verifier of type `V`.
pub trait ValidateProof<V, T> {
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
    ) -> Result<ProofValidity, ProofValidationError>;
}

impl<V, T, P: ValidateProof<V, T>> ValidateProof<V, T> for Vec<P> {
    async fn validate_proof<'a>(
        &'a self,
        verifier: &'a V,
        claims: &'a T,
    ) -> Result<ProofValidity, ProofValidationError> {
        if self.is_empty() {
            // No proof.
            Ok(Err(InvalidProof::Missing))
        } else {
            for p in self {
                if let Err(e) = p.validate_proof(verifier, claims).await? {
                    return Ok(Err(e));
                }
            }

            Ok(Ok(()))
        }
    }
}
