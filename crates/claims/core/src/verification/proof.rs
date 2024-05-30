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

/// Proof type.
pub trait Proof {
    /// Prepared proof type.
    ///
    /// A prepared proof also contains any information derived from the claims
    /// and/or unprepared proof required for the verification.
    /// Examples of information may be:
    ///   - a hash of the claims;
    ///   - JSON-LD expansion of the proof;
    ///   - canonical form of the claims;
    ///   - etc.
    type Prepared;
}

/// A list of proofs is also a proof.
impl<P: Proof> Proof for Vec<P> {
    type Prepared = Vec<P::Prepared>;
}

/// Proof that can be prepared to verify `T` claims.
///
/// Preparation consists in computing any information derived from the claims
/// and/or proof required for verification.
/// Examples of information may be:
///   - a hash of the claims;
///   - JSON-LD expansion of the proof;
///   - canonical form of the claims;
///   - etc.
///
/// An environment of type `E` is provided with all the data required for the
/// preparation. For instance, JSON-LD proofs will require a JSON-LD document
/// loader to fetch remote JSON-LD contexts.
pub trait PrepareWith<T, E = ()>: Proof {
    /// Prepare this proof to verify the given claims.
    #[allow(async_fn_in_trait)]
    async fn prepare_with(
        self,
        claims: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, ProofPreparationError>;
}

impl<T, E, P: PrepareWith<T, E>> PrepareWith<T, E> for Vec<P> {
    async fn prepare_with(
        self,
        claims: &T,
        environment: &mut E,
    ) -> Result<Self::Prepared, ProofPreparationError> {
        let mut prepared = Vec::with_capacity(self.len());

        for p in self {
            prepared.push(p.prepare_with(claims, environment).await?)
        }

        Ok(prepared)
    }
}

/// Reverse proof preparation.
///
/// Provides a method to strip a proof from its preparation data.
/// This is the inverse of [`PrepareWith`].
pub trait UnprepareProof {
    /// Unprepared proof.
    type Unprepared: Proof<Prepared = Self>;

    /// Reverses the proof preparation.
    fn unprepare(self) -> Self::Unprepared;
}

impl<P: UnprepareProof> UnprepareProof for Vec<P> {
    type Unprepared = Vec<P::Unprepared>;

    fn unprepare(self) -> Self::Unprepared {
        self.into_iter().map(P::unprepare).collect()
    }
}

/// Proof that can be validated against `T` claims with a verifier of type `V`.
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
        claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, ProofValidationError>;
}

impl<T, V, P: ValidateProof<T, V>> ValidateProof<T, V> for Vec<P> {
    async fn validate_proof<'a>(
        &'a self,
        claims: &'a T,
        verifier: &'a V,
    ) -> Result<ProofValidity, ProofValidationError> {
        if self.is_empty() {
            // No proof.
            Ok(Err(InvalidProof::Missing))
        } else {
            for p in self {
                if let Err(e) = p.validate_proof(claims, verifier).await? {
                    return Ok(Err(e));
                }
            }

            Ok(Ok(()))
        }
    }
}
