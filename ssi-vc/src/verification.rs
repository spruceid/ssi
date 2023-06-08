use ssi_crypto::{UnsupportedAlgorithm, VerifierProvider};

/// Credential verifiable with a proof of type `P`.
pub trait VerifiableWith<P> {
    /// Verification method.
    type Method;

    /// Transformed credential.
    type Transformed;

    /// Verification parameters.
    type Parameters;

    type Error;

    fn verify_with(
        &self,
        context: &mut impl Context<Self, P>,
        verifiers: &impl VerifierProvider<Self::Method>,
        proof: &P,
        parameters: Self::Parameters,
    ) -> Result<ProofValidity, Self::Error>;

    fn verify(
        &self,
        verifiers: &impl VerifierProvider<Self::Method>,
        proof: &P,
        parameters: Self::Parameters,
    ) -> Result<ProofValidity, Self::Error>
    where
        Self: VerifiableWith<P, Transformed = ()>,
    {
        self.verify_with(&mut (), verifiers, proof, parameters)
    }
}

/// Error raised when a proof verification fails.
#[derive(Debug, thiserror::Error)]
#[error("invalid proof")]
pub struct InvalidProof;

#[derive(Debug, thiserror::Error)]
pub enum VerificationError {
    #[error(transparent)]
    UnsupportedAlgorithm(UnsupportedAlgorithm),

    #[error("unknown verification method")]
    UnknownVerificationMethod,
}

impl From<UnsupportedAlgorithm> for VerificationError {
    fn from(value: UnsupportedAlgorithm) -> Self {
        Self::UnsupportedAlgorithm(value)
    }
}

/// Verification context.
pub trait Context<T: ?Sized + VerifiableWith<P>, P> {
    fn transform(
        &mut self,
        value: &T,
        proof: &P,
        parameters: &T::Parameters,
    ) -> Result<T::Transformed, T::Error>;
}

impl<T: ?Sized + VerifiableWith<P, Transformed = ()>, P> Context<T, P> for () {
    fn transform(
        &mut self,
        _value: &T,
        _proof: &P,
        _parameters: &T::Parameters,
    ) -> Result<(), T::Error> {
        Ok(())
    }
}

/// Result of a credential verification.
pub enum ProofValidity {
    /// The proof is valid.
    Valid,

    /// The proof is invalid.
    Invalid,
}

impl ProofValidity {
    pub fn into_result(self) -> Result<(), InvalidProof> {
        match self {
            Self::Valid => Ok(()),
            Self::Invalid => Err(InvalidProof),
        }
    }
}

impl From<bool> for ProofValidity {
    fn from(value: bool) -> Self {
        if value {
            Self::Valid
        } else {
            Self::Invalid
        }
    }
}

impl From<ProofValidity> for bool {
    fn from(value: ProofValidity) -> Self {
        match value {
            ProofValidity::Valid => true,
            ProofValidity::Invalid => false,
        }
    }
}
