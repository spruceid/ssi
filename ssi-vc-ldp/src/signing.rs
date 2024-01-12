use ssi_vc::Verifiable;
use ssi_verification_methods::{SignatureError, Signer};

use crate::{
    suite::{CryptographicSuiteInput, HashError, TransformError},
    CryptographicSuite, DataIntegrity, ProofConfiguration,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("missing credential")]
    MissingCredentialId,

    #[error("input transformation failed: {0}")]
    Transform(#[from] TransformError),

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),

    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(#[from] SignatureError),
}

impl From<crate::Error> for Error {
    fn from(value: crate::Error) -> Self {
        match value {
            crate::Error::Transform(e) => Self::Transform(e),
            crate::Error::HashFailed(e) => Self::HashFailed(e),
        }
    }
}

pub async fn sign<'max, T, S: CryptographicSuite, X, I>(
    input: T,
    context: X,
    signer: &'max I,
    suite: S,
    params: ProofConfiguration<S::VerificationMethod, S::Options>,
) -> Result<Verifiable<DataIntegrity<T, S>>, Error>
where
    S: CryptographicSuiteInput<T, X>,
    S::VerificationMethod: 'max,
    I: 'max + Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
{
    DataIntegrity::<T, S>::sign(input, context, signer, suite, params).await
}

impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
    /// Sign the given credential with the given Data Integrity cryptographic
    /// suite.
    pub async fn sign<'max, X, I>(
        input: T,
        context: X,
        signer: &'max I,
        suite: S,
        params: ProofConfiguration<S::VerificationMethod, S::Options>,
    ) -> Result<Verifiable<DataIntegrity<T, S>>, Error>
    where
        S: CryptographicSuiteInput<T, X>,
        S::VerificationMethod: 'max,
        I: 'max + Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
    {
        let di = DataIntegrity::new(input, context, &suite, params.borrowed()).await?;

        let proof = suite.generate_proof(&di.hash, signer, params).await?;

        Ok(Verifiable::new(di, proof.into_typed(suite)))
    }
}
