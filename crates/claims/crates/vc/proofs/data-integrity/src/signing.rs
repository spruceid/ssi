use ssi_claims_core::Verifiable;
use ssi_vc_core::verification::Claims;
use ssi_verification_methods::{SignatureError, Signer};

use crate::{
    suite::{CryptographicSuiteInput, HashError, TransformError},
    CryptographicSuite, PreparedProof, Proof, ProofConfiguration,
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

// impl From<crate::Error> for Error {
//     fn from(value: crate::Error) -> Self {
//         match value {
//             crate::Error::Transform(e) => Self::Transform(e),
//             crate::Error::HashFailed(e) => Self::HashFailed(e),
//         }
//     }
// }

pub async fn sign<'max, T, S: CryptographicSuite, X, I>(
    input: T,
    mut environment: X,
    signer: &'max I,
    suite: S,
    params: ProofConfiguration<S::VerificationMethod, S::Options>,
) -> Result<Verifiable<Claims<T, Proof<S>>>, Error>
where
    S: CryptographicSuiteInput<T, X>,
    S::VerificationMethod: 'max,
    I: 'max + Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
{
    let transformed = suite
        .transform(&input, &mut environment, params.borrowed())
        .await?;
    let hash = suite.hash(transformed, params.borrowed())?;
    let untyped_proof = suite.generate_proof(&hash, signer, params).await?;
    let proof = untyped_proof.into_typed(suite);
    Ok(Verifiable::new(
        Claims::from_proofless(input),
        vec![PreparedProof::new(proof, hash)],
    ))
}

// impl<T, S: CryptographicSuite> DataIntegrity<T, S> {
//     /// Sign the given credential with the given Data Integrity cryptographic
//     /// suite.
//     pub async fn sign<'max, X, I>(
//         input: T,
//         context: X,
//         signer: &'max I,
//         suite: S,
//         params: ProofConfiguration<S::VerificationMethod, S::Options>,
//     ) -> Result<Verifiable<DataIntegrity<T, S>>, Error>
//     where
//         S: CryptographicSuiteInput<T, X>,
//         S::VerificationMethod: 'max,
//         I: 'max + Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
//     {
//         let di = DataIntegrity::new(input, context, &suite, params.borrowed()).await?;

//         let proof = suite.generate_proof(&di.hash, signer, params).await?;

//         Ok(Verifiable::new(di, proof.into_typed(suite)))
//     }
// }
