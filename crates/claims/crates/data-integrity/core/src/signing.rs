use ssi_claims_core::Verifiable;
use ssi_json_ld::WithJsonLdContext;
use ssi_verification_methods::{SignatureError, Signer};

use crate::{
    suite::{CryptographicSuiteInput, CryptographicSuiteOptions, HashError, TransformError},
    ConfigurationExpansionError, CryptographicSuite, PreparedProof, Proof, ProofConfiguration,
    ProofConfigurationRefExpansion, Proofs,
};

#[derive(Debug, thiserror::Error)]
pub enum Error<E = ssi_json_ld::UnknownContext> {
    #[error("missing credential")]
    MissingCredentialId,

    #[error("input transformation failed: {0}")]
    Transform(#[from] TransformError),

    #[error("hash failed: {0}")]
    HashFailed(#[from] HashError),

    #[error("proof generation failed: {0}")]
    ProofGenerationFailed(#[from] SignatureError),

    #[error("proof configuration expansion failed: {0}")]
    ConfigurationExpansionFailed(#[from] ConfigurationExpansionError<E>),
}

// impl From<crate::Error> for Error {
//     fn from(value: crate::Error) -> Self {
//         match value {
//             crate::Error::Transform(e) => Self::Transform(e),
//             crate::Error::HashFailed(e) => Self::HashFailed(e),
//         }
//     }
// }

pub async fn sign<'max, T, S: CryptographicSuite, X, N>(
    input: T,
    environment: X,
    signer: &'max N,
    suite: S,
    params: ProofConfiguration<S::VerificationMethod, S::Options>,
) -> Result<Verifiable<T, Proofs<S>>, Error<X::LoadError>>
where
    T: WithJsonLdContext,
    S: CryptographicSuiteInput<T, X>,
    S::VerificationMethod: 'max,
    N: 'max + Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
    X: for<'a> ProofConfigurationRefExpansion<'a, S>,
{
    Ok(sign_single(input, environment, signer, suite, params)
        .await?
        .map(|t, p| (t, vec![p])))
}

pub async fn sign_single<'max, T, S: CryptographicSuite, X, N>(
    input: T,
    mut environment: X,
    signer: &'max N,
    suite: S,
    mut params: ProofConfiguration<S::VerificationMethod, S::Options>,
) -> Result<Verifiable<T, Proof<S>>, Error<X::LoadError>>
where
    T: WithJsonLdContext,
    S: CryptographicSuiteInput<T, X>,
    S::VerificationMethod: 'max,
    N: 'max + Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
    X: for<'a> ProofConfigurationRefExpansion<'a, S>,
{
    if let Some(context) = suite.required_proof_context() {
        params.context = Some(context); // TODO: merge instead of replacing.
    }
    params.options.prepare(&suite);

    let expanded_params = params
        .borrowed()
        .expand(input.json_ld_context().as_ref(), &suite, &mut environment)
        .await?
        .with_configuration(params.borrowed());

    let transformed = suite
        .transform(&input, &mut environment, expanded_params.borrow())
        .await?;
    let hash = suite.hash(transformed, expanded_params)?;
    let proof = suite.generate_proof(&hash, signer, params).await?;
    Ok(Verifiable::from_parts(
        input,
        PreparedProof::new(proof, hash),
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