use ssi_claims_core::{SignatureError, Verifiable};
use ssi_json_ld::JsonLdNodeObject;
use ssi_verification_methods_core::{Signer, VerificationMethodResolver};

use crate::{
    suite::{CryptographicSuiteInput, CryptographicSuiteOptions, HashError, TransformError},
    ConfigurationExpansionError, PreparedProof, Proof, ProofConfiguration,
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

pub async fn sign<'max, T, S, X, R, N>(
    input: T,
    environment: X,
    resolver: &'max R,
    signer: &'max N,
    suite: S,
    params: ProofConfiguration<S::VerificationMethod, S::Options>,
) -> Result<Verifiable<T, Proofs<S>>, SignatureError>
where
    T: JsonLdNodeObject,
    S: CryptographicSuiteInput<T, X>,
    S::VerificationMethod: 'max,
    R: 'max + VerificationMethodResolver<Method = S::VerificationMethod>,
    N: 'max + Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
    X: for<'a> ProofConfigurationRefExpansion<'a, S>,
{
    Ok(
        sign_single(input, environment, resolver, signer, suite, params)
            .await?
            .map(|t, p| (t, vec![p])),
    )
}

pub async fn sign_single<'max, T, S, X, R, N>(
    input: T,
    mut environment: X,
    resolver: &'max R,
    signer: &'max N,
    suite: S,
    mut params: ProofConfiguration<S::VerificationMethod, S::Options>,
) -> Result<Verifiable<T, Proof<S>>, SignatureError>
where
    T: JsonLdNodeObject,
    S: CryptographicSuiteInput<T, X>,
    S::VerificationMethod: 'max,
    R: 'max + VerificationMethodResolver<Method = S::VerificationMethod>,
    N: 'max + Signer<S::VerificationMethod, S::MessageSignatureAlgorithm, S::SignatureProtocol>,
    X: for<'a> ProofConfigurationRefExpansion<'a, S>,
{
    if let Some(context) = suite.required_proof_context() {
        params.context = Some(context); // TODO: merge instead of replacing.
    }
    params.options.prepare(&suite);

    let expanded_params = params
        .borrowed()
        .expand(
            input.json_ld_context().as_deref(),
            input.json_ld_type(),
            &suite,
            &mut environment,
        )
        .await?
        .with_configuration(params.borrowed());

    let transformed = suite
        .transform(&input, &mut environment, expanded_params.borrow())
        .await?;
    let hash = suite.hash(transformed, expanded_params)?;
    let proof = suite
        .generate_proof(&hash, resolver, signer, params)
        .await?;
    Ok(Verifiable::from_parts(
        input,
        PreparedProof::new(proof, hash),
    ))
}
